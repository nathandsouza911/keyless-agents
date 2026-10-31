"""The launcher: start one queued run in a sandbox and see it to its end (Task 14).

run_once():
  1. Claim the oldest queued run (FOR UPDATE SKIP LOCKED, so two launchers
     never take the same run). Its manifest must be the one it was created
     with (id, digest, mode, profile id, version, digest: as the broker
     checks) and its params must satisfy it; otherwise it ends
     failed / manifest_invalid or params_invalid and nothing starts.
  2. Mint the run token (only its SHA-256 is stored), set the row running
     with deadline_at = database now() + the manifest's timeout_seconds, and
     write RUN_STARTED, in one locked transaction. If RUN_STARTED cannot be
     written, the row stays queued and nothing starts. The container is
     started only after both are committed, so the token is never usable
     for a run the chain has not seen start. If RUN_STARTED committed but the
     row did not (the row commit failed, or the record's acknowledgement was
     lost, RR-4), the run is still queued with a start in the chain: the
     writer refuses a second RUN_STARTED (SD-034) and the run ends
     failed / start_unrecorded, with nothing started and both records kept.
  3. Start the container (sandbox_spec) and read its stdout while it runs,
     until it exits, its stdout passes 5 MiB, or the deadline passes.
  4. End the run (lifecycle):
       deadline passed      kill; timed_out / timeout (details.kill = failed
                            if the kill failed; the broker refuses the token
                            after the deadline regardless, and the row
                            revokes it)
       stdout over 5 MiB    kill; failed / result_too_large
       exit code != 0       failed / task_error (details.exit_code); any
                            result line is discarded
       exit 0, bad output   failed / result_missing, result_duplicate,
                            result_malformed, unexpected_output
       exit 0, valid result completed / succeeded, the result stored in
                            runs.result and its SHA-256 in RUN_COMPLETED;
                            if that cannot be recorded, failed / <reason>
     If the run was halted meanwhile (the broker's audit failed), it ends
     failed / audit_unavailable whatever the task did. If it was ended
     elsewhere (the broker failed it, the reconciler timed it out), nothing
     more is recorded and a late result is discarded.
  5. Remove the container.

Killing the task does not cancel a broker operation already in flight: the
broker finishes or abandons it, and anything it records after the terminal
record is refused (lifecycle; SD-034).

Script runs (SD-044) take the same path, only when the runner is configured
for them (a script image): otherwise they stay queued.
  1. The run must still be bound to its approval: the approval is the
     tenant's, of the run's script, with the run's manifest digest (and the
     stored manifest still loads to it), and the script's text hashes to the
     approved digest. Otherwise failed / approval_invalid, nothing started.
  2. The deadline is SCRIPT_TIMEOUT_SECONDS; RUN_STARTED records the script's
     digest, the approval and the bootstrap's digest.
  3. The script container (script_container_kwargs) gets the script on
     stdin; its stdout is read up to MAX_SCRIPT_OUTPUT_BYTES.
  4. A bootstrap refusal ends failed / <its reason>; a non-zero container
     exit, failed / task_error; otherwise the script's output is the result
     (parse_script_output), whatever the script's own exit code.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.events import AuditRunStateRefused, EventType
from clw.broker.capability import issue_run_token
from clw.broker.facade.rules import load_script_manifest
from clw.broker.manifest import TaskManifest
from clw.common.timeutil import utc_now
from clw.db.models.run import Run
from clw.db.models.script import Script, ScriptApproval
from clw.runner.backend import ContainerBackend, TaskProcess
from clw.runner.lifecycle import HALTED, QUEUED, CompletionRefused, Ended, RunKey, RunLifecycle
from clw.runner.result import ResultRejected, bootstrap_refusal, parse_result, parse_script_output
from clw.runner.sandbox_spec import (MAX_RESULT_BYTES, MAX_SCRIPT_OUTPUT_BYTES, SCRIPT_NETWORK, SCRIPT_TIMEOUT_SECONDS,
                                     TASK_NETWORK, InvalidRunParams, SandboxConfig, ScriptSandboxConfig, peer_host,
                                     sandbox_container_kwargs, script_container_kwargs, task_arguments)

log = logging.getLogger("clw.runner")
alert_log = logging.getLogger("clw.runner.alert")

KILL_GRACE_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class ClaimedRun:
    id: uuid.UUID
    tenant_id: str
    task_id: str
    params: dict
    deadline_at: datetime
    token: str
    manifest: TaskManifest | None   # None for a script run
    kind: str = "task"
    script: bytes | None = None     # a script run's approved script, its UTF-8 bytes
    script_sha256: str | None = None

    @property
    def key(self) -> RunKey:
        return RunKey(str(self.id), self.tenant_id)


@dataclass(frozen=True, slots=True)
class LaunchOutcome:
    run_id: str
    status: str          # what this launcher recorded: completed, failed, timed_out, not_started, already_ended
    reason: str
    ended: Ended | None = None


@dataclass(frozen=True, slots=True)
class _Supervised:
    kind: str            # exited, overflow, timeout
    stdout: bytes = b""
    exit_code: int | None = None
    kill_failed: bool = False


def _bound(manifest: object, row: Run) -> bool:
    return (isinstance(manifest, TaskManifest) and manifest.id == row.task_id
            and manifest.sha256 == row.task_manifest_sha256 and manifest.mode == row.auth_mode
            and manifest.profile.id == row.profile_id and manifest.profile.version == row.profile_version
            and manifest.profile.sha256 == row.profile_sha256)


def _script_bound(row: Run, script: Script | None, approval: ScriptApproval | None) -> bool:
    """A script run is still bound to its approval and its script (SD-044)."""
    if script is None or approval is None:
        return False
    if not (script.tenant_id == approval.tenant_id == row.tenant_id and approval.script_id == script.id
            and approval.script_sha256 == script.sha256
            == hashlib.sha256(script.text.encode("utf-8")).hexdigest()
            and approval.manifest_sha256 == row.task_manifest_sha256):
        return False
    try:
        return load_script_manifest(approval.manifest).sha256 == row.task_manifest_sha256
    except Exception:  # noqa: BLE001 - an approval that no longer loads runs nothing
        return False


async def _sleep_until(deadline: datetime, clock: Callable[[], datetime]) -> None:
    await asyncio.sleep(max(0.0, (deadline - clock()).total_seconds()))


class _NotStarted(Exception):
    def __init__(self, run_id: str) -> None:
        super().__init__(run_id)
        self.run_id = run_id


class _StartAlreadyRecorded(Exception):
    def __init__(self, run_id: str, tenant_id: str) -> None:
        super().__init__(run_id)
        self.run_id = run_id
        self.tenant_id = tenant_id


class Launcher:
    def __init__(self, *, sessionmaker: async_sessionmaker[AsyncSession], writer, backend: ContainerBackend,
                 catalog: Mapping[str, TaskManifest], config: SandboxConfig,
                 script_config: ScriptSandboxConfig | None = None, bootstrap_sha256: str | None = None,
                 clock: Callable[[], datetime] = utc_now,
                 timer: Callable[[datetime], Awaitable[None]] | None = None,
                 kill_grace_seconds: float = KILL_GRACE_SECONDS) -> None:
        self._sessionmaker = sessionmaker
        self._writer = writer
        self._backend = backend
        self._catalog = catalog
        self._config = config
        if (script_config is None) != (bootstrap_sha256 is None):
            raise ValueError("script runs need both the script sandbox and the bootstrap digest")
        self._script_config = script_config  # None: script runs stay queued
        self._bootstrap = bootstrap_sha256
        self._lifecycle = RunLifecycle(sessionmaker, writer)
        # Waits until the deadline; replaceable so tests decide when it passes.
        self._timer = timer or (lambda deadline: _sleep_until(deadline, clock))
        self._kill_grace = kill_grace_seconds

    async def run_once(self) -> LaunchOutcome | None:
        claimed = await self._claim()
        if claimed is None or isinstance(claimed, LaunchOutcome):
            return claimed
        script = claimed.kind == "script"
        network = SCRIPT_NETWORK if script else TASK_NETWORK
        url = self._script_config.broker_url if script else self._config.broker_url
        try:
            # The one peer the container may reach, by address (SD-044): its
            # name then resolves from the hosts file, under runc and gVisor alike.
            peer = await asyncio.to_thread(self._backend.peer_address, network, peer_host(url))
            if peer is None:
                log.warning("runner_peer_unavailable run_id=%s network=%s", claimed.id, network)
                return await self._end(claimed.key, "failed", "peer_unavailable")
            if script:
                kwargs = script_container_kwargs(claimed, claimed.token, script_sha256=claimed.script_sha256,
                                                 bootstrap=self._bootstrap, config=self._script_config, peer=peer)
                process = await asyncio.to_thread(self._backend.start, kwargs, claimed.script)
            else:
                kwargs = sandbox_container_kwargs(claimed, claimed.token, manifest=claimed.manifest,
                                                  config=self._config, peer=peer)
                process = await asyncio.to_thread(self._backend.start, kwargs)
        except Exception:  # noqa: BLE001 - nothing ran; the run must not stay usable
            log.warning("runner_launch_failed run_id=%s", claimed.id)
            return await self._end(claimed.key, "failed", "launch_failed")
        limit = MAX_SCRIPT_OUTPUT_BYTES if claimed.kind == "script" else MAX_RESULT_BYTES
        try:
            supervised = await self._supervise(process, claimed.deadline_at, claimed.key, limit)
        finally:
            await self._remove(process, claimed.key)
        return await self._conclude(claimed.key, supervised, claimed.kind)

    # ------------------------------------------------------------- claim

    async def _claim(self) -> ClaimedRun | LaunchOutcome | None:
        refused: tuple[RunKey, str] | None = None
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    queued = select(Run).where(Run.status == "queued")
                    if self._script_config is None:
                        # Not configured for script runs (no PowerShell sandbox): they stay queued.
                        queued = queued.where(Run.kind == "task")
                    row = (await session.execute(
                        queued.order_by(Run.created_at, Run.id).limit(1)
                        .with_for_update(skip_locked=True))).scalar_one_or_none()
                    if row is None:
                        return None
                    key = RunKey(str(row.id), row.tenant_id)
                    if row.kind == "script":
                        script = await session.get(Script, row.script_id)
                        approval = await session.get(ScriptApproval, row.approval_id)
                        if not _script_bound(row, script, approval):
                            refused = (key, "approval_invalid")
                        else:
                            return await self._start(session, row, None, script=script)
                    else:
                        manifest = self._catalog.get(row.task_id)
                        if not _bound(manifest, row):
                            refused = (key, "manifest_invalid")
                        else:
                            try:
                                task_arguments(manifest, row.params)
                            except InvalidRunParams:
                                refused = (key, "params_invalid")
                        if refused is None:
                            # Raising _NotStarted leaves this block, so the row change rolls back.
                            return await self._start(session, row, manifest)
        except _NotStarted as exc:
            alert_log.critical("runner_run_not_started run_id=%s reason=audit_unavailable", exc.run_id)
            return LaunchOutcome(exc.run_id, "not_started", "audit_unavailable")
        except _StartAlreadyRecorded as exc:
            alert_log.critical("runner_start_already_recorded run_id=%s action=fail_run", exc.run_id)
            return await self._end(RunKey(exc.run_id, exc.tenant_id), "failed", "start_unrecorded",
                                   from_statuses=QUEUED)
        # The claim's lock is released; ending takes its own (a run that
        # another launcher ended meanwhile is left as it is).
        return await self._end(refused[0], "failed", refused[1], from_statuses=QUEUED)

    async def _start(self, session: AsyncSession, row: Run, manifest: TaskManifest | None, *,
                     script: Script | None = None) -> ClaimedRun:
        issued = issue_run_token()
        now = await session.scalar(select(func.now()))
        timeout = SCRIPT_TIMEOUT_SECONDS if script is not None else manifest.timeout_seconds
        deadline = now + timedelta(seconds=timeout)
        await session.execute(update(Run).where(Run.id == row.id).values(
            status="running", run_token_sha256=issued.sha256, deadline_at=deadline, started_at=func.now(),
            updated_at=func.now()))
        event = {
            "tenant_id": row.tenant_id, "event_type": EventType.RUN_STARTED, "status": "started",
            "run_id": str(row.id), "task_id": row.task_id, "task_manifest_sha256": row.task_manifest_sha256,
            "profile_id": row.profile_id, "profile_version": row.profile_version, "auth_mode": row.auth_mode}
        if script is not None:
            event["details"] = {"script_sha256": script.sha256, "approval_id": str(row.approval_id),
                                "bootstrap_sha256": self._bootstrap}
        try:
            await self._writer.append(chain_id=row.tenant_id, event=event)
        except AuditRunStateRefused as exc:
            # The chain already records this run's start (or end) although its
            # row is still queued: a start whose row commit was lost, or whose
            # audit acknowledgement was lost (RR-4). Starting again would put a
            # second RUN_STARTED in the chain; the run is failed instead.
            raise _StartAlreadyRecorded(str(row.id), row.tenant_id) from exc
        except Exception as exc:  # noqa: BLE001 - the row change rolls back; the run stays queued
            raise _NotStarted(str(row.id)) from exc
        if script is not None:
            return ClaimedRun(id=row.id, tenant_id=row.tenant_id, task_id=row.task_id, params={},
                              deadline_at=deadline, token=issued.token, manifest=None, kind="script",
                              script=script.text.encode("utf-8"), script_sha256=script.sha256)
        return ClaimedRun(id=row.id, tenant_id=row.tenant_id, task_id=row.task_id, params=dict(row.params),
                          deadline_at=deadline, token=issued.token, manifest=manifest)

    # ------------------------------------------------------------- supervise

    @staticmethod
    def _collect(process: TaskProcess, limit: int) -> _Supervised:
        buffer = bytearray()
        for chunk in process.stdout():
            buffer += chunk
            if len(buffer) > limit:
                return _Supervised("overflow")
        return _Supervised("exited", bytes(buffer), process.wait())

    async def _kill(self, process: TaskProcess, run: RunKey) -> bool:
        try:
            await asyncio.to_thread(process.kill)
            return True
        except Exception:  # noqa: BLE001 - reported; the token is revoked when the run ends
            alert_log.critical("runner_kill_failed run_id=%s", run.run_id)
            return False

    async def _supervise(self, process: TaskProcess, deadline: datetime, run: RunKey,
                         limit: int = MAX_RESULT_BYTES) -> _Supervised:
        reader = asyncio.ensure_future(asyncio.to_thread(self._collect, process, limit))
        timer = asyncio.ensure_future(self._timer(deadline))
        try:
            await asyncio.wait({reader, timer}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            timer.cancel()
        if reader.done():
            outcome = reader.result()
            if outcome.kind == "overflow":
                return _Supervised("overflow", kill_failed=not await self._kill(process, run))
            return outcome
        killed = await self._kill(process, run)
        # Output written after the deadline is never used. Wait briefly for
        # the reader to see the end of the stream, then leave it.
        await asyncio.wait({reader}, timeout=self._kill_grace)
        return _Supervised("timeout", kill_failed=not killed)

    async def _remove(self, process: TaskProcess, run: RunKey) -> None:
        try:
            await asyncio.to_thread(process.remove)
        except Exception:  # noqa: BLE001 - left for the reconciler
            alert_log.warning("runner_container_not_removed run_id=%s", run.run_id)

    # ------------------------------------------------------------- conclude

    async def _conclude(self, run: RunKey, supervised: _Supervised, kind: str = "task") -> LaunchOutcome:
        if supervised.kind == "timeout":
            details = {"kill": "failed"} if supervised.kill_failed else {}
            return await self._end(run, "timed_out", "timeout", details=details)
        if supervised.kind == "overflow":
            return await self._end(run, "failed", "result_too_large")
        if kind == "script":
            refusal = bootstrap_refusal(supervised.exit_code, supervised.stdout)
            if refusal is not None:
                return await self._end(run, "failed", refusal)
        if supervised.exit_code != 0:
            return await self._end(run, "failed", "task_error", details={"exit_code": supervised.exit_code})
        try:
            result = parse_script_output(supervised.stdout) if kind == "script" else parse_result(supervised.stdout)
        except ResultRejected as exc:
            return await self._end(run, "failed", exc.reason)
        try:
            await self._lifecycle.complete(run, result.value, result.sha256)
        except CompletionRefused as exc:
            if exc.reason == "run_not_running":
                return await self._end(run, "failed", "result_unrecorded")
            return await self._end(run, "failed", exc.reason)
        return LaunchOutcome(run.run_id, "completed", "succeeded", Ended.RECORDED)

    async def _end(self, run: RunKey, status: str, reason: str, *, details: dict | None = None,
                   from_statuses: frozenset[str] | None = None) -> LaunchOutcome:
        ended = await self._lifecycle.end(run, status, reason, details=details, from_statuses=from_statuses)
        if ended is not Ended.NOT_ENDED:
            return LaunchOutcome(run.run_id, status, reason, ended)
        if from_statuses is None and await self._lifecycle.status(run) == "halted":
            ended = await self._lifecycle.end(run, "failed", "audit_unavailable", from_statuses=HALTED)
            if ended is not Ended.NOT_ENDED:
                return LaunchOutcome(run.run_id, "failed", "audit_unavailable", ended)
        log.info("runner_outcome_discarded run_id=%s would_be=%s/%s", run.run_id, status, reason)
        return LaunchOutcome(run.run_id, "already_ended", reason, Ended.NOT_ENDED)
