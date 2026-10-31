"""The runner's script-analysis job (Part B, M4; SD-043).

run_once():
  1. Claim the oldest queued analysis (FOR UPDATE SKIP LOCKED) and mark it
     running.
  2. Start the analyser container (`analyser_container_kwargs`): no network,
     read-only root, a small /tmp, every capability dropped, no credentials
     and no environment of the run's; the script text is written to its stdin
     (nothing from the host is mounted, and the root stays read-only).
     task_pwsh/analyse.ps1 parses it and never executes it.
  3. Read at most MAX_OUTPUT_BYTES of stdout until it exits or ANALYSIS_TIMEOUT
     passes (then it is killed).
  4. Record, once: analyzed (the analysis, its SHA-256, the proposed manifest,
     the summary) or failed (a reason), and SCRIPT_ANALYZED to the tenant's
     chain, in the lifecycle pattern (row update, audit record, commit). If the
     record cannot be written the row stays unchanged and the analysis is
     failed without a record, so an unrecorded analysis can never be approved.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.canonical import CanonicalizationError, canonical_json
from clw.audit.events import AuditUnavailable, EventType
from clw.common.timeutil import utc_now
from clw.db.models.script import Script, ScriptAnalysis
from clw.runner.sandbox_spec import NPROC_ULIMIT
from clw.scripts.analysis import MAX_OUTPUT_BYTES, AnalysisRefused, parse_analysis, propose, summarize

alert_log = logging.getLogger("clw.runner.alert")

ANALYSIS_TIMEOUT = 60.0


def analyser_container_kwargs(analysis_id: str, *, image: str, runtime: str | None = None) -> dict:
    return {
        "image": image,
        "command": [],
        "stdin_open": True,   # the script arrives on stdin, once (StdinOnce: see DockerBackend.analyse)
        "network_mode": "none",
        "name": f"clw-analysis-{analysis_id}",
        "labels": {"clw.analysis_id": analysis_id},
        "detach": True,
        "read_only": True,
        "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=32m"},
        "user": "10005:10005",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "pids_limit": 64,
        "ulimits": [NPROC_ULIMIT],
        # The cmdlet index is built into the image (SD-044): an analysis needs
        # under 200 MiB. (Loading the SDK's whole command metadata per analysis
        # peaked near 500 MiB and ran 512 MiB out of memory half the time.)
        "mem_limit": "512m",
        "memswap_limit": "512m",
        "nano_cpus": 1_000_000_000,
        "environment": {},
        "log_config": {"type": "json-file", "config": {"max-size": "2m", "max-file": "1"}},
        **({"runtime": runtime} if runtime else {}),  # CLW_TASK_RUNTIME, for example runsc (SD-044)
    }


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    analysis_id: str
    status: str   # analyzed | failed
    reason: str | None = None


class Analyser:
    def __init__(self, *, sessionmaker: async_sessionmaker[AsyncSession], writer, backend, image: str,
                 runtime: str | None = None, timeout: float = ANALYSIS_TIMEOUT, clock: Callable[[], datetime] = utc_now) -> None:
        self._sessionmaker = sessionmaker
        self._writer = writer
        self._backend = backend
        self._image = image
        self._runtime = runtime
        self._timeout = timeout
        self._clock = clock

    async def run_once(self) -> AnalysisOutcome | None:
        claimed = await self._claim()
        if claimed is None:
            return None
        analysis_id, tenant_id, sha256, text = claimed
        try:
            exit_code, stdout = await asyncio.to_thread(
                self._backend.analyse, analyser_container_kwargs(analysis_id, image=self._image, runtime=self._runtime),
                text.encode("utf-8"), self._timeout, MAX_OUTPUT_BYTES)
        except TimeoutError:
            return await self._failed(analysis_id, tenant_id, sha256, "analysis_timeout")
        except Exception:  # noqa: BLE001 - nothing usable came back
            alert_log.warning("analyser_launch_failed analysis_id=%s", analysis_id)
            return await self._failed(analysis_id, tenant_id, sha256, "analyser_unavailable")
        if exit_code != 0:
            return await self._failed(analysis_id, tenant_id, sha256, "analyser_error")
        try:
            analysis = parse_analysis(stdout)
            digest = hashlib.sha256(canonical_json(analysis)).hexdigest()
        except (AnalysisRefused, CanonicalizationError) as exc:
            reason = exc.args[0] if isinstance(exc, AnalysisRefused) else "analysis_malformed"
            return await self._failed(analysis_id, tenant_id, sha256, reason)
        proposed = propose(analysis)
        values = {"status": "analyzed", "analyser_version": str(analysis.get("version"))[:32], "analysis": analysis,
                  "analysis_sha256": digest, "proposed_manifest": proposed, "summary": summarize(analysis, proposed)}
        details = {"script_sha256": sha256, "analysis_sha256": digest, "analyser_version": values["analyser_version"]}
        return await self._record(analysis_id, tenant_id, values, "analyzed", details, None)

    async def _claim(self):
        async with self._sessionmaker() as session:
            async with session.begin():
                row = (await session.execute(
                    select(ScriptAnalysis).where(ScriptAnalysis.status == "queued")
                    .order_by(ScriptAnalysis.created_at, ScriptAnalysis.id).limit(1)
                    .with_for_update(skip_locked=True))).scalar_one_or_none()
                if row is None:
                    return None
                script = await session.get(Script, row.script_id)
                await session.execute(update(ScriptAnalysis).where(ScriptAnalysis.id == row.id).values(status="running"))
                return str(row.id), row.tenant_id, script.sha256, script.text

    async def _failed(self, analysis_id, tenant_id, sha256, reason) -> AnalysisOutcome:
        return await self._record(analysis_id, tenant_id, {"status": "failed", "reason": reason}, "failed",
                                  {"script_sha256": sha256, "analyser_version": "1"}, reason)

    async def _record(self, analysis_id, tenant_id, values, status, details, reason) -> AnalysisOutcome:
        event = {"tenant_id": tenant_id, "event_type": EventType.SCRIPT_ANALYZED, "status": status, "details": details}
        if reason:
            event["reason"] = reason
        try:
            await self._transition(analysis_id, values, event)
        except AuditUnavailable:
            alert_log.critical("analysis_record_not_written analysis_id=%s", analysis_id)
            # Never approvable without its record: fail the row alone.
            await self._transition(analysis_id, {"status": "failed", "reason": "audit_unavailable"}, None)
            return AnalysisOutcome(analysis_id, "failed", "audit_unavailable")
        return AnalysisOutcome(analysis_id, status, reason)

    async def _transition(self, analysis_id: str, values: dict, event: dict | None) -> None:
        async with self._sessionmaker() as session:
            async with session.begin():
                await session.execute(update(ScriptAnalysis).where(
                    ScriptAnalysis.id == uuid.UUID(analysis_id), ScriptAnalysis.status == "running"
                ).values(**values, ended_at=func.now()))
                if event is not None:
                    await self._writer.append(chain_id=event["tenant_id"], event=event)
