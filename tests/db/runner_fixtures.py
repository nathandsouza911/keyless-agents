"""Deterministic container fakes and run set-up for the runner tests (Task 14).

FakeProcess plays back scripted stdout chunks from the launcher's reader
thread. A chunk may be a callable (a hook run at that point, from the
reader thread), and `hang=True` keeps stdout open until the process is
killed. Nothing here sleeps to arrange an order: hooks and events do.
"""

from __future__ import annotations

import asyncio
import io
import json
import threading
import uuid
from collections.abc import Callable

from clw.audit.events import AuditUnavailable, EventType
from clw.broker.manifest import TaskManifest
from clw_task_sdk.result import emit_result
from tests.db.broker_fixtures import MANIFEST

RESULT = {"task_id": MANIFEST.id, "inactive_days": 90, "counts": {"dormant": 1, "active": 2},
          "dormant": [{"id": "u-1", "userPrincipalName": "u1@contoso.test", "displayName": "Zoë"}]}


def result_line(payload: dict = RESULT) -> bytes:
    out = io.StringIO()
    emit_result(payload, stream=out)
    return out.getvalue().encode("ascii")


class FakeProcess:
    def __init__(self, chunks=(), *, exit_code: int = 0, hang: bool = False, kill_fails: bool = False,
                 after_kill: bytes = b"") -> None:
        self.chunks = list(chunks)
        self.exit_code = exit_code
        self.hang = hang
        self.kill_fails = kill_fails
        self.after_kill = after_kill
        self.killed = threading.Event()
        self.kill_calls = 0
        self.removed = False
        self.kwargs: dict | None = None
        self.reading = threading.Event()  # set once the reader has started (and the run is running)

    def stdout(self):
        self.reading.set()
        for chunk in self.chunks:
            if callable(chunk):
                chunk(self)
            else:
                yield chunk
        if self.hang:
            self.killed.wait(30)
            if self.after_kill:
                yield self.after_kill

    def wait(self) -> int:
        return 137 if self.killed.is_set() else self.exit_code

    def kill(self) -> None:
        self.kill_calls += 1
        if self.kill_fails:
            raise RuntimeError("kill failed")
        self.killed.set()

    def remove(self) -> None:
        self.removed = True


class FakeBackend:
    def __init__(self, process: FakeProcess | Callable[[dict], FakeProcess] | None = None, *,
                 start_fails: bool = False, peer: str | None = "172.30.0.2") -> None:
        self._process = process or FakeProcess([result_line()])
        self.start_fails = start_fails
        self.peer = peer  # the address peer_address answers; None: no such peer
        self.peer_lookups: list[tuple[str, str]] = []
        self.started: list[dict] = []
        self.stdin: list[bytes | None] = []
        self.killed_runs: list[str] = []

    def start(self, kwargs: dict, stdin: bytes | None = None):
        self.started.append(kwargs)
        self.stdin.append(stdin)
        if self.start_fails:
            raise RuntimeError("docker unavailable")
        process = self._process(kwargs) if callable(self._process) else self._process
        process.kwargs = kwargs
        return process

    def kill_run(self, run_id: str) -> None:
        self.killed_runs.append(run_id)

    def peer_address(self, network: str, name: str) -> str | None:
        self.peer_lookups.append((network, name))
        return self.peer


def on_loop(loop: asyncio.AbstractEventLoop, coro) -> object:
    """Run a coroutine on the test's loop from the reader thread, and wait for it."""
    return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=60)


async def queue_run(admin_conn, writer, tenant, *, params: dict | None = None, manifest: TaskManifest = MANIFEST,
                    row: dict | None = None) -> str:
    """A queued run, as the API will create it (Task 16): the row and RUN_REQUESTED."""
    tid, user_id, oid = tenant
    run_id = uuid.uuid4()
    values = {"task_id": manifest.id, "task_manifest_sha256": manifest.sha256, "profile_id": manifest.profile.id,
              "profile_version": manifest.profile.version, "profile_sha256": manifest.profile.sha256,
              "auth_mode": manifest.mode} | (row or {})
    await admin_conn.execute(
        """INSERT INTO runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,
                             profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, 'queued')""",
        run_id, tid, *values.values(), user_id, oid, tid,
        json.dumps({"inactive_days": 90} if params is None else params))
    await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.RUN_REQUESTED, "status": "requested", "run_id": str(run_id),
        "task_id": manifest.id, "task_manifest_sha256": manifest.sha256, "actor_oid": oid, "actor_tid": tid})
    return str(run_id)


class FailingWriter:
    """Delegates to a real writer, failing the event types named."""

    def __init__(self, writer, *fail: str) -> None:
        self._writer = writer
        self.fail = set(fail)

    async def append(self, *, chain_id, event):
        if event["event_type"] in self.fail:
            raise AuditUnavailable("audit store down")  # what AuditWriter raises for every failure
        return await self._writer.append(chain_id=chain_id, event=event)


async def end_stray_queued_runs(admin_conn) -> None:
    """The launcher takes the oldest queued run in the database; queued rows left
    by other test modules (they share it) are ended first, as admin."""
    await admin_conn.execute("UPDATE runs SET status = 'failed', outcome = 'test_isolation', ended_at = now(), "
                             "run_token_sha256 = NULL WHERE status = 'queued'")
