"""The reconciler: end runs that nobody is seeing to their end (Task 14; threat-model §5.2).

sweep(), run at runner start-up and then every minute, ends every run whose
deadline (database clock) passed more than `grace` ago:

  running  timed_out / outcome_unrecorded   (its launcher stopped, or could
                                             not record the outcome)
           timed_out / session_expired      an agent session (SD-049): its TTL
                                             ran out, the normal end; the broker
                                             already refuses it from the deadline
  halted   failed / audit_unavailable       (the broker halted it after an
                                             audit failure)

through the same lifecycle as the launcher, so the token is revoked even if
the record cannot be written, and nothing is recorded after a terminal
record already in the chain. The grace leaves a live launcher, which kills
its task at the deadline, to record the precise outcome first. Any
container still left for the run is removed (best effort).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.db.models.run import Run
from clw.runner.backend import ContainerBackend
from clw.runner.lifecycle import HALTED, Ended, RunKey, RunLifecycle

alert_log = logging.getLogger("clw.runner.alert")

GRACE = timedelta(seconds=60)
SWEEP_LIMIT = 100


@dataclass(frozen=True, slots=True)
class Reconciled:
    run_id: str
    status: str
    reason: str
    ended: Ended


class Reconciler:
    def __init__(self, *, sessionmaker: async_sessionmaker[AsyncSession], writer,
                 backend: ContainerBackend | None = None, grace: timedelta = GRACE) -> None:
        self._sessionmaker = sessionmaker
        self._lifecycle = RunLifecycle(sessionmaker, writer)
        self._backend = backend
        self._grace = grace

    async def sweep(self) -> list[Reconciled]:
        async with self._sessionmaker() as session:
            rows = (await session.execute(
                select(Run.id, Run.tenant_id, Run.status, Run.kind)
                .where(Run.status.in_(("running", "halted")), Run.deadline_at < func.now() - self._grace)
                .order_by(Run.deadline_at).limit(SWEEP_LIMIT))).all()
        done: list[Reconciled] = []
        for run_id, tenant_id, status, kind in rows:
            run = RunKey(str(run_id), tenant_id)
            if status == "halted":
                ended = await self._lifecycle.end(run, "failed", "audit_unavailable", from_statuses=HALTED)
                outcome = ("failed", "audit_unavailable")
            else:
                reason = "session_expired" if kind == "agent_session" else "outcome_unrecorded"
                ended = await self._lifecycle.end(run, "timed_out", reason)
                outcome = ("timed_out", reason)
            if ended is Ended.NOT_ENDED:
                continue  # ended by someone else since the query
            done.append(Reconciled(run.run_id, *outcome, ended))
            if self._backend is not None and kind != "agent_session":  # a session has no container
                try:
                    await asyncio.to_thread(self._backend.kill_run, run.run_id)
                except Exception:  # noqa: BLE001 - the token is revoked; the container can do nothing
                    alert_log.warning("runner_container_not_removed run_id=%s", run.run_id)
        return done
