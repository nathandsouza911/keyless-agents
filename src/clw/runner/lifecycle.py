"""Run-state transitions owned by the runner (Task 14; SD-014, SD-032, SD-034).

Every transition is one pattern, so that the run row, the audit chain and
the broker cannot disagree about whether a run has ended:

  1. in a transaction, lock the run row (SELECT ... FOR UPDATE) and check its
     status is one the transition may start from;
  2. update the row (status, outcome, result, token revoked, timestamps);
  3. append the audit record (the writer commits it on its own);
  4. commit the row.

While the row is locked, the broker's own status changes (fail, halt) wait
for it, and see the run ended afterwards (they are conditional on
`status = 'running'`). Broker records that race the terminal record are
ordered by the chain's advisory lock: those before it stand (a timeout or
failure may follow open intents, which the verifier lists); those after it
are refused by the writer (SD-034, `run_ended`) and the broker withholds
their data. So nothing follows a run's terminal record, and a completion is
refused while one of the run's requests is unanswered
(`outstanding_requests`).

If step 3 fails, the row change is rolled back. A completion then becomes a
failure. A failure or timeout whose record cannot be written is still applied
to the row alone (status ended, token revoked) and alerted, so a run whose
audit is down cannot stay usable; its chain then has no terminal record
(visible: the run is open in the chain, ended in the table). If the commit
in step 4 fails after the record was written, the chain says the run ended
and the row does not; the reconciler later ends the row (its own record is
refused as `run_ended`, and it ends the row alone).

Who ends a run:
  broker      failed (credential, Graph, binding, manifest change), halted
  launcher    running; failed (manifest or params invalid, launch failure,
              task error, invalid or oversized result, result not
              recordable); completed; timed_out (deadline); a halted run is
              failed / audit_unavailable when its task ends (threat-model §5.2)
  reconciler  running past the deadline: timed_out / outcome_unrecorded;
              halted past the deadline: failed / audit_unavailable
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.events import AuditRunStateRefused, AuditUnavailable, EventType
from clw.db.models.run import Run

alert_log = logging.getLogger("clw.runner.alert")

TERMINAL_STATUSES = frozenset({"completed", "failed", "timed_out"})
_EVENT = {"completed": EventType.RUN_COMPLETED, "failed": EventType.RUN_FAILED, "timed_out": EventType.RUN_TIMED_OUT}
# Default starting states; ending a queued run (it never started) or a
# halted one (failed / audit_unavailable) is always asked for explicitly.
_FROM = {"completed": frozenset({"running"}), "failed": frozenset({"running"}), "timed_out": frozenset({"running"})}
QUEUED = frozenset({"queued"})
HALTED = frozenset({"halted"})


class Ended(Enum):
    RECORDED = "recorded"        # row and audit record both written
    ROW_ONLY = "row_only"        # row ended, audit record could not be written
    NOT_ENDED = "not_ended"      # the row was not in a state this transition may start from


@dataclass(frozen=True, slots=True)
class RunKey:
    run_id: str
    tenant_id: str


class CompletionRefused(Exception):
    """A completion was not recorded; the reason says why (the run is not ended by this)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _event(run: RunKey, status: str, reason: str, details: dict, result_sha256: str | None) -> dict:
    event: dict[str, object] = {"tenant_id": run.tenant_id, "event_type": _EVENT[status], "status": status,
                                "run_id": run.run_id, "details": dict(details)}
    if status == "completed":
        event["outcome"] = reason
        event["details"] = {**details, "result_sha256": result_sha256}
    else:
        event["reason"] = reason
    return event


class RunLifecycle:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], writer) -> None:
        self._sessionmaker = sessionmaker
        self._writer = writer

    async def status(self, run: RunKey) -> str | None:
        async with self._sessionmaker() as session:
            return await session.scalar(select(Run.status).where(Run.id == uuid.UUID(run.run_id),
                                                                 Run.tenant_id == run.tenant_id))

    async def _transition(self, run: RunKey, status: str, reason: str, *, details: dict | None = None,
                          result: dict | None = None, result_sha256: str | None = None,
                          from_statuses: frozenset[str] | None = None, record: bool = True) -> bool:
        """Steps 1-4. False if the row was not in a starting state. Raises
        AuditUnavailable (or a subclass) if the record could not be written;
        the row is then unchanged."""
        allowed = from_statuses or _FROM[status]
        async with self._sessionmaker() as session:
            async with session.begin():
                current = await session.scalar(
                    select(Run.status).where(Run.id == uuid.UUID(run.run_id), Run.tenant_id == run.tenant_id)
                    .with_for_update())
                if current not in allowed:
                    return False
                values: dict[str, object] = {"status": status, "outcome": reason, "run_token_sha256": None,
                                             "ended_at": func.now(), "updated_at": func.now()}
                if result is not None:
                    values["result"] = result
                await session.execute(update(Run).where(Run.id == uuid.UUID(run.run_id)).values(**values))
                if record:
                    await self._writer.append(chain_id=run.tenant_id,
                                              event=_event(run, status, reason, details or {}, result_sha256))
        return True

    async def complete(self, run: RunKey, result: dict, sha256: str) -> None:
        """Store the result and record RUN_COMPLETED, or raise CompletionRefused
        (`run_not_running`, `outstanding_requests`, `run_ended`,
        `audit_unavailable`, `result_unpersisted`) with nothing changed."""
        try:
            done = await self._transition(run, "completed", "succeeded", result=result, result_sha256=sha256)
        except AuditRunStateRefused as exc:
            raise CompletionRefused(exc.reason) from None
        except AuditUnavailable:
            raise CompletionRefused("audit_unavailable") from None
        except Exception:  # noqa: BLE001 - the row could not be written; nothing was recorded
            raise CompletionRefused("result_unpersisted") from None
        if not done:
            raise CompletionRefused("run_not_running")

    async def end(self, run: RunKey, status: str, reason: str, *, details: dict | None = None,
                  from_statuses: frozenset[str] | None = None) -> Ended:
        """End a run failed or timed_out. The token is revoked even when the
        audit record cannot be written."""
        if status not in ("failed", "timed_out"):
            raise ValueError("end() is for failed and timed_out")
        try:
            if await self._transition(run, status, reason, details=details, from_statuses=from_statuses):
                return Ended.RECORDED
            return Ended.NOT_ENDED
        except AuditRunStateRefused:
            # The chain already holds this run's terminal record (an earlier
            # commit of ours was lost): end the row to match, record nothing.
            pass
        except AuditUnavailable:
            alert_log.critical("runner_terminal_record_not_written run_id=%s status=%s reason=%s",
                               run.run_id, status, reason)
        if await self._transition(run, status, reason, details=details, from_statuses=from_statuses, record=False):
            return Ended.ROW_ONLY
        return Ended.NOT_ENDED
