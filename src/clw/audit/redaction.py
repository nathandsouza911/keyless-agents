"""Audited removal of a completed run's stored result (SD-037).

A run result can hold personal data. redact_result removes it without
touching the audit chain's existing records, in this order:

  1. lock the run row (SELECT ... FOR UPDATE); it must be the chain's tenant's
     run, `completed`, and still hold its result;
  2. the stored result must re-hash to its RUN_COMPLETED digest
     (verify_run_result == "ok"); a result that does not is evidence of
     tampering and is never removed by this procedure;
  3. append RESULT_REDACTED (operator, reason, run id, that digest) through
     the fail-closed writer, so the removal is recorded before it happens;
  4. clear runs.result and set result_redacted_at, and commit.

If step 3 fails nothing is removed. If step 4's commit fails after step 3,
the chain records a redaction the row has not had; running the procedure
again finds that record, appends nothing and completes step 4 (resumed).
The database allows the change only together with result_redacted_at
(migration 20261025_result_redaction), which no application role may set.

Afterwards the chain still verifies; verify_run_result reports "redacted".
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from sqlalchemy import func, null, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.chain import verify_run_result
from clw.audit.events import AuditRecord, EventType
from clw.audit.verifier import load_chain
from clw.db.models.run import Run

_MAX_TEXT = 256
_PRINTABLE = re.compile(r"[\x20-\x7e]+")


class RedactionRefused(Exception):
    """Nothing was recorded or removed. The message says why (no result data)."""


@dataclass(frozen=True, slots=True)
class Redacted:
    run_id: str
    result_sha256: str
    redaction_seq: int
    resumed: bool  # the RESULT_REDACTED record already existed (an earlier attempt's row commit was lost)


def _text(name: str, value: object) -> str:
    if not (isinstance(value, str) and 0 < len(value) <= _MAX_TEXT and _PRINTABLE.fullmatch(value)):
        raise RedactionRefused(f"{name} must be 1 to {_MAX_TEXT} printable ASCII characters")
    return value


def _redaction_for(records: list[AuditRecord], run_id: str) -> AuditRecord | None:
    for record in records:
        details = record.details if isinstance(record.details, dict) else {}
        if record.event_type == EventType.RESULT_REDACTED and details.get("redacted_run_id") == run_id:
            return record
    return None


async def redact_result(
    sessionmaker: async_sessionmaker[AsyncSession], writer, *, chain_id: str, run_id: str, operator: str, reason: str,
) -> Redacted:
    operator, reason = _text("operator", operator), _text("reason", reason)
    try:
        rid = uuid.UUID(run_id)
    except (ValueError, AttributeError, TypeError):
        raise RedactionRefused("run id is not a UUID") from None
    run_id = str(rid)

    async with sessionmaker() as session:
        async with session.begin():
            row = (await session.execute(
                select(Run).where(Run.id == rid, Run.tenant_id == chain_id).with_for_update())).scalar_one_or_none()
            if row is None:
                raise RedactionRefused("no such run in this chain's tenant")
            if row.status != "completed" or row.result is None:
                raise RedactionRefused(
                    "run is not completed" if row.status != "completed" else "run holds no result (already redacted)")

            records = await load_chain(session, chain_id=chain_id)
            completion = next((r for r in records
                               if r.event_type == EventType.RUN_COMPLETED and r.run_id == run_id), None)
            if completion is None:
                raise RedactionRefused("the chain has no RUN_COMPLETED for this run")
            if verify_run_result(completion, row.result) != "ok":
                raise RedactionRefused("stored result does not match its RUN_COMPLETED digest; investigate, do not redact")
            digest = completion.details["result_sha256"]

            existing = _redaction_for(records, run_id)
            if existing is not None and existing.details.get("result_sha256") != digest:
                raise RedactionRefused("the chain already records a redaction of this run with another digest")
            record = existing or await writer.append(chain_id=chain_id, event={
                "tenant_id": chain_id, "event_type": EventType.RESULT_REDACTED, "status": "recorded",
                "reason": reason, "actor_oid": operator,
                "details": {"redacted_run_id": run_id, "result_sha256": digest}})

            # null(), not None: None in a JSONB column is the JSON value null,
            # which the database rightly refuses as a change to the result.
            await session.execute(update(Run).where(Run.id == rid).values(
                result=null(), result_redacted_at=func.now(), updated_at=func.now()))
    return Redacted(run_id=run_id, result_sha256=digest, redaction_seq=record.seq, resumed=existing is not None)
