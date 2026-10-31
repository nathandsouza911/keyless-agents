"""Load and verify a tenant's audit chain as stored in Postgres.

details is fetched as the text PostgreSQL returns for the stored jsonb and
kept alongside the parsed value (StoredRecord), so:
- a malformed or pathologically nested value (possible only for a role that
  can bypass the CHECK constraints) becomes a verification finding instead
  of crashing the load, and
- checkpoint fingerprints are computed over the persisted value itself,
  never over a re-serialization that could silently change it (N1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import Text, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from clw.audit.chain import ChainReport, verify_records
from clw.audit.events import AuditRecord
from clw.db.models.audit_event import AuditEventRow

_COLUMNS = [name for name in AuditRecord.__dataclass_fields__ if name != "details"]


@dataclass(frozen=True)
class StoredRecord:
    """A record as persisted: parsed fields plus details exactly as returned."""

    record: AuditRecord
    details_text: str | None

    @classmethod
    def from_record(cls, record: AuditRecord) -> "StoredRecord":
        """For records that were never stored (tests, in-memory chains)."""
        try:
            text = json.dumps(record.details, ensure_ascii=False, allow_nan=True, default=repr)
        except (ValueError, RecursionError, TypeError):
            text = repr(record.details)
        return cls(record, text)


def _parse_details(text: str | None) -> object:
    try:
        return json.loads(text) if text is not None else None
    except (ValueError, RecursionError):
        return None  # verifier reports the record as malformed / unhashable


async def load_stored_chain(session: AsyncSession, *, chain_id: str, after_seq: int = 0) -> list[StoredRecord]:
    stmt = (
        select(*(getattr(AuditEventRow, c) for c in _COLUMNS), cast(AuditEventRow.details, Text).label("details"))
        .where(AuditEventRow.chain_id == chain_id, AuditEventRow.seq > after_seq)
        .order_by(AuditEventRow.seq)
    )
    rows = (await session.execute(stmt)).mappings().all()
    return [
        StoredRecord(
            AuditRecord(**{c: row[c] for c in _COLUMNS}, details=_parse_details(row["details"])),  # type: ignore[arg-type]
            row["details"],
        )
        for row in rows
    ]


async def load_chain(session: AsyncSession, *, chain_id: str, after_seq: int = 0) -> list[AuditRecord]:
    return [s.record for s in await load_stored_chain(session, chain_id=chain_id, after_seq=after_seq)]


async def verify_chain(session: AsyncSession, *, chain_id: str) -> ChainReport:
    return verify_records(await load_chain(session, chain_id=chain_id), chain_id=chain_id)
