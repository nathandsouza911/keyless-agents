"""audit_events: append-only, hash-chained (SD-005, SD-006).

One column per protected field plus record_hash. Immutability, chain
continuity and the full set of CHECK constraints are defined by the
migrations (20261014_audit_events through 20261019_audit_ts_no_escapes), which
are the source of truth; this model only describes the shape.
"""

from __future__ import annotations

from sqlalchemy import CheckConstraint, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from clw.audit.events import AuditRecord
from clw.db.base import Base


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint("seq >= 1", name="ck_audit_events_seq_positive"),
        CheckConstraint("char_length(record_hash) = 64", name="ck_audit_events_record_hash_len"),
        CheckConstraint("char_length(previous_hash) = 64", name="ck_audit_events_previous_hash_len"),
        CheckConstraint("tenant_id = chain_id", name="ck_audit_events_tenant_is_chain"),
    )

    chain_id: Mapped[str] = mapped_column(Text, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    tenant_id: Mapped[str] = mapped_column(Text, nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(Text)
    run_id: Mapped[str | None] = mapped_column(Text, index=True)
    task_id: Mapped[str | None] = mapped_column(Text)
    task_manifest_sha256: Mapped[str | None] = mapped_column(Text)
    profile_id: Mapped[str | None] = mapped_column(Text)
    profile_version: Mapped[int | None] = mapped_column(Integer)
    auth_mode: Mapped[str | None] = mapped_column(Text)
    actor_oid: Mapped[str | None] = mapped_column(Text)
    actor_tid: Mapped[str | None] = mapped_column(Text)
    operation: Mapped[str | None] = mapped_column(Text)
    decision_seq: Mapped[int | None] = mapped_column(Integer)
    http_method: Mapped[str | None] = mapped_column(Text)
    path_template: Mapped[str | None] = mapped_column(Text)
    request_target: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    graph_request_id: Mapped[str | None] = mapped_column(Text)
    attempt: Mapped[int | None] = mapped_column(Integer)
    item_count: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # Canonical RFC 3339 string: database-clock time formatted by the writer
    # (SD-017), stored as text exactly as hashed.
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    def to_record(self) -> AuditRecord:
        return AuditRecord(**{name: getattr(self, name) for name in AuditRecord.__dataclass_fields__})

    @classmethod
    def from_record(cls, record: AuditRecord) -> "AuditEventRow":
        return cls(**{name: getattr(record, name) for name in AuditRecord.__dataclass_fields__})
