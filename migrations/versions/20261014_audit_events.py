"""audit_events: append-only hash chain (SD-005, SD-006)

Revision ID: 20261014_audit_events
Revises:
Create Date: 2026-10-14

Database-side guarantees (each covered by tests/db/test_audit_trigger.py):
- UPDATE and DELETE are rejected for every row, unconditionally (no
  write-once exception: the hash is computed before the single INSERT).
- TRUNCATE is rejected.
- INSERT must extend the chain head: seq = head.seq + 1 and
  previous_hash = head.record_hash (or seq 1 linked to genesis).
- (chain_id, seq) is the primary key, so concurrent writers cannot fork.

A role that owns the table or is superuser can disable these triggers;
that residual risk is documented in docs/threat-model.md section 6.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20261014_audit_events"
down_revision = None
branch_labels = None
depends_on = None

_TEXT_COLUMNS_NULLABLE = (
    "reason", "outcome", "run_id", "task_id", "task_manifest_sha256", "profile_id", "auth_mode",
    "actor_oid", "actor_tid", "operation", "http_method", "path_template", "request_target",
    "graph_request_id",
)
_INT_COLUMNS_NULLABLE = (
    "profile_version", "decision_seq", "http_status", "attempt", "item_count", "duration_ms",
)

_REJECT_FN = r"""
CREATE FUNCTION clw_audit_events_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$
"""

_APPEND_FN = r"""
CREATE FUNCTION clw_audit_events_check_append() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    head_seq integer;
    head_hash text;
BEGIN
    SELECT seq, record_hash INTO head_seq, head_hash
      FROM audit_events
     WHERE chain_id = NEW.chain_id
     ORDER BY seq DESC
     LIMIT 1;
    IF head_seq IS NULL THEN
        IF NEW.seq <> 1 OR NEW.previous_hash <> repeat('0', 64) THEN
            RAISE EXCEPTION 'audit_events: first record of chain must be seq 1 linked to genesis'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.seq <> head_seq + 1 OR NEW.previous_hash <> head_hash THEN
        RAISE EXCEPTION 'audit_events: insert must extend the chain head (expected seq %)', head_seq + 1
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

# asyncpg executes one statement per call, so each DDL statement is separate.
_TRIGGERS = (
    """CREATE TRIGGER audit_events_reject_update_delete
           BEFORE UPDATE OR DELETE ON audit_events
           FOR EACH ROW EXECUTE FUNCTION clw_audit_events_reject_change()""",
    """CREATE TRIGGER audit_events_reject_truncate
           BEFORE TRUNCATE ON audit_events
           FOR EACH STATEMENT EXECUTE FUNCTION clw_audit_events_reject_change()""",
    """CREATE TRIGGER audit_events_check_append
           BEFORE INSERT ON audit_events
           FOR EACH ROW EXECUTE FUNCTION clw_audit_events_check_append()""",
)


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("chain_id", sa.Text, primary_key=True),
        sa.Column("seq", sa.Integer, primary_key=True),
        sa.Column("schema_version", sa.Integer, nullable=False),
        sa.Column("tenant_id", sa.Text, nullable=False),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        *(sa.Column(name, sa.Text, nullable=True) for name in _TEXT_COLUMNS_NULLABLE),
        *(sa.Column(name, sa.Integer, nullable=True) for name in _INT_COLUMNS_NULLABLE),
        sa.Column("details", JSONB, nullable=False),
        sa.Column("created_at", sa.Text, nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("seq >= 1", name="ck_audit_events_seq_positive"),
        sa.CheckConstraint("char_length(record_hash) = 64", name="ck_audit_events_record_hash_len"),
        sa.CheckConstraint("char_length(previous_hash) = 64", name="ck_audit_events_previous_hash_len"),
        sa.CheckConstraint("tenant_id = chain_id", name="ck_audit_events_tenant_is_chain"),
    )
    op.create_index("ix_audit_events_run_id", "audit_events", ["run_id"])
    op.execute(_REJECT_FN)
    op.execute(_APPEND_FN)
    for statement in _TRIGGERS:
        op.execute(statement)


def downgrade() -> None:
    # Dropping the audit table destroys evidence; refuse rather than do it silently.
    raise RuntimeError("downgrade of 20261014_audit_events is not supported (it would destroy audit evidence)")
