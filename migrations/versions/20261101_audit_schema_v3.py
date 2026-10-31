"""Audit schema v3: facade targets and script records (SD-040)

Revision ID: 20261101_audit_schema_v3
Revises: 20261025_result_redaction
Create Date: 2026-10-25

- ck_audit_events_schema_version: 2 or 3 (new records are written as v3; v2
  records stay and are verified under v2's rules).
- ck_audit_events_event_type_known: adds SCRIPT_SUBMITTED, SCRIPT_ANALYZED and
  MANIFEST_APPROVED.

The per-version rules (a /beta request target, the script records' shapes and
cross-record rules) live in clw.audit.events and clw.audit.chain; the database
keeps its structural bounds. Downgrade is refused once any v3 record exists:
going back would make those records invalid evidence.
"""

from alembic import op

revision = "20261101_audit_schema_v3"
down_revision = "20261025_result_redaction"
branch_labels = None
depends_on = None

_BEFORE = (
    "RUN_REQUESTED", "RUN_STARTED", "OP_DECISION", "CREDENTIAL_ACQUIRED", "CREDENTIAL_REJECTED",
    "GRAPH_REQUEST", "GRAPH_RESPONSE", "RUN_COMPLETED", "RUN_FAILED", "RUN_TIMED_OUT", "CHAIN_RECOVERY",
    "RESULT_REDACTED",
)
_AFTER = (*_BEFORE, "SCRIPT_SUBMITTED", "SCRIPT_ANALYZED", "MANIFEST_APPROVED")


def _known(types: tuple[str, ...]) -> str:
    return "event_type IN (" + ", ".join(f"'{t}'" for t in types) + ")"


_REFUSE_IF_V3 = r"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.audit_events WHERE schema_version = 3) THEN
        RAISE EXCEPTION 'v3 audit records exist; refusing to downgrade 20261101_audit_schema_v3';
    END IF;
END
$$
"""


def upgrade() -> None:
    op.drop_constraint("ck_audit_events_schema_version", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_schema_version", "audit_events", "schema_version IN (2, 3)")
    op.drop_constraint("ck_audit_events_event_type_known", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_event_type_known", "audit_events", _known(_AFTER))


def downgrade() -> None:
    op.execute(_REFUSE_IF_V3)
    op.drop_constraint("ck_audit_events_event_type_known", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_event_type_known", "audit_events", _known(_BEFORE))
    op.drop_constraint("ck_audit_events_schema_version", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_schema_version", "audit_events", "schema_version = 2")
