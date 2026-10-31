"""change_proposals (v0.1, SD-054)

Revision ID: 20261105_change_proposals
Revises: 20261104_agent_sessions
Create Date: 2026-10-31

A change an agent asked for, filed for a person to review and never executed
in v0.1. One row per proposal, written by the broker only, and never changed.

- The proposal binds to the target's object id and the canonical request
  (request, request_sha256); the hash is also in the session's audit chain
  (the OP_DECISION that refused the write names it).
- The target's display name, UPN and accountEnabled are a display snapshot,
  taken by the broker's own lookup at looked_up_at. They are tenant data:
  untrusted, shown escaped and labelled, never part of the binding.
- lookup_status: found (snapshot present), or not_found (no user with that id,
  or the object is not a user; snapshot absent).
- BEFORE INSERT guard: the session is a running agent session of the same
  tenant. BEFORE UPDATE: refused (clw_refuse_update, 20261103_scripts).
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "20261105_change_proposals"
down_revision = "20261104_agent_sessions"
branch_labels = None
depends_on = None

_HEX64 = "^[0-9a-f]{64}$"
_GUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

# No backslashes in the body (SD-019).
_GUARD_FN = r"""
CREATE FUNCTION public.clw_change_proposals_guard_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.runs r WHERE r.id = NEW.session_id AND r.tenant_id = NEW.tenant_id
                   AND r.kind = 'agent_session' AND r.status = 'running') THEN
        RAISE EXCEPTION 'change_proposals: not a running agent session of this tenant'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "change_proposals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("operation", sa.Text, nullable=False),
        sa.Column("target_id", sa.String(36), nullable=False),
        sa.Column("request", JSONB, nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("agent_reason", sa.Text, nullable=False),
        sa.Column("lookup_status", sa.Text, nullable=False),
        sa.Column("target_display_name", sa.Text, nullable=True),
        sa.Column("target_upn", sa.Text, nullable=True),
        sa.Column("target_account_enabled", sa.Boolean, nullable=True),
        sa.Column("looked_up_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("action = 'disable_user' AND operation = 'users.update'", name="ck_change_proposals_action"),
        sa.CheckConstraint(f"target_id ~ '{_GUID}'", name="ck_change_proposals_target_guid"),
        sa.CheckConstraint(f"request_sha256 ~ '{_HEX64}'", name="ck_change_proposals_request_hex"),
        sa.CheckConstraint("jsonb_typeof(request) = 'object'", name="ck_change_proposals_request_object"),
        sa.CheckConstraint("char_length(agent_reason) <= 500", name="ck_change_proposals_reason_length"),
        sa.CheckConstraint("lookup_status IN ('found', 'not_found')", name="ck_change_proposals_lookup_status"),
        sa.CheckConstraint("lookup_status = 'found' OR (target_display_name IS NULL AND target_upn IS NULL "
                           "AND target_account_enabled IS NULL)", name="ck_change_proposals_snapshot"),
        sa.CheckConstraint("target_display_name IS NULL OR char_length(target_display_name) <= 512",
                           name="ck_change_proposals_name_length"),
        sa.CheckConstraint("target_upn IS NULL OR char_length(target_upn) <= 512",
                           name="ck_change_proposals_upn_length"),
    )
    op.create_index("ix_change_proposals_tenant_id", "change_proposals", ["tenant_id"])
    op.create_index("ix_change_proposals_session_id", "change_proposals", ["session_id"])
    op.execute(_GUARD_FN)
    op.execute("REVOKE ALL ON FUNCTION public.clw_change_proposals_guard_insert() FROM PUBLIC")
    op.execute("CREATE TRIGGER change_proposals_guard_insert BEFORE INSERT ON public.change_proposals "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_change_proposals_guard_insert()")
    op.execute("CREATE TRIGGER change_proposals_guard_update BEFORE UPDATE ON public.change_proposals "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_refuse_update()")


def downgrade() -> None:
    op.execute("DROP TRIGGER change_proposals_guard_update ON public.change_proposals")
    op.execute("DROP TRIGGER change_proposals_guard_insert ON public.change_proposals")
    op.execute("DROP FUNCTION public.clw_change_proposals_guard_insert()")
    op.drop_index("ix_change_proposals_session_id", table_name="change_proposals")
    op.drop_index("ix_change_proposals_tenant_id", table_name="change_proposals")
    op.drop_table("change_proposals")
