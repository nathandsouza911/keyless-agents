"""tenants, workbench_users and oidc_logins (Task 6, SD-029)

Revision ID: 20261020_tenants_users
Revises: 20261019_audit_ts_no_escapes
Create Date: 2026-10-16

The plan names this revision 20261013_tenants_users; the date prefix follows
the existing chain instead, so the file order matches the upgrade order.

tenants: registered Entra tenants (id = tid, lowercase GUID); only `active`
tenants can sign in. workbench_users: membership and role per (tenant, oid).
oidc_logins: single-use sign-in records holding SHA-256 hashes only.

No grants are made here: database roles for the api are created with the
deployment, not by migrations (as for audit_events).
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "20261020_tenants_users"
down_revision = "20261019_audit_ts_no_escapes"
branch_labels = None
depends_on = None

_GUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_HEX64 = "^[0-9a-f]{64}$"


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("display_name", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"id ~ '{_GUID}'", name="ck_tenants_id_guid"),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="ck_tenants_status"),
    )
    op.create_table(
        "workbench_users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("oid", sa.String(36), nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "oid", name="uq_workbench_users_tenant_oid"),
        sa.CheckConstraint(f"oid ~ '{_GUID}'", name="ck_workbench_users_oid_guid"),
        sa.CheckConstraint("role IN ('analyst', 'security_lead')", name="ck_workbench_users_role"),
    )
    op.create_table(
        "oidc_logins",
        sa.Column("state_hash", sa.String(64), primary_key=True),
        sa.Column("nonce_hash", sa.String(64), nullable=False),
        sa.Column("binding_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(f"state_hash ~ '{_HEX64}'", name="ck_oidc_logins_state_hash"),
        sa.CheckConstraint(f"nonce_hash ~ '{_HEX64}'", name="ck_oidc_logins_nonce_hash"),
        sa.CheckConstraint(f"binding_hash ~ '{_HEX64}'", name="ck_oidc_logins_binding_hash"),
    )
    op.create_index("ix_oidc_logins_created_at", "oidc_logins", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_oidc_logins_created_at", table_name="oidc_logins")
    op.drop_table("oidc_logins")
    op.drop_table("workbench_users")
    op.drop_table("tenants")
