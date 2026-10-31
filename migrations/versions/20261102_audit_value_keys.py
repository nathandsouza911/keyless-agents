"""Per-tenant keys for hashing free-text query values in the audit chain (SD-042)

Revision ID: 20261102_audit_value_keys
Revises: 20261101_audit_schema_v3
Create Date: 2026-10-25

A facade request's $filter and $search values can hold personal data (a name
in `displayName eq '...'`). The chain records them as an HMAC-SHA256 under
the tenant's key (`clwhash.<key_id>.<hex>`), never as written. One key per
tenant:

- audit_value_keys(tenant_id, key_id, key, created_at): key_id 8 lowercase
  hex, key exactly 32 bytes.
- The broker role may read and create a key (clw.db.roles), never change or
  delete one. Deleting a tenant's key (owner role) "shreds" every value hash
  made with it: nobody can tie those hashes to values any more. The next
  facade request then creates a new key under a new key_id.
"""

import sqlalchemy as sa
from alembic import op

revision = "20261102_audit_value_keys"
down_revision = "20261101_audit_schema_v3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_value_keys",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), primary_key=True),
        sa.Column("key_id", sa.Text, nullable=False),
        sa.Column("key", sa.LargeBinary, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("key_id ~ '^[0-9a-f]{8}$'", name="ck_audit_value_keys_key_id"),
        sa.CheckConstraint("octet_length(key) = 32", name="ck_audit_value_keys_key_len"),
    )


def downgrade() -> None:
    op.drop_table("audit_value_keys")
