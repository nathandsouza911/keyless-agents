"""audit_events: byte limits on text columns (gate 1 L-1)

Revision ID: 20261018_audit_text_limits
Revises: 20261017_audit_ts_session_free
Create Date: 2026-10-18

L-1 (third review): only details was bounded; a 200 MB reason was accepted
and verified valid. Every free-text column is now limited to 1024 bytes and
request_target to 4096 bytes, measured with octet_length(), which is the
UTF-8 byte length because the database encoding must be UTF8 (checked
below). The writer enforces the same limits (events.MAX_TEXT_BYTES,
events.MAX_REQUEST_TARGET_BYTES) and the verifier flags stored records over
them as invalid_event_shape.

The hash, timestamp, event type and tenant columns already have stricter
constraints; chain_id and tenant_id are included anyway.

Upgrade implications: before adding the constraint the upgrade counts rows
over the limits. If there are any, it aborts and changes nothing: audit
evidence is never truncated. Such rows must be handled as an incident
(docs/runbooks/audit-chain-recovery.md), not by a migration.
"""

from alembic import op

revision = "20261018_audit_text_limits"
down_revision = "20261017_audit_ts_session_free"
branch_labels = None
depends_on = None

TEXT_COLUMNS = (
    "chain_id", "tenant_id", "event_type", "status", "reason", "outcome", "run_id", "task_id",
    "task_manifest_sha256", "profile_id", "auth_mode", "actor_oid", "actor_tid", "operation",
    "http_method", "path_template", "graph_request_id",
)
TEXT_BOUNDS = " AND ".join(
    [f"octet_length(coalesce({c}, '')) <= 1024" for c in TEXT_COLUMNS]
    + ["octet_length(coalesce(request_target, '')) <= 4096"]
)

_PRECHECK = r"""
DO $$
DECLARE
    bad bigint;
BEGIN
    IF pg_catalog.current_setting('server_encoding') <> 'UTF8' THEN
        RAISE EXCEPTION '20261018: the database encoding must be UTF8 so octet_length() counts UTF-8 bytes';
    END IF;
    SELECT count(*) INTO bad FROM public.audit_events WHERE NOT (""" + TEXT_BOUNDS + r""");
    IF bad > 0 THEN
        RAISE EXCEPTION '20261018: % existing audit_events rows exceed the text limits; nothing was changed '
                        '(audit evidence is never truncated; see docs/runbooks/audit-chain-recovery.md)', bad;
    END IF;
END;
$$
"""


def upgrade() -> None:
    op.execute(_PRECHECK)
    op.create_check_constraint("ck_audit_events_text_bounds", "audit_events", TEXT_BOUNDS)


def downgrade() -> None:
    raise RuntimeError("downgrade of 20261018_audit_text_limits is not supported (it would restore L-1)")
