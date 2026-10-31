"""audit_events hardening after security review gate 1 (H1, H2, H3)

Revision ID: 20261015_audit_hardening
Revises: 20261014_audit_events
Create Date: 2026-10-15

H1  Trigger functions are recreated with every table reference schema-
    qualified (public.audit_events) and a pinned search_path
    (pg_catalog, pg_temp), so a temporary table named audit_events can no
    longer shadow the real one. TEMPORARY on this database and CREATE on
    schema public are revoked from PUBLIC.
H2  CHECK constraints: lowercase-hex hashes, known event types, fixed
    created_at format, schema_version = 2, details is a JSON object no
    deeper than 15 levels (the record-level canonical limit is 16).
H3  The insert trigger also rejects a created_at earlier than the head's.

Upgrade implications:
- Rows written under schema v1 cannot satisfy schema_version = 2. The
  upgrade refuses to run if any exist. None exist outside test databases;
  there is no automatic conversion because re-hashing would rewrite
  evidence. See docs/runbooks/audit-chain-recovery.md.
- Revoking TEMPORARY from PUBLIC affects every role without an explicit
  grant on this database; the application does not use temporary tables.
"""

from alembic import op

revision = "20261015_audit_hardening"
down_revision = "20261014_audit_events"
branch_labels = None
depends_on = None

EVENT_TYPES = (
    "RUN_REQUESTED", "RUN_STARTED", "OP_DECISION", "CREDENTIAL_ACQUIRED", "CREDENTIAL_REJECTED",
    "GRAPH_REQUEST", "GRAPH_RESPONSE", "RUN_COMPLETED", "RUN_FAILED", "RUN_TIMED_OUT", "CHAIN_RECOVERY",
)

_REFUSE_V1 = r"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.audit_events WHERE schema_version <> 2) THEN
        RAISE EXCEPTION 'audit_events contains records with schema_version <> 2; '
            'refusing to upgrade (see docs/runbooks/audit-chain-recovery.md)';
    END IF;
END
$$
"""

_REJECT_FN = r"""
CREATE OR REPLACE FUNCTION public.clw_audit_events_reject_change() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$
"""

_APPEND_FN = r"""
CREATE OR REPLACE FUNCTION public.clw_audit_events_check_append() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    head_seq integer;
    head_hash text;
    head_created text;
BEGIN
    SELECT e.seq, e.record_hash, e.created_at INTO head_seq, head_hash, head_created
      FROM public.audit_events AS e
     WHERE e.chain_id = NEW.chain_id
     ORDER BY e.seq DESC
     LIMIT 1;
    IF head_seq IS NULL THEN
        IF NEW.seq <> 1 OR NEW.previous_hash <> pg_catalog.repeat('0', 64) THEN
            RAISE EXCEPTION 'audit_events: first record of chain must be seq 1 linked to genesis'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.seq <> head_seq + 1 OR NEW.previous_hash <> head_hash THEN
        RAISE EXCEPTION 'audit_events: insert must extend the chain head (expected seq %)', head_seq + 1
            USING ERRCODE = 'check_violation';
    ELSIF NEW.created_at < head_created THEN
        RAISE EXCEPTION 'audit_events: created_at must not precede the chain head'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

_DEPTH_FN = r"""
CREATE FUNCTION public.clw_jsonb_depth(j jsonb) RETURNS integer
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
    WITH RECURSIVE walk(v, d) AS (
        SELECT j, 1
        UNION ALL
        SELECT child.value, walk.d + 1
          FROM walk
          CROSS JOIN LATERAL (
              SELECT e.value FROM jsonb_each(
                  CASE WHEN jsonb_typeof(walk.v) = 'object' THEN walk.v ELSE '{}'::jsonb END) AS e
              UNION ALL
              SELECT a.value FROM jsonb_array_elements(
                  CASE WHEN jsonb_typeof(walk.v) = 'array' THEN walk.v ELSE '[]'::jsonb END) AS a
          ) AS child
         WHERE walk.d <= 16  -- stop early: anything past 16 is already too deep
    )
    SELECT max(d) FROM walk
$$
"""

_REVOKES = (
    """DO $$
       BEGIN
           EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
       END
       $$""",
    "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    "REVOKE ALL ON FUNCTION public.clw_audit_events_reject_change() FROM PUBLIC",
    "REVOKE ALL ON FUNCTION public.clw_audit_events_check_append() FROM PUBLIC",
)

_CONSTRAINTS = (
    ("ck_audit_events_record_hash_hex", "record_hash ~ '^[0-9a-f]{64}$'"),
    ("ck_audit_events_previous_hash_hex", "previous_hash ~ '^[0-9a-f]{64}$'"),
    ("ck_audit_events_event_type_known", "event_type IN (" + ", ".join(f"'{t}'" for t in EVENT_TYPES) + ")"),
    ("ck_audit_events_created_at_format", r"created_at ~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$'"),
    ("ck_audit_events_schema_version", "schema_version = 2"),
    ("ck_audit_events_details_object", "jsonb_typeof(details) = 'object'"),
    ("ck_audit_events_details_depth", "public.clw_jsonb_depth(details) <= 15"),
    ("ck_audit_events_manifest_hex", "task_manifest_sha256 IS NULL OR task_manifest_sha256 ~ '^[0-9a-f]{64}$'"),
)


def upgrade() -> None:
    op.execute(_REFUSE_V1)
    op.execute(_REJECT_FN)
    op.execute(_APPEND_FN)
    op.execute(_DEPTH_FN)
    for statement in _REVOKES:
        op.execute(statement)
    for name, condition in _CONSTRAINTS:
        op.create_check_constraint(name, "audit_events", condition)


def downgrade() -> None:
    raise RuntimeError("downgrade of 20261015_audit_hardening is not supported (it would weaken audit protections)")
