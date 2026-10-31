"""audit_events: timestamp checks independent of session settings (gate 1 M-1)

Revision ID: 20261017_audit_ts_session_free
Revises: 20261016_audit_time_size
Create Date: 2026-10-17

M-1 (third review): clw_valid_created_at parsed with to_timestamp(), which
interprets its input in the session TimeZone. Any role can SET TIME ZONE, so
the application role could make a valid head timestamp look invalid (for
example under Europe/London in summer), which disabled the trigger's
"not before the head" rule and let a backdated record in. On a database
whose default TimeZone was not UTC, valid timestamps were rejected outright.

This revision replaces both functions:
- clw_valid_created_at checks the fixed format, the field ranges and the
  calendar date with make_date() only. Nothing it calls reads TimeZone,
  DateStyle, lc_time or any other session setting, so IMMUTABLE is now true.
- clw_audit_events_check_append compares timestamps with COLLATE "C" (the
  code-point order Python uses), so the database collation cannot change the
  comparison. The clock bound uses clock_timestamp() AT TIME ZONE 'UTC',
  which does not depend on the session TimeZone.

Upgrade implications: no schema change. The upgrade re-validates every
existing row against the new function and aborts (nothing is changed or
removed) if any row fails; such rows need the recovery runbook, not a
migration. The CHECK constraint ck_audit_events_created_at_valid keeps its
name and now calls the replaced function.
"""

from alembic import op

revision = "20261017_audit_ts_session_free"
down_revision = "20261016_audit_time_size"
branch_labels = None
depends_on = None

_VALID_TS_FN = r"""
CREATE OR REPLACE FUNCTION public.clw_valid_created_at(t text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF (t COLLATE "C") !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$' THEN
        RETURN false;
    END IF;
    IF substr(t, 12, 2)::integer > 23 OR substr(t, 15, 2)::integer > 59 OR substr(t, 18, 2)::integer > 59 THEN
        RETURN false;
    END IF;
    -- make_date raises for year 0 and for impossible dates (2026-02-30, month 13).
    PERFORM pg_catalog.make_date(substr(t, 1, 4)::integer, substr(t, 6, 2)::integer, substr(t, 9, 2)::integer);
    RETURN true;
EXCEPTION WHEN others THEN
    RETURN false;
END;
$$
"""

_NOW_PLUS_SKEW = (
    "pg_catalog.to_char((pg_catalog.clock_timestamp() + interval '5 minutes') AT TIME ZONE 'UTC', "
    "'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
)

_APPEND_FN = r"""
CREATE OR REPLACE FUNCTION public.clw_audit_events_check_append() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    head_seq integer;
    head_hash text;
    head_created text;
    limit_ts text := """ + _NOW_PLUS_SKEW + r""";
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
    END IF;
    IF (NEW.created_at COLLATE "C") > (limit_ts COLLATE "C") THEN
        RAISE EXCEPTION 'audit_events: created_at is more than 5 minutes ahead of the database clock'
            USING ERRCODE = 'check_violation';
    END IF;
    IF head_seq IS NOT NULL
       AND public.clw_valid_created_at(head_created)
       AND (head_created COLLATE "C") <= (limit_ts COLLATE "C")
       AND (NEW.created_at COLLATE "C") < (head_created COLLATE "C") THEN
        RAISE EXCEPTION 'audit_events: created_at must not precede the chain head'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

_REVALIDATE = r"""
DO $$
DECLARE
    bad bigint;
BEGIN
    SELECT count(*) INTO bad FROM public.audit_events WHERE NOT public.clw_valid_created_at(created_at);
    IF bad > 0 THEN
        RAISE EXCEPTION '20261017: % existing audit_events rows fail the session-independent timestamp check; '
                        'nothing was changed (see docs/runbooks/audit-chain-recovery.md)', bad;
    END IF;
END;
$$
"""


def upgrade() -> None:
    op.execute(_VALID_TS_FN)
    op.execute(_APPEND_FN)
    op.execute(_REVALIDATE)


def downgrade() -> None:
    raise RuntimeError("downgrade of 20261017_audit_ts_session_free is not supported (it would restore M-1)")
