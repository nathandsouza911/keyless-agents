"""audit_events: timestamp validator without backslash escapes (gate 1 F-3)

Revision ID: 20261019_audit_ts_no_escapes
Revises: 20261018_audit_text_limits
Create Date: 2026-10-19

F-3 (fourth review): the regular expression in clw_valid_created_at
contained the literal '\\.'. A plpgsql function body is parsed in the calling
session, and with standard_conforming_strings = off the backslash is an
escape character there, so the pattern became '.' and accepted any
character in place of the decimal point. It only widened what the validator
accepted (the CHECK constraint ck_audit_events_created_at_format, parsed once
when it was created, still rejected such rows), but the function was not
independent of session settings as SD-019 claimed.

The pattern now uses the bracket expression [.] and contains no backslash,
so it means the same under every setting. Every other function body was
checked: none contains a backslash.

Upgrade implications: no schema change. Existing rows are re-validated with
the replaced function; if any fails, the upgrade aborts and nothing changes.
"""

from alembic import op

revision = "20261019_audit_ts_no_escapes"
down_revision = "20261018_audit_text_limits"
branch_labels = None
depends_on = None

_VALID_TS_FN = r"""
CREATE OR REPLACE FUNCTION public.clw_valid_created_at(t text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF (t COLLATE "C") !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$' THEN
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

_REVALIDATE = r"""
DO $$
DECLARE
    bad bigint;
BEGIN
    SELECT count(*) INTO bad FROM public.audit_events WHERE NOT public.clw_valid_created_at(created_at);
    IF bad > 0 THEN
        RAISE EXCEPTION '20261019: % existing audit_events rows fail the timestamp check; nothing was changed', bad;
    END IF;
END;
$$
"""


def upgrade() -> None:
    op.execute(_VALID_TS_FN)
    op.execute(_REVALIDATE)


def downgrade() -> None:
    raise RuntimeError("downgrade of 20261019_audit_ts_no_escapes is not supported (it would restore F-3)")
