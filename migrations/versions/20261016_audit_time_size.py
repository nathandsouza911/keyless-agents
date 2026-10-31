"""audit_events: real timestamps, future-skew bound, details size limit (N2, N3, N8)

Revision ID: 20261016_audit_time_size
Revises: 20261015_audit_hardening
Create Date: 2026-10-16

N2  created_at must be a real calendar timestamp (CHECK via an IMMUTABLE
    parser), not merely match the shape: "9999-99-99T99:99:99.999999Z" and
    "2026-02-30T..." are rejected.
N3  The insert trigger rejects created_at more than 5 minutes ahead of the
    database server clock (clock_timestamp(), the authoritative clock), and
    applies the "not before the head" rule only when the head's timestamp is
    itself trustworthy (valid and not in the future), so a corrupt head can
    be followed by a recovery record.
N8  details is limited to 64 KiB, defined as the UTF-8 byte length of its
    compact JSON serialization (no insignificant whitespace; key order does
    not change the length). clw_jsonb_compact_size computes exactly that and
    equals len(canonical_json(details)) for any value the writer accepts
    (tested). A cheap length pre-check on the stored text runs first so an
    oversized value is rejected before any recursive work; it replaces the
    separate depth constraint, which is folded into the same CASE so the
    expensive checks never run on oversized input.

Upgrade implications: existing rows must satisfy the new constraints, or
the upgrade fails. Rows written by the application always do.

Correction (gate 1 finding M-1): clw_valid_created_at as defined here is
declared IMMUTABLE but is not: to_timestamp() reads the session TimeZone,
so its result changed with SET TIME ZONE. Both it and the append trigger
are replaced by 20261017_audit_ts_session_free. This file is kept
unchanged in behaviour because migrations are history.
"""

from alembic import op

revision = "20261016_audit_time_size"
down_revision = "20261015_audit_hardening"
branch_labels = None
depends_on = None

_VALID_TS_FN = r"""
CREATE FUNCTION public.clw_valid_created_at(t text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF t !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$' THEN
        RETURN false;
    END IF;
    PERFORM pg_catalog.to_timestamp(substr(t, 1, 26), 'YYYY-MM-DD"T"HH24:MI:SS.US');
    -- to_timestamp normalises out-of-range fields; require an exact round trip.
    RETURN pg_catalog.to_char(pg_catalog.to_timestamp(substr(t, 1, 26), 'YYYY-MM-DD"T"HH24:MI:SS.US')
                              AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') = substr(t, 1, 26)
           AND substr(t, 1, 4) <> '0000';
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
    IF NEW.created_at > limit_ts THEN
        RAISE EXCEPTION 'audit_events: created_at is more than 5 minutes ahead of the database clock'
            USING ERRCODE = 'check_violation';
    END IF;
    IF head_seq IS NOT NULL
       AND public.clw_valid_created_at(head_created)
       AND head_created <= limit_ts
       AND NEW.created_at < head_created THEN
        RAISE EXCEPTION 'audit_events: created_at must not precede the chain head'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

_SIZE_FN = r"""
CREATE FUNCTION public.clw_jsonb_compact_size(j jsonb) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    total bigint := 0;
    n bigint := 0;
    k text;
    v jsonb;
BEGIN
    CASE jsonb_typeof(j)
    WHEN 'object' THEN
        FOR k, v IN SELECT e.key, e.value FROM jsonb_each(j) AS e LOOP
            total := total + octet_length(to_jsonb(k)::text) + 1 + public.clw_jsonb_compact_size(v);
            n := n + 1;
        END LOOP;
        RETURN 2 + total + greatest(n - 1, 0);
    WHEN 'array' THEN
        FOR v IN SELECT a.value FROM jsonb_array_elements(j) AS a LOOP
            total := total + public.clw_jsonb_compact_size(v);
            n := n + 1;
        END LOOP;
        RETURN 2 + total + greatest(n - 1, 0);
    ELSE
        RETURN octet_length(j::text);
    END CASE;
END;
$$
"""

# Stored jsonb text adds at most one space per separator, so it is < 2x the
# compact size; anything over 128 KiB of text is certainly over the limit.
_DETAILS_BOUNDS = (
    "CASE WHEN octet_length(details::text) > 131072 THEN false "
    "WHEN public.clw_jsonb_depth(details) > 15 THEN false "
    "ELSE public.clw_jsonb_compact_size(details) <= 65536 END"
)


def upgrade() -> None:
    op.execute(_VALID_TS_FN)
    op.execute(_SIZE_FN)
    op.execute(_APPEND_FN)
    # EXECUTE stays granted to PUBLIC: CHECK constraints and the trigger call
    # these pure validators with the inserting role's privileges.
    op.create_check_constraint("ck_audit_events_created_at_valid", "audit_events",
                               "public.clw_valid_created_at(created_at)")
    op.drop_constraint("ck_audit_events_details_depth", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_details_bounds", "audit_events", _DETAILS_BOUNDS)


def downgrade() -> None:
    raise RuntimeError("downgrade of 20261016_audit_time_size is not supported (it would weaken audit protections)")
