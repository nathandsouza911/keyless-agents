"""Gate 1 M-1 (third review): database timestamp checks must not depend on
session settings the application role can change (TimeZone, DateStyle), nor
on the database's default TimeZone. Every check runs as the app role."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.audit.events import PROTECTED_FIELDS
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter

from tests.db.conftest import _sqlalchemy_url
from tests.unit.audit.helpers import rehash, standard_events

pytestmark = pytest.mark.pg
COLS = [*PROTECTED_FIELDS, "record_hash"]

# A summer timestamp (BST in London) and the current time make the old
# to_timestamp() validator fail under these zones whatever the date of the run;
# the fixed-offset and POSIX zones are never UTC.
TIME_ZONES = ["UTC", "Europe/London", "America/St_Johns", "<+03>-03", "EST5EDT,M3.2.0,M11.1.0", "Pacific/Kiritimati"]
SUMMER = "2026-07-01T12:00:00.000000Z"


async def _raw_insert(conn, record):
    values = record.stored()
    args = [json.dumps(values[c]) if c == "details" else values[c] for c in COLS]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(COLS))
    await conn.execute(f"INSERT INTO public.audit_events ({', '.join(COLS)}) VALUES ({placeholders})", *args)


def _successor(head, created_at):
    return rehash(replace(
        head, seq=head.seq + 1, previous_hash=head.record_hash, event_type="RUN_TIMED_OUT", status="timed_out",
        run_id="run-x", task_id=None, task_manifest_sha256=None, profile_id=None, profile_version=None,
        auth_mode=None, reason=None, operation=None, http_method=None, path_template=None, created_at=created_at,
    ))


async def _start(sessionmaker, chain_id, n=3):
    writer = AuditWriter(sessionmaker)
    return [await writer.append(chain_id=chain_id, event={**e, "tenant_id": chain_id}) for e in standard_events()[:n]]


@pytest.mark.parametrize("zone", TIME_ZONES)
@pytest.mark.parametrize("datestyle", ["ISO, MDY", "SQL, DMY", "German"])
async def test_validator_ignores_session_time_zone_and_datestyle(app_conn, zone, datestyle):
    await app_conn.execute(f"SET TIME ZONE '{zone}'")
    await app_conn.execute(f"SET DateStyle = '{datestyle}'")
    now = await app_conn.fetchval(
        "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    for stamp in (SUMMER, "2026-01-15T09:00:00.000000Z", "2026-03-29T01:30:00.000000Z", now):
        assert await app_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is True, (zone, stamp)
    for stamp in ("2026-02-30T00:00:00.000000Z", "2026-10-14T24:00:00.000000Z", "2026-10-14T09:00:60.000000Z",
                  "0000-01-01T00:00:00.000000Z", "2026-10-14T09:00:00.000000Z\n"):
        assert await app_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is False, (zone, stamp)


@pytest.mark.parametrize("zone", TIME_ZONES)
async def test_backdated_insert_rejected_under_any_session_time_zone(app_sessionmaker, app_conn, chain_id, zone):
    """The reviewer's M-1 attack: change TimeZone so the head looks invalid,
    then insert a backdated successor. Must be rejected in every zone."""
    head = (await _start(app_sessionmaker, chain_id))[-1]
    await app_conn.execute(f"SET TIME ZONE '{zone}'")
    assert await app_conn.fetchval("SELECT public.clw_valid_created_at($1)", head.created_at) is True
    with pytest.raises(asyncpg.PostgresError, match="must not precede the chain head"):
        await _raw_insert(app_conn, _successor(head, "2026-01-15T09:00:00.000000Z"))


@pytest.mark.parametrize("zone", TIME_ZONES)
async def test_valid_insert_and_future_bound_under_any_session_time_zone(app_sessionmaker, app_conn, chain_id, zone):
    head = (await _start(app_sessionmaker, chain_id))[-1]
    await app_conn.execute(f"SET TIME ZONE '{zone}'")
    stamp = await app_conn.fetchval(
        "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    far = await app_conn.fetchval(
        "SELECT to_char((clock_timestamp() + interval '6 minutes') AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    with pytest.raises(asyncpg.PostgresError, match="more than 5 minutes ahead"):
        await _raw_insert(app_conn, _successor(head, far))
    await _raw_insert(app_conn, _successor(head, max(stamp, head.created_at)))


@pytest.fixture
async def london_default_database(admin_conn, pg_dsn):
    """The test database with a non-UTC default TimeZone, for new sessions."""
    await admin_conn.execute("ALTER DATABASE clw_test SET timezone = 'Europe/London'")
    try:
        yield
    finally:
        await admin_conn.execute("ALTER DATABASE clw_test RESET timezone")


async def test_writer_works_on_a_database_whose_default_time_zone_is_not_utc(
        london_default_database, app_role_dsn, chain_id):
    engine = create_async_engine(_sqlalchemy_url(app_role_dsn))
    try:
        sessionmaker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        conn = await asyncpg.connect(app_role_dsn)
        try:
            assert await conn.fetchval("SHOW timezone") == "Europe/London"
            assert await conn.fetchval("SELECT public.clw_valid_created_at($1)", SUMMER) is True
        finally:
            await conn.close()
        records = await _start(sessionmaker, chain_id, n=8)
        assert [r.seq for r in records] == list(range(1, 9))
        async with sessionmaker() as session:
            report = await verify_chain(session, chain_id=chain_id)
        assert report.valid, report.errors
        # Timestamps are still UTC values, not London local time.
        written = datetime.strptime(records[-1].created_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        assert abs(datetime.now(timezone.utc) - written) < timedelta(minutes=1)
    finally:
        await engine.dispose()


SAMPLE_DETAILS = {"result_sha256": "a" * 64, "n": 12345678901234, "neg": -5, "dec": 1.5, "s": "é😀\"\\n",
                  "list": [True, False, None, {"k": [1, 2, {}]}], "": ""}


async def test_details_size_function_ignores_session_settings(app_conn):
    """clw_jsonb_compact_size is declared IMMUTABLE but calls to_jsonb (STABLE
    in the catalog) on text keys. Its result must not move with any setting
    the app role can change."""
    baseline = await app_conn.fetchval("SELECT public.clw_jsonb_compact_size($1::jsonb)", json.dumps(SAMPLE_DETAILS))
    for setting in ("SET TIME ZONE 'Pacific/Kiritimati'", "SET DateStyle = 'German'", "SET extra_float_digits = 3",
                    "SET extra_float_digits = -15", "SET IntervalStyle = 'sql_standard'", "SET lc_numeric = 'C'",
                    "SET standard_conforming_strings = off", "SET bytea_output = 'escape'"):
        await app_conn.execute(setting)
        size = await app_conn.fetchval("SELECT public.clw_jsonb_compact_size($1::jsonb)", json.dumps(SAMPLE_DETAILS))
        assert size == baseline, setting


# ------------------------------------- F-3: escapes in function bodies

VALID = [SUMMER, "2026-01-15T09:00:00.000000Z", "2024-02-29T23:59:59.999999Z"]
INVALID = ["2026-10-14T12:00:00X000000Z", "2026-10-14T12:00:00" + chr(92) + "000000Z", "2026-02-30T00:00:00.000000Z",
           "2026-10-14T24:00:00.000000Z", "0000-01-01T00:00:00.000000Z", "2026-10-14T09:00:00.000000Z\n",
           "2026-10-14 09:00:00.000000Z"]
SETTINGS = [
    "SET standard_conforming_strings = off",
    "SET standard_conforming_strings = on",
    "SET escape_string_warning = off",
    "SET backslash_quote = on",
    "SET DateStyle = 'German'",
    "SET IntervalStyle = 'postgres_verbose'",
    "SET extra_float_digits = -15",
    "SET lc_time = 'C'",
    "SET lc_numeric = 'C'",
    "SET timezone_abbreviations = 'India'",
    "SET search_path = pg_temp, public",
    "SET search_path = ''",
    "SET plpgsql.variable_conflict = 'use_column'",
    "SET transform_null_equals = on",
]


@pytest.mark.parametrize("setting", SETTINGS)
async def test_validator_gives_the_same_answers_under_every_setting(app_conn, setting):
    """Gate 1 F-3 (fourth review): with standard_conforming_strings = off the
    old pattern's backslash-dot became '.', accepting 'X' in place of the point."""
    await app_conn.execute(setting)
    for stamp in VALID:
        assert await app_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is True, (setting, stamp)
    for stamp in INVALID:
        assert await app_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is False, (setting, stamp)


async def test_no_audit_function_body_contains_a_backslash(admin_conn):
    """Function bodies are parsed in the calling session, where a backslash
    may or may not be an escape character (standard_conforming_strings)."""
    rows = await admin_conn.fetch(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' AND p.proname LIKE 'clw!_%' ESCAPE '!' AND strpos(p.prosrc, chr(92)) > 0")
    assert [r["proname"] for r in rows] == []
    names = {r["proname"] for r in await admin_conn.fetch(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'public' AND p.proname LIKE 'clw!_%' ESCAPE '!'")}
    assert {"clw_valid_created_at", "clw_audit_events_check_append", "clw_jsonb_compact_size"} <= names


async def test_backdated_and_future_inserts_rejected_with_nonstandard_strings(app_sessionmaker, app_conn, chain_id):
    head = (await _start(app_sessionmaker, chain_id))[-1]
    await app_conn.execute("SET standard_conforming_strings = off")
    with pytest.raises(asyncpg.PostgresError, match="must not precede the chain head"):
        await _raw_insert(app_conn, _successor(head, "2026-01-15T09:00:00.000000Z"))
    with pytest.raises(asyncpg.PostgresError):
        await _raw_insert(app_conn, _successor(head, head.created_at[:19] + "X" + head.created_at[20:]))
