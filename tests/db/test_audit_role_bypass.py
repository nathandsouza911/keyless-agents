"""H1 regression and bypass attempts by the least-privileged application role.

Every test here connects as clw_app_test (SELECT, INSERT on audit_events
only), the role the broker, runner and API are meant to use.
"""

from __future__ import annotations

import json
from dataclasses import replace

import asyncpg
import pytest

from clw.audit.events import PROTECTED_FIELDS
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter

from tests.db.conftest import APP_ROLE, TEST_DB
from tests.unit.audit.helpers import build_chain, rehash, standard_events

pytestmark = pytest.mark.pg

COLS = [*PROTECTED_FIELDS, "record_hash"]


def _events_for(chain_id):
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


async def _raw_insert(conn, record, table="public.audit_events", **overrides):
    values = {**record.stored(), **overrides}
    args = [json.dumps(values[c]) if c == "details" and not isinstance(values[c], str) else values[c] for c in COLS]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(COLS))
    await conn.execute(f"INSERT INTO {table} ({', '.join(COLS)}) VALUES ({placeholders})", *args)


async def _write(sessionmaker, chain_id, n=None):
    writer = AuditWriter(sessionmaker)
    events = _events_for(chain_id)
    return [await writer.append(chain_id=chain_id, event=e) for e in (events if n is None else events[:n])]


# ------------------------------------------------- H1: temp-table shadowing


async def test_app_role_cannot_create_temp_tables(app_conn):
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("CREATE TEMP TABLE audit_events (chain_id text, seq int, record_hash text)")


async def test_reviewer_poc_a_shadow_bypass_is_blocked_even_with_temp_privilege(
    sessionmaker, app_sessionmaker, admin_conn, app_conn, chain_id
):
    # Defence in depth: grant TEMP back and replay poc_db section A exactly.
    # Schema qualification + pinned search_path must still hold.
    records = await _write(app_sessionmaker, chain_id, 3)
    await admin_conn.execute(f'GRANT TEMPORARY ON DATABASE "{TEST_DB}" TO {APP_ROLE}')
    try:
        await app_conn.execute("CREATE TEMP TABLE audit_events (chain_id text, seq int, record_hash text)")
        await app_conn.execute("INSERT INTO pg_temp.audit_events VALUES ($1, 9, 'whatever')", chain_id)
        squat = rehash(replace(records[-1], seq=10, previous_hash="a" * 64))
        with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):
            await _raw_insert(app_conn, squat)
        # An unqualified INSERT now resolves to the temp table (pg_temp is first
        # in the session path): harmless, the real chain is checked below.
        with pytest.raises(asyncpg.PostgresError):
            await _raw_insert(app_conn, squat, table="audit_events")
        await app_conn.execute("DROP TABLE pg_temp.audit_events")
    finally:
        await admin_conn.execute(f'REVOKE TEMPORARY ON DATABASE "{TEST_DB}" FROM {APP_ROLE}')
    async with sessionmaker() as s:
        assert (await verify_chain(s, chain_id=chain_id)).valid


async def test_new_chain_cannot_start_mid_sequence_via_shadow(admin_conn, app_conn, chain_id):
    await admin_conn.execute(f'GRANT TEMPORARY ON DATABASE "{TEST_DB}" TO {APP_ROLE}')
    try:
        await app_conn.execute("CREATE TEMP TABLE audit_events (chain_id text, seq int, record_hash text, created_at text)")
        await app_conn.execute("INSERT INTO pg_temp.audit_events VALUES ($1, 9, $2, '2026-01-01T00:00:00.000000Z')",
                               chain_id, "a" * 64)
        first = build_chain([{**e, "tenant_id": chain_id} for e in standard_events()[:1]], chain_id=chain_id)[0]
        forged = rehash(replace(first, seq=10, previous_hash="a" * 64))
        with pytest.raises(asyncpg.PostgresError, match="genesis"):
            await _raw_insert(app_conn, forged)
        await app_conn.execute("DROP TABLE pg_temp.audit_events")
    finally:
        await admin_conn.execute(f'REVOKE TEMPORARY ON DATABASE "{TEST_DB}" FROM {APP_ROLE}')


async def test_trigger_functions_pin_search_path(admin_conn):
    rows = await admin_conn.fetch(
        "SELECT proname, proconfig FROM pg_proc WHERE proname IN "
        "('clw_audit_events_check_append', 'clw_audit_events_reject_change', 'clw_jsonb_depth')"
    )
    assert len(rows) == 3
    for row in rows:
        assert row["proconfig"] == ["search_path=pg_catalog, pg_temp"], row["proname"]


# ------------------------------------------------ alternate SQL paths


async def test_app_role_cannot_create_objects_in_public_schema(app_conn):
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("CREATE TABLE public.audit_events_shadow (x int)")
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("CREATE FUNCTION public.repeat(text, int) RETURNS text LANGUAGE sql AS $$ SELECT 'x' $$")


async def test_app_role_cannot_replace_trigger_functions(app_conn):
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute(
            "CREATE OR REPLACE FUNCTION public.clw_audit_events_check_append() RETURNS trigger "
            "LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$"
        )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("ALTER FUNCTION public.clw_audit_events_check_append() RESET search_path")


@pytest.mark.parametrize("statement", [
    "ALTER TABLE audit_events DISABLE TRIGGER audit_events_check_append",
    "ALTER TABLE audit_events DISABLE TRIGGER USER",
    "DROP TRIGGER audit_events_check_append ON audit_events",
    "CREATE RULE r AS ON INSERT TO audit_events DO INSTEAD NOTHING",
    "ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_record_hash_hex",
    "SET session_replication_role = replica",
    "TRUNCATE audit_events",
])
async def test_app_role_cannot_switch_off_protections(app_conn, statement):
    with pytest.raises(asyncpg.PostgresError):
        await app_conn.execute(statement)


async def test_copy_cannot_bypass_continuity(app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 3)
    forged = rehash(replace(records[-1], seq=9, previous_hash="a" * 64))
    row = [json.dumps(v) if c == "details" else v for c, v in forged.stored().items()]
    with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):
        await app_conn.copy_records_to_table("audit_events", records=[tuple(row)], columns=COLS)


async def test_on_conflict_cannot_rewrite_or_bypass(sessionmaker, app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 3)
    cols = ", ".join(COLS)
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(COLS))
    tampered = replace(records[1], status="tampered")
    args = [json.dumps(v) if c == "details" else v for c, v in tampered.stored().items()]
    with pytest.raises(asyncpg.PostgresError):  # needs UPDATE privilege and hits the trigger anyway
        await app_conn.execute(
            f"INSERT INTO audit_events ({cols}) VALUES ({placeholders}) "
            f"ON CONFLICT (chain_id, seq) DO UPDATE SET status = EXCLUDED.status", *args)
    with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):  # trigger runs before conflict check
        await app_conn.execute(
            f"INSERT INTO audit_events ({cols}) VALUES ({placeholders}) ON CONFLICT DO NOTHING", *args)
    async with sessionmaker() as s:
        assert (await verify_chain(s, chain_id=chain_id)).valid


async def test_app_role_privileges_are_minimal(admin_conn):
    role = await admin_conn.fetchrow(
        "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, rolinherit "
        "FROM pg_roles WHERE rolname = $1", APP_ROLE)
    assert dict(role) == {"rolsuper": False, "rolcreaterole": False, "rolcreatedb": False,
                          "rolbypassrls": False, "rolreplication": False, "rolinherit": False}
    memberships = await admin_conn.fetch(
        "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
        "JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = $1", APP_ROLE)
    assert memberships == []
    owner = await admin_conn.fetchval("SELECT tableowner FROM pg_tables WHERE tablename = 'audit_events'")
    assert owner != APP_ROLE
    for privilege, expected in [("SELECT", True), ("INSERT", True), ("UPDATE", False), ("DELETE", False),
                                ("TRUNCATE", False), ("REFERENCES", False), ("TRIGGER", False)]:
        has = await admin_conn.fetchval("SELECT has_table_privilege($1, 'public.audit_events', $2)", APP_ROLE, privilege)
        assert has is expected, privilege
    assert await admin_conn.fetchval("SELECT has_database_privilege($1, current_database(), 'TEMP')", APP_ROLE) is False
    assert await admin_conn.fetchval("SELECT has_schema_privilege($1, 'public', 'CREATE')", APP_ROLE) is False


# -------------------------------------------- H2/H3: database constraints


@pytest.mark.parametrize("override, constraint", [
    ({"record_hash": "Z" * 64}, "record_hash_hex"),
    ({"record_hash": "0" * 63 + "G"}, "record_hash_hex"),
    ({"event_type": "OP_MAYBE"}, "event_type_known"),
    ({"created_at": "2026-10-14 09:00:00"}, "created_at_format|must not precede"),
    ({"schema_version": 1}, "schema_version"),
    ({"details": "[]"}, "details_object"),
    ({"details": "{" + '"a":{' * 15 + "}" * 15 + "}"}, "details_bounds"),
    ({"details": '{"a":' * 3000 + "1" + "}" * 3000}, "details_bounds"),
    ({"task_manifest_sha256": "XYZ"}, "manifest_hex"),
])
async def test_constraints_reject_malformed_rows_from_app_role(app_sessionmaker, app_conn, chain_id, override, constraint):
    records = await _write(app_sessionmaker, chain_id, 3)
    nxt = rehash(replace(records[-1], seq=4, previous_hash=records[-1].record_hash, event_type="RUN_TIMED_OUT",
                         status="timed_out", task_id=None, task_manifest_sha256=None,
                         profile_id=None, profile_version=None, auth_mode=None))
    with pytest.raises(asyncpg.PostgresError, match=constraint):
        await _raw_insert(app_conn, nxt, **override)


async def test_details_at_the_depth_limit_is_accepted(app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 1)
    deep = "{" + '"a":{' * 14 + "}" * 14 + "}"  # 15 levels
    nxt = rehash(replace(records[-1], seq=2, previous_hash=records[-1].record_hash))
    await _raw_insert(app_conn, nxt, details=deep)


async def test_backdated_insert_rejected_by_database(app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 3)
    nxt = rehash(replace(records[-1], seq=4, previous_hash=records[-1].record_hash,
                         created_at="2001-01-01T00:00:00.000000Z"))
    with pytest.raises(asyncpg.PostgresError, match="must not precede"):
        await _raw_insert(app_conn, nxt)


# ------------------------------------------- continuity as the app role


async def test_app_role_insert_skipping_seq_rejected(app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 3)
    forged = rehash(replace(records[-1], seq=5, previous_hash=records[-1].record_hash))
    with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):
        await _raw_insert(app_conn, forged)


async def test_app_role_insert_with_wrong_link_rejected(app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 3)
    forged = rehash(replace(records[-1], seq=4, previous_hash="f" * 64))
    with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):
        await _raw_insert(app_conn, forged)


async def test_app_role_cannot_start_chain_mid_sequence(app_conn, chain_id):
    first = build_chain([{**e, "tenant_id": chain_id} for e in standard_events()[:2]], chain_id=chain_id)[1]
    with pytest.raises(asyncpg.PostgresError, match="genesis"):
        await _raw_insert(app_conn, first)


async def test_app_role_reusing_seq_rejected(app_sessionmaker, app_conn, chain_id):
    records = await _write(app_sessionmaker, chain_id, 3)
    with pytest.raises(asyncpg.PostgresError):
        await _raw_insert(app_conn, records[1])


async def test_app_role_cannot_update_or_delete(app_sessionmaker, app_conn, chain_id):
    await _write(app_sessionmaker, chain_id, 3)
    for statement in ("UPDATE audit_events SET status = 'x' WHERE chain_id = $1",
                      "DELETE FROM audit_events WHERE chain_id = $1"):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await app_conn.execute(statement, chain_id)
