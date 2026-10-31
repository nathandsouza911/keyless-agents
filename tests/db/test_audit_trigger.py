"""Database-side immutability and continuity of audit_events (SD-006).

These tests exercise the real Postgres triggers and privileges; they are the
evidence for the claims in the migration docstring and threat-model §6.
"""

from __future__ import annotations

from dataclasses import replace

import asyncpg
import pytest

from clw.audit.events import PROTECTED_FIELDS
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter

from tests.unit.audit.helpers import ev, rehash, standard_events

pytestmark = pytest.mark.pg


def _events_for(chain_id: str) -> list[dict]:
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


async def _write_standard_run(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    return [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)]


COLUMNS = [*PROTECTED_FIELDS, "record_hash"]


def _new_value(column: str):
    if column in {"seq", "schema_version", "profile_version", "decision_seq", "http_status",
                  "attempt", "item_count", "duration_ms"}:
        return 99
    if column == "details":
        return '{"tampered": true}'
    return "tampered"


@pytest.mark.parametrize("column", COLUMNS)
async def test_update_of_any_column_is_rejected(sessionmaker, admin_conn, chain_id, column):
    await _write_standard_run(sessionmaker, chain_id)
    cast = "::jsonb" if column == "details" else ""
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        await admin_conn.execute(
            f"UPDATE audit_events SET {column} = $1{cast} WHERE chain_id = $2 AND seq = 3",
            _new_value(column), chain_id,
        )


async def test_delete_is_rejected(sessionmaker, admin_conn, chain_id):
    await _write_standard_run(sessionmaker, chain_id)
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        await admin_conn.execute("DELETE FROM audit_events WHERE chain_id = $1", chain_id)


async def test_truncate_is_rejected(sessionmaker, admin_conn, chain_id):
    await _write_standard_run(sessionmaker, chain_id)
    with pytest.raises(asyncpg.PostgresError, match="append-only"):
        await admin_conn.execute("TRUNCATE audit_events")


# ---------------------------------------------------- insert continuity


async def _raw_insert(conn, record):
    cols = [*PROTECTED_FIELDS, "record_hash"]
    values = [getattr(record, c) for c in cols]
    idx = cols.index("details")
    import json

    values[idx] = json.dumps(values[idx])
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(cols))
    await conn.execute(f"INSERT INTO audit_events ({', '.join(cols)}) VALUES ({placeholders})", *values)


async def test_insert_skipping_a_seq_is_rejected(sessionmaker, admin_conn, chain_id):
    records = await _write_standard_run(sessionmaker, chain_id)
    forged = rehash(replace(records[-1], seq=records[-1].seq + 2, previous_hash=records[-1].record_hash))
    with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):
        await _raw_insert(admin_conn, forged)


async def test_insert_with_wrong_previous_hash_is_rejected(sessionmaker, admin_conn, chain_id):
    records = await _write_standard_run(sessionmaker, chain_id)
    forged = rehash(replace(records[-1], seq=records[-1].seq + 1, previous_hash="f" * 64))
    with pytest.raises(asyncpg.PostgresError, match="extend the chain head"):
        await _raw_insert(admin_conn, forged)


async def test_insert_reusing_a_seq_is_rejected(sessionmaker, admin_conn, chain_id):
    records = await _write_standard_run(sessionmaker, chain_id)
    with pytest.raises(asyncpg.PostgresError):
        await _raw_insert(admin_conn, records[2])


async def test_first_insert_must_be_genesis(admin_conn, chain_id):
    from tests.unit.audit.helpers import build_chain

    records = build_chain(_events_for(chain_id), chain_id=chain_id)
    with pytest.raises(asyncpg.PostgresError, match="genesis"):
        await _raw_insert(admin_conn, records[1])


# ------------------------------------------------- least-privilege app role


async def test_app_role_has_no_update_or_delete_privilege(sessionmaker, app_conn, chain_id):
    await _write_standard_run(sessionmaker, chain_id)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("UPDATE audit_events SET status = 'x' WHERE chain_id = $1", chain_id)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("DELETE FROM audit_events WHERE chain_id = $1", chain_id)


async def test_app_role_cannot_disable_or_drop_triggers(app_conn):
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_reject_update_delete")
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_conn.execute("DROP TRIGGER audit_events_reject_update_delete ON audit_events")


async def test_trigger_still_blocks_when_privileges_are_overgranted(sessionmaker, admin_conn, app_conn, chain_id):
    # Defence in depth: even if someone grants UPDATE/DELETE, the trigger holds.
    await _write_standard_run(sessionmaker, chain_id)
    await admin_conn.execute("GRANT UPDATE, DELETE ON audit_events TO clw_app_test")
    try:
        with pytest.raises(asyncpg.PostgresError, match="append-only"):
            await app_conn.execute("UPDATE audit_events SET status = 'x' WHERE chain_id = $1", chain_id)
        with pytest.raises(asyncpg.PostgresError, match="append-only"):
            await app_conn.execute("DELETE FROM audit_events WHERE chain_id = $1", chain_id)
    finally:
        await admin_conn.execute("REVOKE UPDATE, DELETE ON audit_events FROM clw_app_test")


# ------------------------------------- privileged tampering (residual risk)


async def _with_triggers_disabled(admin_conn, action):
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        await action()
    finally:
        await admin_conn.execute("SET session_replication_role = origin")


async def test_superuser_partial_edit_is_detected_by_verifier(sessionmaker, admin_conn, chain_id):
    await _write_standard_run(sessionmaker, chain_id)

    async def flip_denial_to_allowed():
        await admin_conn.execute(
            "UPDATE audit_events SET status = 'allowed', reason = 'allowed' WHERE chain_id = $1 AND seq = 7",
            chain_id,
        )

    await _with_triggers_disabled(admin_conn, flip_denial_to_allowed)
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=chain_id)
    assert not report.valid
    assert (7, "hash_mismatch") in {(e.seq, e.issue) for e in report.errors}


async def test_superuser_full_rewrite_is_not_detected_by_verifier_alone(sessionmaker, admin_conn, chain_id):
    # SD-006 residual risk, pinned as a test: rewrite seq 7 and recompute
    # every hash from there to the head. Only an external checkpoint (2c)
    # can reveal this.
    records = await _write_standard_run(sessionmaker, chain_id)
    rewritten = list(records[:6])
    for original in records[6:]:
        r = original
        if r.seq == 7:
            r = replace(r, status="allowed", reason="allowed", http_method="PATCH", path_template="/users/{user_id}")
        r = rehash(replace(r, previous_hash=rewritten[-1].record_hash))
        rewritten.append(r)

    async def rewrite():
        for r in rewritten[6:]:
            await admin_conn.execute(
                "UPDATE audit_events SET status=$1, reason=$2, previous_hash=$3, record_hash=$4, "
                "http_method=$7, path_template=$8 WHERE chain_id=$5 AND seq=$6",
                r.status, r.reason, r.previous_hash, r.record_hash, chain_id, r.seq,
                r.http_method, r.path_template,
            )

    await _with_triggers_disabled(admin_conn, rewrite)
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=chain_id)
    assert report.valid  # the limit: nothing in the database alone reveals this


async def test_triggers_are_enabled_after_privileged_tests(admin_conn):
    states = await admin_conn.fetch(
        "SELECT tgname, tgenabled FROM pg_trigger WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal"
    )
    assert {r["tgname"] for r in states} == {
        "audit_events_reject_update_delete", "audit_events_reject_truncate", "audit_events_check_append"
    }
    assert all(r["tgenabled"] == b"O" for r in states)  # "char" arrives as bytes
