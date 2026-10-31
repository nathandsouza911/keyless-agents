"""Migration behaviour that cannot be exercised on the shared test database."""

from __future__ import annotations

import asyncio
import json

import asyncpg
import pytest
from alembic import command
from alembic.config import Config

from tests.db.conftest import REPO, _dsn_for, _sqlalchemy_url, ADMIN_DSN

pytestmark = pytest.mark.pg
DB = "clw_test_migrations"


async def _recreate() -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{DB}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{DB}"')
    finally:
        await conn.close()


async def _insert_v1_row() -> None:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        await conn.execute(
            "INSERT INTO audit_events (chain_id, seq, schema_version, tenant_id, event_type, status, details, "
            "created_at, previous_hash, record_hash) VALUES ('c', 1, 1, 'c', 'RUN_TIMED_OUT', 'timed_out', $1::jsonb, "
            "'2026-10-14T09:00:00.000000Z', repeat('0', 64), repeat('a', 64))", json.dumps({}))
    finally:
        await conn.close()


def test_hardening_migration_refuses_to_run_over_schema_v1_rows():
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "20261014_audit_events")
    asyncio.run(_insert_v1_row())
    with pytest.raises(Exception, match="schema_version <> 2"):
        command.upgrade(cfg, "head")


async def _plant_impossible_timestamp() -> None:
    """Superuser plants a row the session-independent validator rejects (the
    constraint is dropped first so the row can exist at all)."""
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        await conn.execute("ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_created_at_valid")
        await conn.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
        await conn.execute(
            "INSERT INTO audit_events (chain_id, seq, schema_version, tenant_id, event_type, status, details, "
            "created_at, previous_hash, record_hash) VALUES ('c', 1, 2, 'c', 'RUN_TIMED_OUT', 'timed_out', $1::jsonb, "
            "'2026-02-30T09:00:00.000000Z', repeat('0', 64), repeat('a', 64))", json.dumps({}))
        await conn.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")
    finally:
        await conn.close()


async def _rows_and_version() -> tuple[list[str], str]:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        rows = [r["created_at"] for r in await conn.fetch("SELECT created_at FROM audit_events ORDER BY seq")]
        return rows, await conn.fetchval("SELECT version_num FROM alembic_version")
    finally:
        await conn.close()


def test_session_free_timestamp_migration_aborts_over_invalid_rows_and_keeps_them():
    """M-1 migration: existing rows are re-validated; a failing row aborts the
    upgrade and is neither changed nor removed."""
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "20261016_audit_time_size")
    asyncio.run(_plant_impossible_timestamp())
    with pytest.raises(Exception, match="fail the session-independent timestamp check"):
        command.upgrade(cfg, "20261017_audit_ts_session_free")
    assert asyncio.run(_rows_and_version()) == (["2026-02-30T09:00:00.000000Z"], "20261016_audit_time_size")


async def _plant_long_reason() -> None:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        await conn.execute(
            "INSERT INTO audit_events (chain_id, seq, schema_version, tenant_id, event_type, status, reason, details, "
            "created_at, previous_hash, record_hash) VALUES ('c', 1, 2, 'c', 'RUN_TIMED_OUT', 'timed_out', "
            "repeat('é', 513), $1::jsonb, '2026-10-14T09:00:00.000000Z', repeat('0', 64), repeat('a', 64))",
            json.dumps({}))
    finally:
        await conn.close()


async def _reason_and_version() -> tuple[int, str]:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        return (await conn.fetchval("SELECT octet_length(reason) FROM audit_events"),
                await conn.fetchval("SELECT version_num FROM alembic_version"))
    finally:
        await conn.close()


def test_text_limit_migration_aborts_over_long_rows_and_never_truncates():
    """L-1 migration: a row over the limit (1026 UTF-8 bytes) aborts the upgrade;
    the row is kept byte-for-byte."""
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "20261017_audit_ts_session_free")
    asyncio.run(_plant_long_reason())
    with pytest.raises(Exception, match="exceed the text limits"):
        command.upgrade(cfg, "head")
    assert asyncio.run(_reason_and_version()) == (1026, "20261017_audit_ts_session_free")


async def _guard_source() -> str:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        return await conn.fetchval("SELECT prosrc FROM pg_proc WHERE proname = 'clw_runs_guard_update'")
    finally:
        await conn.close()


def test_result_redaction_round_trips_when_nothing_was_redacted():
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "20261021_runs")
    before = asyncio.run(_guard_source())
    command.upgrade(cfg, "head")
    assert asyncio.run(_guard_source()) != before
    command.downgrade(cfg, "20261021_runs")
    assert asyncio.run(_guard_source()) == before  # the original guard, restored verbatim
    command.upgrade(cfg, "head")


async def _plant_redaction_record() -> None:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        await conn.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
        await conn.execute(
            "INSERT INTO audit_events (chain_id, seq, schema_version, tenant_id, event_type, status, details, "
            "created_at, previous_hash, record_hash) VALUES ('c', 1, 2, 'c', 'RESULT_REDACTED', 'recorded', "
            "$1::jsonb, '2026-10-25T09:00:00.000000Z', repeat('0', 64), repeat('a', 64))", json.dumps({}))
        await conn.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")
    finally:
        await conn.close()


def test_result_redaction_downgrade_refuses_once_a_redaction_exists():
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "head")
    asyncio.run(_plant_redaction_record())
    with pytest.raises(Exception, match="redactions exist"):
        command.downgrade(cfg, "20261021_runs")


async def _check_sources() -> dict[str, str]:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        rows = await conn.fetch("SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
                                "WHERE conname IN ('ck_audit_events_schema_version', 'ck_audit_events_event_type_known')")
        return {r[0]: r[1] for r in rows}
    finally:
        await conn.close()


def test_schema_v3_round_trips_when_no_v3_record_exists():
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "20261025_result_redaction")
    before = asyncio.run(_check_sources())
    command.upgrade(cfg, "head")
    after = asyncio.run(_check_sources())
    assert "2, 3" in after["ck_audit_events_schema_version"] and "MANIFEST_APPROVED" in after["ck_audit_events_event_type_known"]
    command.downgrade(cfg, "20261025_result_redaction")
    assert asyncio.run(_check_sources()) == before


async def _plant_v3_record() -> None:
    conn = await asyncpg.connect(_dsn_for(DB))
    try:
        await conn.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
        await conn.execute(
            "INSERT INTO audit_events (chain_id, seq, schema_version, tenant_id, event_type, status, details, "
            "created_at, previous_hash, record_hash) VALUES ('c', 1, 3, 'c', 'RUN_TIMED_OUT', 'timed_out', "
            "$1::jsonb, '2026-10-25T09:00:00.000000Z', repeat('0', 64), repeat('a', 64))", json.dumps({}))
        await conn.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")
    finally:
        await conn.close()


def test_schema_v3_downgrade_refuses_once_a_v3_record_exists():
    asyncio.run(_recreate())
    cfg = Config(str(REPO / "alembic.ini"))
    cfg.attributes["database_url"] = _sqlalchemy_url(_dsn_for(DB))
    command.upgrade(cfg, "head")
    asyncio.run(_plant_v3_record())
    with pytest.raises(Exception, match="v3 audit records exist"):
        command.downgrade(cfg, "20261025_result_redaction")
