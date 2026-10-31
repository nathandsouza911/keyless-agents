"""Gate 1 L-3 (third review): an audit write cannot wait without bound. A
held chain lock or a slow statement makes the write fail with
AuditUnavailable, and the protected operation is then not performed."""

from __future__ import annotations

import time

import pytest
from sqlalchemy import text

from clw.audit import writer as writer_module
from clw.audit.events import AuditUnavailable
from clw.audit.write_ahead import audited_attempt
from clw.audit.writer import LOCK_TIMEOUT_MS, STATEMENT_TIMEOUT_MS, AuditWriter

from tests.unit.audit.helpers import standard_events

pytestmark = pytest.mark.pg


def _event(chain_id, i=0):
    return {**standard_events()[i], "tenant_id": chain_id}


async def _hold_chain_lock(conn, chain_id):
    await conn.execute("BEGIN")
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", f"clw-audit:{chain_id}")


def test_defaults_are_the_approved_bounds():
    assert (LOCK_TIMEOUT_MS, STATEMENT_TIMEOUT_MS) == (5_000, 30_000)


async def test_defaults_are_applied_inside_the_append_transaction(sessionmaker, chain_id, monkeypatch):
    seen = {}
    original = AuditWriter._db_now

    async def spy(self, session):
        seen["lock"] = await session.scalar(text("SHOW lock_timeout"))
        seen["statement"] = await session.scalar(text("SHOW statement_timeout"))
        return await original(self, session)

    monkeypatch.setattr(AuditWriter, "_db_now", spy)
    await AuditWriter(sessionmaker).append(chain_id=chain_id, event=_event(chain_id))
    assert seen == {"lock": "5s", "statement": "30s"}


async def test_settings_do_not_leak_outside_the_transaction(sessionmaker, chain_id):
    await AuditWriter(sessionmaker).append(chain_id=chain_id, event=_event(chain_id))
    async with sessionmaker() as session:
        assert await session.scalar(text("SHOW lock_timeout")) == "0"


async def test_held_chain_lock_fails_the_append_after_the_lock_timeout(sessionmaker, app_conn, chain_id):
    """The reviewer's L-3 case with the real 5-second default."""
    await AuditWriter(sessionmaker).append(chain_id=chain_id, event=_event(chain_id))
    await _hold_chain_lock(app_conn, chain_id)
    started = time.monotonic()
    try:
        with pytest.raises(AuditUnavailable):
            await AuditWriter(sessionmaker).append(chain_id=chain_id, event=_event(chain_id, 1))
    finally:
        await app_conn.execute("ROLLBACK")
    assert 4 < time.monotonic() - started < 15
    # Nothing was written; the next append succeeds once the lock is free.
    record = await AuditWriter(sessionmaker).append(chain_id=chain_id, event=_event(chain_id, 1))
    assert record.seq == 2


async def test_held_lock_also_bounds_recovery(sessionmaker, app_conn, chain_id):
    writer = AuditWriter(sessionmaker, lock_timeout_ms=500)
    await writer.append(chain_id=chain_id, event=_event(chain_id))
    await _hold_chain_lock(app_conn, chain_id)
    try:
        with pytest.raises(AuditUnavailable):
            await writer.append_recovery(chain_id=chain_id, operator="op", reason="r", expected_head_hash="0" * 64)
    finally:
        await app_conn.execute("ROLLBACK")


async def test_slow_statement_fails_the_append_after_the_statement_timeout(sessionmaker, chain_id, monkeypatch):
    original = writer_module.load_chain

    async def slow(session, **kw):
        await session.execute(text("SELECT pg_sleep(3)"))
        return await original(session, **kw)

    monkeypatch.setattr(writer_module, "load_chain", slow)
    started = time.monotonic()
    with pytest.raises(AuditUnavailable):
        await AuditWriter(sessionmaker, statement_timeout_ms=500).append(chain_id=chain_id, event=_event(chain_id))
    assert time.monotonic() - started < 2.5


async def test_protected_operation_is_not_performed_when_its_audit_write_times_out(sessionmaker, app_conn, chain_id):
    writer = AuditWriter(sessionmaker, lock_timeout_ms=500)
    await writer.append(chain_id=chain_id, event=_event(chain_id))
    sent = []

    async def send():
        sent.append(True)
        return {"ok": True}

    async def outcome(result, error):
        return None

    await _hold_chain_lock(app_conn, chain_id)
    try:
        with pytest.raises(AuditUnavailable, match="intent not recorded; request not sent"):
            await audited_attempt(record_intent=lambda: writer.append(chain_id=chain_id, event=_event(chain_id, 1)),
                                  send=send, record_outcome=outcome)
    finally:
        await app_conn.execute("ROLLBACK")
    assert sent == []


@pytest.mark.parametrize("bad", [0, -1, "5s; DROP TABLE audit_events", 1.5, True])
def test_timeouts_must_be_positive_integers(sessionmaker, bad):
    with pytest.raises(ValueError):
        AuditWriter(sessionmaker, lock_timeout_ms=bad)
