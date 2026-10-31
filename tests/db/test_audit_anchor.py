"""Gate 1 F-1 (fourth review): a long-lived writer's cached chain position
must not let it keep appending after the database clock steps back.

The fast-clock phase is simulated as the reviewer did: the writer's
_db_now returns real time + 1 hour, and those appends run as the superuser
with session_replication_role = replica, because the trigger reads the real
clock and would reject them. From the step-back on, everything runs as the
least-privileged app role on the unmodified production path."""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.audit.chain import Anchor, verify_records
from clw.audit.events import AuditChainCompromised
from clw.audit.verifier import load_chain
from clw.audit.writer import AuditWriter

from tests.db.conftest import _sqlalchemy_url
from tests.unit.audit.helpers import standard_events

pytestmark = pytest.mark.pg


def _events(chain_id):
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


@pytest.fixture
async def replica_sessionmaker(pg_dsn):
    engine = create_async_engine(_sqlalchemy_url(pg_dsn))

    @event.listens_for(engine.sync_engine, "connect")
    def _replica(dbapi_conn, _):
        dbapi_conn.run_async(lambda c: c.execute("SET session_replication_role = replica"))

    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


async def _count(admin_conn, chain_id) -> int:
    return await admin_conn.fetchval("SELECT count(*) FROM audit_events WHERE chain_id = $1", chain_id)


async def _long_lived_writer_with_fast_records(app_sessionmaker, replica_sessionmaker, chain_id, monkeypatch):
    """The same writer appends seq 1-2 normally, then seq 3-4 while the
    database clock runs an hour fast, then the clock steps back."""
    writer = AuditWriter(app_sessionmaker)
    events = _events(chain_id)
    for e in events[:2]:
        await writer.append(chain_id=chain_id, event=e)
    real = AuditWriter._db_now

    async def fast(self, session):
        return (await real(self, session)) + timedelta(hours=1)

    monkeypatch.setattr(AuditWriter, "_db_now", fast)
    writer._sessionmaker = replica_sessionmaker
    for e in events[2:4]:
        await writer.append(chain_id=chain_id, event=e)
    monkeypatch.setattr(AuditWriter, "_db_now", real)  # NTP steps the clock back
    writer._sessionmaker = app_sessionmaker
    assert writer._anchors[chain_id].seq == 4
    return writer, events


async def test_same_writer_refuses_after_the_clock_steps_back_and_inserts_nothing(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, monkeypatch, caplog):
    writer, events = await _long_lived_writer_with_fast_records(
        app_sessionmaker, replica_sessionmaker, chain_id, monkeypatch)
    before = await _count(admin_conn, chain_id)
    with caplog.at_level(logging.WARNING, logger="clw.audit.alert"):
        with pytest.raises(AuditChainCompromised) as refused:
            await writer.append(chain_id=chain_id, event=events[4])
    assert (4, "created_at_in_future") in refused.value.findings
    assert await _count(admin_conn, chain_id) == before == 4  # nothing inserted
    assert any("audit_anchor_untrusted" in r.getMessage() for r in caplog.records)
    assert any(r.levelno == logging.CRITICAL and "audit_chain_integrity_failure" in r.getMessage()
               for r in caplog.records)
    # Repeated attempts keep refusing; the cache is not re-established.
    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=events[4])
    assert chain_id not in writer._anchors and await _count(admin_conn, chain_id) == 4


async def test_restarted_writer_refuses_too_and_recovery_restores_both(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, monkeypatch):
    writer, events = await _long_lived_writer_with_fast_records(
        app_sessionmaker, replica_sessionmaker, chain_id, monkeypatch)
    restarted = AuditWriter(app_sessionmaker)  # a process restart: empty cache
    with pytest.raises(AuditChainCompromised):
        await restarted.append(chain_id=chain_id, event=events[4])

    async with app_sessionmaker() as s:
        head = (await load_chain(s, chain_id=chain_id))[-1]
    recovery = await restarted.append_recovery(chain_id=chain_id, operator="op:alice", reason="INC-F1",
                                               expected_head_hash=head.record_hash)
    assert sorted((a["seq"], a["issue"]) for a in recovery.details["acknowledged"]) == [
        (3, "created_at_in_future"), (4, "created_at_in_future")]

    # The long-lived writer still holds its fast anchor (seq 4). It must not
    # treat the valid recovery as out of order (reviewer's corollary), and
    # must append after verifying the whole chain.
    assert writer._anchors[chain_id].seq == 4
    record = await writer.append(chain_id=chain_id, event={**events[0], "run_id": "run-0002"})
    assert record.seq == recovery.seq + 1 and record.created_at >= recovery.created_at
    async with app_sessionmaker() as s:
        records = await load_chain(s, chain_id=chain_id)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    for delta in (timedelta(0), timedelta(hours=2), timedelta(days=1)):
        report = verify_records(records, chain_id=chain_id, now=now + delta)
        assert report.integrity_state == "recovered" and not report.valid and report.provisional == ()


async def test_cached_position_within_skew_is_still_used(app_sessionmaker, chain_id, monkeypatch):
    """The ordinary case keeps the incremental path (no full re-read)."""
    from clw.audit import writer as writer_module

    writer = AuditWriter(app_sessionmaker)
    events = _events(chain_id)
    for e in events[:3]:
        await writer.append(chain_id=chain_id, event=e)
    seen = []
    original = writer_module.load_chain

    async def spy(session, **kw):
        seen.append(kw.get("after_seq", 0))
        return await original(session, **kw)

    monkeypatch.setattr(writer_module, "load_chain", spy)
    await writer.append(chain_id=chain_id, event=events[3])
    assert seen == [3]


@pytest.mark.parametrize("stamp", ["garbage", "9999-99-99T99:99:99.999999Z", None, "2099-01-01T00:00:00.000000Z",
                                   "0000-00-00T00:00:00.000000Z"])  # sorts before any real time
async def test_untrustworthy_cached_position_forces_full_verification(app_sessionmaker, chain_id, monkeypatch, stamp):
    """Fail closed on the cache: if the cached position cannot be shown to be
    trustworthy, the writer re-verifies from seq 1."""
    from clw.audit import writer as writer_module

    writer = AuditWriter(app_sessionmaker)
    events = _events(chain_id)
    records = [await writer.append(chain_id=chain_id, event=e) for e in events[:3]]
    writer._anchors[chain_id] = Anchor(records[-1].seq, records[-1].record_hash, stamp)
    seen = []
    original = writer_module.load_chain

    async def spy(session, **kw):
        seen.append(kw.get("after_seq", 0))
        return await original(session, **kw)

    monkeypatch.setattr(writer_module, "load_chain", spy)
    record = await writer.append(chain_id=chain_id, event=events[3])
    assert seen == [0] and record.seq == 4
