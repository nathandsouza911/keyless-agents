"""Gate 1 L-A and L-B (fifth review): writers with cached positions, recovery
and the clock.

The database clock is simulated by patching AuditWriter._db_now; writes made
under a simulated clock go through a superuser session with
session_replication_role = replica, because the real trigger reads the real
clock. CHECK constraints still apply. Writes at real time use the
least-privileged app role and the real trigger."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.audit.chain import (
    Anchor,
    blocking_findings,
    integrity_findings,
    next_record,
    recovery_record,
    verify_records,
)
from clw.audit.events import AuditChainCompromised
from clw.audit.verifier import load_chain
from clw.audit.writer import AuditRecoveryRefused, AuditWriter
from clw.db.models.audit_event import AuditEventRow

from tests.db.conftest import _sqlalchemy_url
from tests.unit.audit.helpers import standard_events

pytestmark = pytest.mark.pg


class SimClock:
    """Controls AuditWriter._db_now; ``at`` None means the real DB clock."""

    def __init__(self, monkeypatch):
        self.at: datetime | None = None
        real = AuditWriter._db_now
        clock = self

        async def fake(writer, session):
            now = await real(writer, session)
            return now if clock.at is None else clock.at

        monkeypatch.setattr(AuditWriter, "_db_now", fake)


@pytest.fixture
def clock(monkeypatch):
    return SimClock(monkeypatch)


@pytest.fixture
async def replica_sessionmaker(pg_dsn):
    engine = create_async_engine(_sqlalchemy_url(pg_dsn))

    @event.listens_for(engine.sync_engine, "connect")
    def _replica(dbapi_conn, _):
        dbapi_conn.run_async(lambda c: c.execute("SET session_replication_role = replica"))

    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


def _events(chain_id):
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


def _run(chain_id, i):
    return {**standard_events()[0], "tenant_id": chain_id, "run_id": f"run-extra-{i}"}


async def _records(sessionmaker, chain_id):
    async with sessionmaker() as s:
        return await load_chain(s, chain_id=chain_id)


async def _count(admin_conn, chain_id) -> int:
    return await admin_conn.fetchval("SELECT count(*) FROM audit_events WHERE chain_id = $1", chain_id)


async def _db_time(admin_conn) -> datetime:
    return await admin_conn.fetchval("SELECT clock_timestamp()")


# ------------------------------------------------------------- L-A


async def test_stale_cached_writer_accepts_a_validly_recovered_chain(
        replica_sessionmaker, admin_conn, chain_id, clock, caplog):
    """The reviewer's L-A case: writer B caches a record written while the
    clock ran an hour fast; after the step-back another writer recovers;
    when B appends 56 minutes later its cached record is inside the 5-minute
    window again. B must append (full verification accepts the chain), with
    no CRITICAL alert, rather than flag the valid recovery."""
    T = await _db_time(admin_conn)
    ev = _events(chain_id)
    B = AuditWriter(replica_sessionmaker)
    clock.at = T
    await B.append(chain_id=chain_id, event=ev[0])
    await B.append(chain_id=chain_id, event=ev[1])
    clock.at = T + timedelta(hours=1)
    await B.append(chain_id=chain_id, event=ev[2])
    await B.append(chain_id=chain_id, event=ev[3])
    assert B._anchors[chain_id].seq == 4

    clock.at = T
    C = AuditWriter(replica_sessionmaker)
    with pytest.raises(AuditChainCompromised):
        await C.append(chain_id=chain_id, event=ev[4])
    head = (await _records(replica_sessionmaker, chain_id))[-1]
    recovery = await C.append_recovery(chain_id=chain_id, operator="op", reason="r", expected_head_hash=head.record_hash)
    clock.at = T + timedelta(minutes=10)
    await C.append(chain_id=chain_id, event=_run(chain_id, 1))

    clock.at = T + timedelta(minutes=56)
    assert B._anchors[chain_id].seq == 4  # stale, but inside the window again
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="clw.audit.alert"):
        record = await B.append(chain_id=chain_id, event=_run(chain_id, 2))
    assert record.seq == recovery.seq + 2
    assert not [r for r in caplog.records if r.levelno >= logging.CRITICAL]
    records = await _records(replica_sessionmaker, chain_id)
    report = verify_records(records, chain_id=chain_id, now=clock.at)
    assert report.integrity_state == "recovered" and report.provisional == ()
    assert B._anchors[chain_id].seq == record.seq  # cache re-established from the full check


async def test_cached_writer_still_refuses_when_full_verification_refuses(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    """Fail closed is kept: if the fast path flags something and the whole
    chain confirms it, the writer refuses and inserts nothing."""
    writer = AuditWriter(app_sessionmaker)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events(chain_id)[:3]]
    # A superuser plants a hash-broken record after the cached position.
    bad = next_record(records[-1], chain_id=chain_id, event=_run(chain_id, 1), created_at=await _db_time(admin_conn))
    from dataclasses import replace

    bad = replace(bad, record_hash="0" * 64)
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(bad))
    before = await _count(admin_conn, chain_id)
    with pytest.raises(AuditChainCompromised) as refused:
        await writer.append(chain_id=chain_id, event=_run(chain_id, 2))
    assert (4, "hash_mismatch") in refused.value.findings
    assert await _count(admin_conn, chain_id) == before
    assert chain_id not in writer._anchors


# ------------------------------------------------------------- L-B


async def _ahead_then_app_role_insert(app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    """The reviewer's L-B chain at real time: seq 1 planted 5m30s ahead (the
    only step needing the trigger bypassed), seq 2 inserted directly by the
    app role at T+4m, which the real trigger allows because the head is
    untrusted (more than 5 minutes ahead)."""
    T = await _db_time(admin_conn)
    ev = _events(chain_id)
    clock.at = T + timedelta(minutes=5, seconds=30)
    first = await AuditWriter(replica_sessionmaker).append(chain_id=chain_id, event=ev[0])
    clock.at = None
    second = next_record(Anchor(first.seq, first.record_hash, "x"), chain_id=chain_id, event=ev[1],
                         created_at=T + timedelta(minutes=4))
    async with app_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(second))
    return T, first, second


async def test_recovery_that_would_leave_a_provisional_finding_is_refused(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    T, first, second = await _ahead_then_app_role_insert(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock)
    writer = AuditWriter(app_sessionmaker)
    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=_run(chain_id, 1))
    before = await _count(admin_conn, chain_id)
    with pytest.raises(AuditRecoveryRefused,
                       match=r"retry once the database clock has passed the created_at \S+ of seq 1"):
        await writer.append_recovery(chain_id=chain_id, operator="op", reason="r", expected_head_hash=second.record_hash)
    assert await _count(admin_conn, chain_id) == before  # nothing written

    # Once the clock has passed seq 1, the chain itself settles it: seq 2 is
    # out of order, the recovery acknowledges that, and nothing is provisional.
    clock.at = T + timedelta(minutes=6)
    recovery = await AuditWriter(replica_sessionmaker).append_recovery(
        chain_id=chain_id, operator="op", reason="r", expected_head_hash=second.record_hash)
    assert [(a["seq"], a["issue"]) for a in recovery.details["acknowledged"]] == [(2, "created_at_not_monotonic")]
    cached = AuditWriter(replica_sessionmaker)
    await cached.append(chain_id=chain_id, event=_run(chain_id, 2))
    records = await _records(replica_sessionmaker, chain_id)
    for delta in (timedelta(minutes=6), timedelta(hours=2), timedelta(days=1)):
        report = verify_records(records, chain_id=chain_id, now=T + delta)
        assert report.integrity_state == "recovered" and report.provisional == (), delta


async def _plant_acknowledged_provisional(app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    """A recovery acknowledging a provisional finding, as older code or any
    INSERT-capable writer (RR-1) could write. append_recovery now refuses to."""
    T, first, second = await _ahead_then_app_role_insert(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock)
    records = await _records(replica_sessionmaker, chain_id)
    blocking = blocking_findings(records, integrity_findings(records, chain_id=chain_id, now=T))
    forged = recovery_record(records, blocking, chain_id=chain_id, operator="op", reason="r", created_at=T, now=T)
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(forged))
    records = await _records(replica_sessionmaker, chain_id)
    report = verify_records(records, chain_id=chain_id, now=T)
    assert report.integrity_state == "recovered" and report.provisional, "precondition: acknowledged provisional"
    return T, first


async def test_writer_never_caches_while_an_acknowledged_provisional_finding_exists(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    T, first = await _plant_acknowledged_provisional(app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock)
    cached = AuditWriter(replica_sessionmaker)
    clock.at = T + timedelta(seconds=10)
    await cached.append(chain_id=chain_id, event=_run(chain_id, 1))  # accepted now...
    assert chain_id not in cached._anchors                           # ...but not cached

    # The clock passes seq 1: the recovery becomes invalid. The same writer
    # (full verification every time) and a fresh writer both refuse, and
    # nothing more is inserted.
    passed = datetime.strptime(first.created_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    clock.at = passed - timedelta(minutes=4)
    before = await _count(admin_conn, chain_id)
    for writer in (cached, AuditWriter(replica_sessionmaker)):
        with pytest.raises(AuditChainCompromised) as refused:
            await writer.append(chain_id=chain_id, event=_run(chain_id, 2))
        assert any(issue == "invalid_recovery" for _, issue in refused.value.findings)
    assert await _count(admin_conn, chain_id) == before
    for later in (timedelta(hours=1), timedelta(days=1)):
        clock.at = passed + later
        with pytest.raises(AuditChainCompromised):
            await cached.append(chain_id=chain_id, event=_run(chain_id, 3))
    assert await _count(admin_conn, chain_id) == before


# ------------------------------------------------- I-1 gaps 2, 3 and 5


async def test_writer_judges_with_the_database_clock_not_the_host_clock(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock, caplog):
    """I-1 gap 2 (reviewer S7): with the host clock an hour ahead of the
    database, a record 30 minutes ahead of the database clock must still be
    flagged, and new records still carry database time."""
    db_now = await _db_time(admin_conn)
    host_ahead = AuditWriter(app_sessionmaker, clock=lambda: datetime.now(timezone.utc) + timedelta(hours=1))
    with caplog.at_level(logging.WARNING, logger="clw.audit.alert"):
        record = await host_ahead.append(chain_id=chain_id, event=_events(chain_id)[0])
    assert any("audit_clock_drift" in r.getMessage() for r in caplog.records)
    written = datetime.strptime(record.created_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert abs(written - db_now) < timedelta(minutes=1)

    clock.at = db_now + timedelta(minutes=30)
    await AuditWriter(replica_sessionmaker).append(chain_id=chain_id, event=_events(chain_id)[1])
    clock.at = None
    with pytest.raises(AuditChainCompromised) as refused:
        await AuditWriter(app_sessionmaker, clock=lambda: datetime.now(timezone.utc) + timedelta(hours=1)).append(
            chain_id=chain_id, event=_events(chain_id)[2])
    assert (2, "created_at_in_future") in refused.value.findings


async def test_superuser_backdated_record_after_the_cached_position_is_refused(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    """I-1 gap 3 (reviewer S8): the incremental check must use the cached
    record's timestamp as the baseline; a backdated record inserted after it
    (trigger bypassed) is refused by the cached writer and by a fresh one."""
    writer = AuditWriter(app_sessionmaker)
    for e in _events(chain_id)[:3]:
        await writer.append(chain_id=chain_id, event=e)
    assert writer._anchors[chain_id].seq == 3
    head = (await _records(app_sessionmaker, chain_id))[-1]
    backdated = next_record(head, chain_id=chain_id, event=_run(chain_id, 1),
                            created_at=await _db_time(admin_conn) - timedelta(hours=2))
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(backdated))
    for w in (writer, AuditWriter(app_sessionmaker)):
        with pytest.raises(AuditChainCompromised) as refused:
            await w.append(chain_id=chain_id, event=_run(chain_id, 2))
        assert (4, "created_at_not_monotonic") in refused.value.findings


@pytest.fixture
async def seqscan_sessionmaker(app_role_dsn):
    """App-role sessions that cannot use indexes, so a query without ORDER BY
    returns rows in physical (heap) order."""
    engine = create_async_engine(_sqlalchemy_url(app_role_dsn))

    @event.listens_for(engine.sync_engine, "connect")
    def _no_index(dbapi_conn, _):
        dbapi_conn.run_async(lambda c: c.execute("SET enable_indexscan = off; SET enable_bitmapscan = off; "
                                                 "SET enable_indexonlyscan = off"))

    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


async def test_chain_is_loaded_in_seq_order_whatever_the_physical_order(admin_conn, seqscan_sessionmaker, chain_id):
    """I-1 gap 5 (reviewer S15): rows are stored out of seq order (trigger
    bypassed); the loader must still return them by seq."""
    writer_records = []
    head = None
    for e in _events(chain_id)[:5]:
        head = next_record(head, chain_id=chain_id, event=e, created_at=datetime.now(timezone.utc))
        writer_records.append(head)
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        for record in reversed(writer_records):  # physical order 5, 4, 3, 2, 1
            row = record.stored()
            cols = list(row)
            await admin_conn.execute(
                f"INSERT INTO audit_events ({', '.join(cols)}) VALUES "
                f"({', '.join(f'${i + 1}' + ('::jsonb' if c == 'details' else '') for i, c in enumerate(cols))})",
                *[__import__('json').dumps(row[c]) if c == "details" else row[c] for c in cols])
    finally:
        await admin_conn.execute("SET session_replication_role = origin")
    async with seqscan_sessionmaker() as s:
        physical = list((await s.execute(text("SELECT seq FROM audit_events WHERE chain_id = :c"),
                                         {"c": chain_id})).scalars())  # no ORDER BY: heap order
    # Inserted 5..1; Postgres may place a row in earlier free space, so the heap
    # order need not be exactly reversed, only out of seq order.
    assert sorted(physical) == [1, 2, 3, 4, 5] and physical != [1, 2, 3, 4, 5]
    loaded = await _records(seqscan_sessionmaker, chain_id)
    assert [r.seq for r in loaded] == [1, 2, 3, 4, 5]
    assert verify_records(loaded, chain_id=chain_id).valid


async def test_database_clock_behind_the_host_is_what_judges_new_records(
        replica_sessionmaker, chain_id, clock):
    """I-1 gap 2, both paths: the database clock is an hour behind the host's.
    A record 30 minutes ahead of the database clock is ahead (provisional)
    even though it is in the host's past; both the cached writer and a fresh
    one must refuse."""
    host_now = datetime.now(timezone.utc)
    clock.at = host_now - timedelta(hours=1)
    cached = AuditWriter(replica_sessionmaker)
    for e in _events(chain_id)[:3]:
        await cached.append(chain_id=chain_id, event=e)
    assert cached._anchors[chain_id].seq == 3
    head = (await _records(replica_sessionmaker, chain_id))[-1]
    ahead = next_record(head, chain_id=chain_id, event=_run(chain_id, 1), created_at=clock.at + timedelta(minutes=30))
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(ahead))
    for writer in (cached, AuditWriter(replica_sessionmaker)):
        with pytest.raises(AuditChainCompromised) as refused:
            await writer.append(chain_id=chain_id, event=_run(chain_id, 2))
        assert (4, "created_at_in_future") in refused.value.findings


async def test_recovery_is_incomplete_if_the_clock_steps_back_before_re_verification(
        replica_sessionmaker, chain_id, monkeypatch):
    """L-B, post-commit: if the database clock steps back between the commit
    and the re-verification, the recovery record itself is ahead of the clock
    (provisional). That must be reported as incomplete, not success."""
    from dataclasses import replace

    from clw.audit.writer import AuditRecoveryIncomplete

    writer = AuditWriter(replica_sessionmaker)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events(chain_id)[:3]]
    bad = replace(next_record(records[-1], chain_id=chain_id, event=_run(chain_id, 1),
                              created_at=datetime.now(timezone.utc)), record_hash="0" * 64)
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(bad))

    real = AuditWriter._db_now
    calls = []

    async def stepping(self, session):
        now = await real(self, session)
        calls.append(now)
        return now if len(calls) == 1 else now - timedelta(hours=1)  # stepped back after the commit

    monkeypatch.setattr(AuditWriter, "_db_now", stepping)
    with pytest.raises(AuditRecoveryIncomplete, match="still blocked"):
        await writer.append_recovery(chain_id=chain_id, operator="op", reason="r", expected_head_hash=bad.record_hash)


# --------------------------------------------- targeted review R1 and R2


def _forged_recovery(head, chain_id, acks):
    from clw.audit.events import EventType
    from clw.common.timeutil import utc_now

    return next_record(head, chain_id=chain_id, created_at=utc_now(), event={
        "tenant_id": chain_id, "event_type": EventType.CHAIN_RECOVERY, "status": "recorded",
        "reason": "forged", "actor_oid": "attacker",
        "details": {"acknowledged": [{"seq": s, "issue": i} for s, i in acks],
                    "observed_head_seq": head.seq, "observed_head_hash": head.record_hash}})


async def _app_insert(app_sessionmaker, record):
    async with app_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(record))


async def test_forged_recoveries_cannot_make_a_cached_writer_disagree_with_full_verification(
        app_sessionmaker, admin_conn, chain_id, caplog):
    """Targeted review R1, the reviewer's reproduction: real clock, real
    trigger, every attacker insert by the least-privileged app role. A
    recovery acknowledging a finding before the cached position is invalid
    in the incremental view only; a second forged recovery acknowledging that
    incremental-only finding is invalid in full. The cached writer must reach
    the same decision as a fresh writer and full verification: refuse."""
    from dataclasses import replace

    from clw.common.timeutil import utc_now

    ev = _events(chain_id)
    cached = AuditWriter(app_sessionmaker)
    await cached.append(chain_id=chain_id, event=ev[0])
    await cached.append(chain_id=chain_id, event=ev[1])
    head = (await _records(app_sessionmaker, chain_id))[-1]
    bad = replace(next_record(head, chain_id=chain_id, event=ev[2], created_at=utc_now()), record_hash="f" * 64)
    await _app_insert(app_sessionmaker, bad)
    await _app_insert(app_sessionmaker, _forged_recovery(bad, chain_id, [(3, "hash_mismatch")]))
    fifth = await cached.append(chain_id=chain_id, event=ev[3])  # full verification accepts (recovered)
    assert fifth.seq == 5 and cached._anchors[chain_id].seq == 5

    head = (await _records(app_sessionmaker, chain_id))[-1]
    sixth = _forged_recovery(head, chain_id, [(3, "hash_mismatch")])
    await _app_insert(app_sessionmaker, sixth)
    await _app_insert(app_sessionmaker, _forged_recovery(sixth, chain_id, [(6, "invalid_recovery")]))

    records = await _records(app_sessionmaker, chain_id)
    full = blocking_findings(records, integrity_findings(records, chain_id=chain_id))
    assert [(f.seq, f.issue) for f in full] == [(7, "invalid_recovery")]
    incremental = integrity_findings(records[5:], chain_id=chain_id,
                                     anchor=Anchor(fifth.seq, fifth.record_hash, fifth.created_at))
    assert [(f.seq, f.issue) for f in incremental] == [(6, "invalid_recovery")]
    assert blocking_findings(records[5:], incremental) == []  # the old fast path's view: all clear

    before = await _count(admin_conn, chain_id)
    for attempt in range(3):
        for writer in (cached, AuditWriter(app_sessionmaker)):
            caplog.clear()
            with caplog.at_level(logging.CRITICAL, logger="clw.audit.alert"):
                with pytest.raises(AuditChainCompromised) as refused:
                    await writer.append(chain_id=chain_id, event=_run(chain_id, attempt))
            assert refused.value.findings == [(7, "invalid_recovery")]
            assert any("audit_chain_integrity_failure" in r.getMessage() for r in caplog.records)
    assert await _count(admin_conn, chain_id) == before
    assert chain_id not in cached._anchors
    assert verify_records(records, chain_id=chain_id).integrity_state == "invalid_recovery"


async def test_retry_guidance_between_the_skew_window_and_created_at(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock):
    """Targeted review R2: at T+0:31 the record is no longer provisional but
    the recovery would copy the head's timestamp and be out of order. The
    refusal must point to the same wait (seq 1's created_at), not only to
    manual investigation, and the recovery must succeed once it has passed."""
    T, first, second = await _ahead_then_app_role_insert(
        app_sessionmaker, replica_sessionmaker, admin_conn, chain_id, clock)
    before = await _count(admin_conn, chain_id)
    clock.at = T + timedelta(seconds=31)
    with pytest.raises(AuditRecoveryRefused) as refused:
        await AuditWriter(replica_sessionmaker).append_recovery(
            chain_id=chain_id, operator="op", reason="r", expected_head_hash=second.record_hash)
    message = str(refused.value)
    assert f"retry once it has passed the created_at {first.created_at} of seq 1" in message
    assert await _count(admin_conn, chain_id) == before
    clock.at = T + timedelta(minutes=5, seconds=30)  # exactly seq 1's created_at: passed
    recovery = await AuditWriter(replica_sessionmaker).append_recovery(
        chain_id=chain_id, operator="op", reason="r", expected_head_hash=second.record_hash)
    assert recovery.created_at == first.created_at


async def test_retry_message_names_the_latest_stamped_record_when_several_are_provisional(
        replica_sessionmaker, admin_conn, chain_id, clock):
    """Several provisional records: the message must name the one whose
    created_at is latest (here seq 2, not the first provisional seq 1), and
    once the clock has passed it nothing is provisional any more."""
    T = await _db_time(admin_conn)
    ev = _events(chain_id)
    planter = AuditWriter(replica_sessionmaker)
    clock.at = T + timedelta(minutes=6)
    await planter.append(chain_id=chain_id, event=ev[0])
    clock.at = T + timedelta(minutes=9)
    second = await planter.append(chain_id=chain_id, event=ev[1])
    # A head 4 minutes ahead: a recovery at T copies its timestamp, so it is
    # not evidence against seq 1 or 2, and both stay provisional.
    # Inserted directly (next_record would copy seq 2's later timestamp).
    head = next_record(Anchor(second.seq, second.record_hash, "x"), chain_id=chain_id, event=ev[2],
                       created_at=T + timedelta(minutes=4))
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(head))
    clock.at = T
    writer = AuditWriter(replica_sessionmaker)
    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=ev[3])
    with pytest.raises(AuditRecoveryRefused) as refused:
        await writer.append_recovery(chain_id=chain_id, operator="op", reason="r", expected_head_hash=head.record_hash)
    message = str(refused.value)
    assert "provisional" in message and "seqs [1, 2]" in message
    assert f"retry once the database clock has passed the created_at {second.created_at} of seq 2" in message
    records = await _records(replica_sessionmaker, chain_id)
    passed = datetime.strptime(second.created_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert verify_records(records, chain_id=chain_id, now=passed).provisional == ()


async def test_retry_message_names_the_first_provisional_record_when_it_is_the_latest_stamped(
        replica_sessionmaker, admin_conn, chain_id, clock):
    """Final review I-2: provisional seqs 1 and 2, with seq 1 stamped later
    (T+9m) than seq 2 (T+6m). The message must name seq 1 and its timestamp,
    not the last provisional seq."""
    T = await _db_time(admin_conn)
    ev = _events(chain_id)
    clock.at = T + timedelta(minutes=9)
    first = await AuditWriter(replica_sessionmaker).append(chain_id=chain_id, event=ev[0])
    # Inserted directly: next_record would copy seq 1's later timestamp.
    second = next_record(Anchor(first.seq, first.record_hash, "x"), chain_id=chain_id, event=ev[1],
                         created_at=T + timedelta(minutes=6))
    head = next_record(Anchor(second.seq, second.record_hash, "x"), chain_id=chain_id, event=ev[2],
                       created_at=T + timedelta(minutes=4))
    async with replica_sessionmaker() as s:
        async with s.begin():
            s.add(AuditEventRow.from_record(second))
            s.add(AuditEventRow.from_record(head))
    clock.at = T
    with pytest.raises(AuditRecoveryRefused) as refused:
        await AuditWriter(replica_sessionmaker).append_recovery(
            chain_id=chain_id, operator="op", reason="r", expected_head_hash=head.record_hash)
    message = str(refused.value)
    assert "provisional" in message and "seqs [1, 2]" in message
    assert f"retry once the database clock has passed the created_at {first.created_at} of seq 1," in message
