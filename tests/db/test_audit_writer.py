"""AuditWriter against real Postgres: success paths, denied paths, and every
failure path raising AuditUnavailable (SD-006, SD-007)."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import func, select

from clw.audit.events import AuditEventInvalid, AuditUnavailable
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter
from clw.db.models import AuditEventRow

from tests.unit.audit.helpers import ev, standard_events

pytestmark = pytest.mark.pg


def _events_for(chain_id):
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


async def _count(sessionmaker, chain_id) -> int:
    async with sessionmaker() as s:
        return await s.scalar(select(func.count()).select_from(AuditEventRow).where(AuditEventRow.chain_id == chain_id))


async def test_standard_run_round_trips_and_verifies(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    written = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)]
    async with sessionmaker() as s:
        rows = (await s.scalars(select(AuditEventRow).where(AuditEventRow.chain_id == chain_id)
                                .order_by(AuditEventRow.seq))).all()
        report = await verify_chain(s, chain_id=chain_id)
    assert [r.to_record() for r in rows] == written  # JSONB/text round-trip is lossless
    assert report.valid and report.complete
    assert report.head_seq == len(written)


async def test_denied_decision_is_recorded_and_verifies(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    e = _events_for(chain_id)
    for event in (e[0], e[1], e[6]):  # requested, started, denied
        await writer.append(chain_id=chain_id, event=event)
    await writer.append(chain_id=chain_id, event={**ev("RUN_FAILED", "failed", reason="all_operations_denied"),
                                                  "tenant_id": chain_id})
    async with sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
        denial = await s.scalar(select(AuditEventRow).where(AuditEventRow.chain_id == chain_id,
                                                            AuditEventRow.seq == 3))
    assert report.valid and report.complete
    assert (denial.event_type, denial.status, denial.reason) == ("OP_DECISION", "denied", "not_in_manifest")


async def _start_run(writer, chain_id):
    for e in _events_for(chain_id)[:2]:  # RUN_REQUESTED, RUN_STARTED
        await writer.append(chain_id=chain_id, event=e)


async def test_concurrent_appends_produce_linear_chain(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    await _start_run(writer, chain_id)
    event = {**ev("OP_DECISION", "denied", operation="users.update", reason="not_in_manifest"), "tenant_id": chain_id}
    await asyncio.gather(*(writer.append(chain_id=chain_id, event=event) for _ in range(50)))
    async with sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
        seqs = (await s.scalars(select(AuditEventRow.seq).where(AuditEventRow.chain_id == chain_id)
                                .order_by(AuditEventRow.seq))).all()
    assert report.valid, report.errors
    assert seqs == list(range(1, 53))


async def test_concurrent_appends_from_two_writers_and_engines(sessionmaker, pg_dsn, chain_id):
    # Broker and runner are separate processes with separate pools.
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    other_engine = create_async_engine(pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    other = async_sessionmaker(other_engine, class_=AsyncSession, expire_on_commit=False)
    try:
        event = {**ev("OP_DECISION", "denied", operation="users.update", reason="not_in_manifest"), "tenant_id": chain_id}
        a, b = AuditWriter(sessionmaker), AuditWriter(other)
        await _start_run(a, chain_id)
        await asyncio.gather(*(w.append(chain_id=chain_id, event=event) for w in [a, b] * 20))
    finally:
        await other_engine.dispose()
    async with sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
    assert report.valid and report.total == 42


async def test_chains_are_independent_per_tenant(sessionmaker):
    import uuid

    writer = AuditWriter(sessionmaker)
    t1, t2 = str(uuid.uuid4()), str(uuid.uuid4())
    for t in (t1, t2):
        for e in _events_for(t)[:3]:
            await writer.append(chain_id=t, event=e)
    async with sessionmaker() as s:
        r1 = await verify_chain(s, chain_id=t1)
        r2 = await verify_chain(s, chain_id=t2)
    assert r1.valid and r2.valid and r1.total == r2.total == 3


async def test_cross_tenant_event_is_refused(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    with pytest.raises(AuditEventInvalid):
        await writer.append(chain_id=chain_id, event={**_events_for(chain_id)[0], "tenant_id": "someone-else"})
    assert await _count(sessionmaker, chain_id) == 0


async def test_invalid_event_writes_nothing(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    with pytest.raises(AuditEventInvalid):
        await writer.append(chain_id=chain_id, event={**_events_for(chain_id)[2], "reason": "fine"})
    assert await _count(sessionmaker, chain_id) == 0


async def test_unreachable_database_raises_audit_unavailable(unreachable_sessionmaker, chain_id):
    writer = AuditWriter(unreachable_sessionmaker)
    with pytest.raises(AuditUnavailable):
        await writer.append(chain_id=chain_id, event=_events_for(chain_id)[0])


async def test_insert_refused_by_database_raises_audit_unavailable(sessionmaker, admin_conn, app_sessionmaker, chain_id):
    await admin_conn.execute("REVOKE INSERT ON audit_events FROM clw_app_test")
    try:
        with pytest.raises(AuditUnavailable):
            await AuditWriter(app_sessionmaker).append(chain_id=chain_id, event=_events_for(chain_id)[0])
    finally:
        await admin_conn.execute("GRANT INSERT ON audit_events TO clw_app_test")
    assert await _count(sessionmaker, chain_id) == 0


async def test_app_role_can_append_and_verify(app_sessionmaker, chain_id):
    writer = AuditWriter(app_sessionmaker)
    for e in _events_for(chain_id):
        await writer.append(chain_id=chain_id, event=e)
    async with app_sessionmaker() as s:
        assert (await verify_chain(s, chain_id=chain_id)).valid


async def test_append_is_independent_of_callers_transaction(sessionmaker, chain_id):
    # The writer commits in its own transaction: a caller rolling back its
    # own work cannot erase the evidence that something was attempted.
    writer = AuditWriter(sessionmaker)
    async with sessionmaker() as caller:
        async with caller.begin():
            await writer.append(chain_id=chain_id, event=_events_for(chain_id)[0])
            await caller.rollback()
    assert await _count(sessionmaker, chain_id) == 1


# ------------------------- write-ahead with the real writer (SD-007)

from clw.audit.write_ahead import audited_attempt


def _request(chain_id):
    return {**standard_events()[4], "tenant_id": chain_id}


def _response(chain_id):
    return {**standard_events()[5], "tenant_id": chain_id}


async def _prefix(writer, chain_id):
    for e in _events_for(chain_id)[:4]:  # requested, started, allowed decision, credential
        await writer.append(chain_id=chain_id, event=e)


async def test_write_ahead_success_with_real_database(sessionmaker, chain_id):
    writer = AuditWriter(sessionmaker)
    await _prefix(writer, chain_id)
    sent = []

    async def send():
        sent.append(1)
        return {"value": [1, 2]}

    result = await audited_attempt(
        record_intent=lambda: writer.append(chain_id=chain_id, event=_request(chain_id)),
        send=send,
        record_outcome=lambda r, e: writer.append(chain_id=chain_id, event=_response(chain_id)),
    )
    async with sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
    assert result == {"value": [1, 2]} and sent == [1]
    assert report.valid and report.complete


async def test_database_down_before_request_means_nothing_is_sent(unreachable_sessionmaker, chain_id):
    down = AuditWriter(unreachable_sessionmaker)
    sent = []

    async def send():
        sent.append(1)
        return {}

    with pytest.raises(AuditUnavailable):
        await audited_attempt(
            record_intent=lambda: down.append(chain_id=chain_id, event=_request(chain_id)),
            send=send,
            record_outcome=lambda r, e: down.append(chain_id=chain_id, event=_response(chain_id)),
        )
    assert sent == []


async def test_database_lost_after_response_withholds_data_and_leaves_visible_gap(
    sessionmaker, unreachable_sessionmaker, chain_id
):
    up, down = AuditWriter(sessionmaker), AuditWriter(unreachable_sessionmaker)
    await _prefix(up, chain_id)

    async def send():
        return {"value": ["user-data"]}

    with pytest.raises(AuditUnavailable):
        await audited_attempt(
            record_intent=lambda: up.append(chain_id=chain_id, event=_request(chain_id)),
            send=send,
            record_outcome=lambda r, e: down.append(chain_id=chain_id, event=_response(chain_id)),
        )
    async with sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
    assert report.valid
    assert report.intents_without_outcome == (5,)
    assert not report.complete
