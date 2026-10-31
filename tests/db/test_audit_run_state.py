"""The writer refuses records that would break a run's end (Task 14; SD-034).

After a run's terminal record nothing more is written for that run, and a
completion is refused while one of its requests is unanswered. The check
runs under the chain's advisory lock in the append transaction, so it holds
against concurrent writers too.
"""

from __future__ import annotations

import asyncio

import pytest

from clw.audit.events import AuditRunStateRefused, AuditUnavailable, EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from tests.db.broker_fixtures import MANIFEST, add_tenant, start_run

pytestmark = pytest.mark.pg

PROFILE = {"profile_id": MANIFEST.profile.id, "profile_version": MANIFEST.profile.version, "auth_mode": MANIFEST.mode}
SHA = "a" * 64


def ev(tid, run_id, kind, **fields):
    statuses = {EventType.RUN_COMPLETED: "completed", EventType.RUN_FAILED: "failed",
                EventType.RUN_TIMED_OUT: "timed_out", EventType.OP_DECISION: "allowed",
                EventType.CREDENTIAL_ACQUIRED: "accepted", EventType.GRAPH_REQUEST: "attempted",
                EventType.GRAPH_RESPONSE: "succeeded"}
    defaults = {
        EventType.RUN_COMPLETED: {"outcome": "succeeded", "details": {"result_sha256": SHA}},
        EventType.RUN_FAILED: {"reason": "task_error"},
        EventType.RUN_TIMED_OUT: {"reason": "timeout"},
        EventType.OP_DECISION: {"operation": "users.list_with_sign_in_activity", "reason": "allowed",
                                "http_method": "GET", "path_template": "/users",
                                "details": {"request_target": "/v1.0/users?$select=id"}},  # RR-5 (SD-039)
        EventType.CREDENTIAL_ACQUIRED: PROFILE,
        EventType.GRAPH_RESPONSE: {"operation": "users.list_with_sign_in_activity", "attempt": 1,
                                   "duration_ms": 5, "http_status": 200, "item_count": 0},
    }
    return {"tenant_id": tid, "event_type": kind, "status": statuses[kind], "run_id": run_id,
            **defaults.get(kind, {}), **fields}


async def request(writer, tid, run_id, attempt=1):
    decision = await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.OP_DECISION))
    if attempt == 1:
        await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.CREDENTIAL_ACQUIRED))
    return await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.GRAPH_REQUEST, "status": "attempted", "run_id": run_id,
        "operation": "users.list_with_sign_in_activity", "decision_seq": decision.seq, "http_method": "GET",
        "path_template": "/users", "request_target": "/v1.0/users?$select=id", "attempt": attempt})


@pytest.fixture
async def tenant(admin_conn):
    return await add_tenant(admin_conn)


@pytest.fixture
def writer(sessionmaker):
    return AuditWriter(sessionmaker)


async def _valid(sessionmaker, tid):
    async with sessionmaker() as session:
        return await verify_chain(session, chain_id=tid)


@pytest.mark.parametrize("terminal", [EventType.RUN_COMPLETED, EventType.RUN_FAILED, EventType.RUN_TIMED_OUT])
@pytest.mark.parametrize("late", [EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_RESPONSE,
                                  EventType.RUN_COMPLETED, EventType.RUN_FAILED, EventType.RUN_TIMED_OUT])
async def test_nothing_is_written_after_a_terminal_record(sessionmaker, writer, admin_conn, tenant, terminal, late):
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)
    await writer.append(chain_id=tid, event=ev(tid, run_id, terminal))
    with pytest.raises(AuditRunStateRefused) as caught:
        await writer.append(chain_id=tid, event=ev(tid, run_id, late))
    assert (caught.value.reason, caught.value.run_id) == ("run_ended", run_id)
    assert isinstance(caught.value, AuditUnavailable)  # callers fail closed as for any audit failure
    report = await _valid(sessionmaker, tid)
    assert report.valid and report.errors == ()


async def test_late_graph_request_is_refused(sessionmaker, writer, admin_conn, tenant):
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)
    decision = await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.OP_DECISION))
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.CREDENTIAL_ACQUIRED))
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_TIMED_OUT))
    with pytest.raises(AuditRunStateRefused, match="run_ended"):
        await writer.append(chain_id=tid, event={
            "tenant_id": tid, "event_type": EventType.GRAPH_REQUEST, "status": "attempted", "run_id": run_id,
            "operation": "users.list_with_sign_in_activity", "decision_seq": decision.seq, "http_method": "GET",
            "path_template": "/users", "request_target": "/v1.0/users?$select=id", "attempt": 1})
    assert (await _valid(sessionmaker, tid)).valid


async def test_completion_refused_while_a_request_is_unanswered(sessionmaker, writer, admin_conn, tenant):
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)
    await request(writer, tid, run_id)
    with pytest.raises(AuditRunStateRefused, match="outstanding_requests"):
        await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_COMPLETED))
    # A failure or timeout may end it; the open intent stays listed.
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_FAILED))
    report = await _valid(sessionmaker, tid)
    assert report.valid and len(report.intents_without_outcome) == 1


async def test_completion_allowed_once_every_request_is_answered(sessionmaker, writer, admin_conn, tenant):
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)
    await request(writer, tid, run_id, attempt=1)
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.GRAPH_RESPONSE, attempt=1))
    await request(writer, tid, run_id, attempt=2)
    with pytest.raises(AuditRunStateRefused, match="outstanding_requests"):
        await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_COMPLETED))
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.GRAPH_RESPONSE, attempt=2))
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_COMPLETED))
    report = await _valid(sessionmaker, tid)
    assert report.valid and report.intents_without_outcome == ()


async def test_other_runs_and_chains_are_unaffected(sessionmaker, writer, admin_conn, tenant):
    tid = tenant[0]
    ended, _ = await start_run(admin_conn, writer, tenant)
    other, _ = await start_run(admin_conn, writer, tenant)
    await writer.append(chain_id=tid, event=ev(tid, ended, EventType.RUN_FAILED))
    await request(writer, tid, other)  # same chain, another run
    second = await add_tenant(admin_conn)
    foreign, _ = await start_run(admin_conn, writer, second)
    await writer.append(chain_id=second[0], event=ev(second[0], foreign, EventType.OP_DECISION))
    assert (await _valid(sessionmaker, tid)).valid and (await _valid(sessionmaker, second[0])).valid


def started(tid, run_id):
    return {"tenant_id": tid, "event_type": EventType.RUN_STARTED, "status": "started", "run_id": run_id,
            "task_id": MANIFEST.id, "task_manifest_sha256": MANIFEST.sha256, **PROFILE}


async def test_a_second_run_started_is_refused(sessionmaker, writer, admin_conn, tenant):
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)  # RUN_REQUESTED + RUN_STARTED
    with pytest.raises(AuditRunStateRefused) as caught:
        await writer.append(chain_id=tid, event=started(tid, run_id))
    assert caught.value.reason == "run_already_started"
    report = await _valid(sessionmaker, tid)
    assert report.valid and "run_already_started" not in [e.issue for e in report.errors]


async def test_a_refused_append_writes_nothing_and_the_writer_continues(sessionmaker, writer, admin_conn, tenant):
    # The refusal rolls back the append transaction: no row, no gap, and the
    # writer's cached position (fast path) is still right for the next append.
    tid = tenant[0]
    ended, _ = await start_run(admin_conn, writer, tenant)
    other, _ = await start_run(admin_conn, writer, tenant)
    await writer.append(chain_id=tid, event=ev(tid, ended, EventType.RUN_FAILED))
    before = await admin_conn.fetchval("SELECT max(seq) FROM audit_events WHERE chain_id = $1", tid)
    for late in (EventType.OP_DECISION, EventType.RUN_TIMED_OUT, EventType.RUN_COMPLETED):
        with pytest.raises(AuditRunStateRefused):
            await writer.append(chain_id=tid, event=ev(tid, ended, late))
    assert await admin_conn.fetchval("SELECT max(seq) FROM audit_events WHERE chain_id = $1", tid) == before
    nxt = await writer.append(chain_id=tid, event=ev(tid, other, EventType.CREDENTIAL_ACQUIRED))
    assert nxt.seq == before + 1
    assert (await _valid(sessionmaker, tid)).valid


async def test_a_concurrent_request_and_completion_never_leave_the_completion_unanswered(sessionmaker, admin_conn,
                                                                                          tenant):
    tid = tenant[0]
    for _ in range(5):
        broker, runner = AuditWriter(sessionmaker), AuditWriter(sessionmaker)
        run_id, _ = await start_run(admin_conn, broker, tenant)
        await request(broker, tid, run_id, attempt=1)
        await broker.append(chain_id=tid, event=ev(tid, run_id, EventType.GRAPH_RESPONSE, attempt=1))
        outcomes = await asyncio.gather(request(broker, tid, run_id, attempt=2),
                                        runner.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_COMPLETED)),
                                        return_exceptions=True)
        # Exactly one side wins: the request (and the completion is refused as
        # outstanding), or the completion (and the request is refused as late).
        refused = [o for o in outcomes if isinstance(o, AuditRunStateRefused)]
        assert len(refused) == 1 and refused[0].reason in ("outstanding_requests", "run_ended")
    report = await _valid(sessionmaker, tid)
    assert report.valid and "completed_with_outstanding_requests" not in [e.issue for e in report.errors]


async def test_a_terminal_record_on_another_chain_does_not_end_the_run(sessionmaker, writer, admin_conn, tenant):
    # A record naming this run on another tenant's chain (forged, RR-1) cannot end it here.
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)
    other = (await add_tenant(admin_conn))[0]
    await writer.append(chain_id=other, event=ev(other, run_id, EventType.RUN_FAILED))
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.CREDENTIAL_ACQUIRED))
    await writer.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_TIMED_OUT))
    assert (await _valid(sessionmaker, tid)).valid


async def test_concurrent_terminal_and_late_records_never_follow_the_end(sessionmaker, admin_conn, tenant):
    # Two writers (two processes in production) race a terminal record against
    # broker records. Whatever the order, nothing of the run follows its end.
    tid = tenant[0]
    for _ in range(5):
        broker, runner = AuditWriter(sessionmaker), AuditWriter(sessionmaker)
        run_id, _ = await start_run(admin_conn, broker, tenant)
        await broker.append(chain_id=tid, event=ev(tid, run_id, EventType.CREDENTIAL_ACQUIRED))

        async def late():
            for _ in range(6):
                try:
                    await broker.append(chain_id=tid, event=ev(tid, run_id, EventType.OP_DECISION))
                except AuditRunStateRefused:
                    return

        await asyncio.gather(late(), runner.append(chain_id=tid, event=ev(tid, run_id, EventType.RUN_TIMED_OUT)))
        async with sessionmaker() as session:
            kinds = [r.event_type for r in await load_chain(session, chain_id=tid) if r.run_id == run_id]
        assert kinds[-1] == EventType.RUN_TIMED_OUT and kinds.count(EventType.RUN_TIMED_OUT) == 1
    assert (await _valid(sessionmaker, tid)).valid
