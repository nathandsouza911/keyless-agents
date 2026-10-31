"""Fail-closed orchestration (Task 12; SD-007, threat model Â§5).

Audit writes that fail before a request: nothing is sent, the run is
halted, 503. An audit write that fails after a response: the data is
withheld, the run is halted, and the verifier lists the intent without an
outcome. A transaction cannot undo a request that reached Graph; these tests
show what the evidence then says, not that the request was undone."""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest
import respx

from clw.audit.events import AuditChainCompromised, AuditUnavailable, EventType
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter
from tests.db.broker_fixtures import (
    USERS, add_tenant, auth, body, kinds, make_service, page, run_records, run_row, start_run, write_key,
)

pytestmark = pytest.mark.pg


@pytest.fixture(scope="module")
def key_path(tmp_path_factory):
    return write_key(tmp_path_factory.mktemp("profile-key"))


@pytest.fixture
async def tenant(admin_conn):
    return await add_tenant(admin_conn)


@pytest.fixture
def writer(sessionmaker):
    return AuditWriter(sessionmaker)


@pytest.fixture
def graph():
    with respx.mock(assert_all_called=False) as mock:
        yield mock.route(host="graph.microsoft.com")


class FailingWriter:
    """The real writer, except that the n-th append of `event_type` raises."""

    def __init__(self, writer: AuditWriter, event_type: str, *, nth: int = 1,
                 error: Exception | None = None) -> None:
        self.writer, self.event_type, self.nth = writer, event_type, nth
        self.error = error or AuditUnavailable("database lost")
        self.seen = 0

    async def append(self, *, chain_id, event):
        if event["event_type"] == self.event_type:
            self.seen += 1
            if self.seen == self.nth:
                raise self.error
        return await self.writer.append(chain_id=chain_id, event=event)


async def _report(sessionmaker, tid):
    async with sessionmaker() as session:
        return await verify_chain(session, chain_id=tid)


async def _halted(svc, token, admin_conn, run_id):
    """Later operations are refused and the database records the halt."""
    assert (await svc.handle_request(auth(token), body())).body == {"status": "denied", "reason": "run_halted"}
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"]) == ("halted", "audit_unavailable")


# ------------------------------------------------------- before the request


@pytest.mark.parametrize("event_type", [EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_REQUEST])
async def test_audit_failure_before_request_sends_nothing(sessionmaker, writer, admin_conn, tenant, key_path, graph,
                                                          event_type):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path, writer=FailingWriter(writer, event_type))

    result = await svc.handle_request(auth(token), body())

    assert (result.status_code, result.body) == (503, {"status": "error", "reason": "audit_unavailable"})
    assert graph.call_count == 0
    await _halted(svc, token, admin_conn, run_id)
    # A fresh broker process (no in-memory halt) refuses too: the halt is in the database.
    fresh = make_service(sessionmaker, key_path=key_path, writer=writer)
    assert (await fresh.handle_request(auth(token), body())).body["reason"] == "run_halted"
    report = await _report(sessionmaker, tenant[0])
    assert report.valid and report.intents_without_outcome == ()


async def test_audit_failure_on_a_denial_halts_the_run(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=FailingWriter(writer, EventType.OP_DECISION))
    result = await svc.handle_request(auth(token), body("users.update", {"user_id": str(uuid.uuid4())}))
    assert result.status_code == 503
    await _halted(svc, token, admin_conn, run_id)


async def test_audit_failure_on_a_retry_decision_sends_no_retry(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [httpx.Response(429), page()]
    svc = make_service(sessionmaker, key_path=key_path, writer=FailingWriter(writer, EventType.OP_DECISION, nth=2))

    result = await svc.handle_request(auth(token), body())

    assert result.status_code == 503 and graph.call_count == 1
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert [r.attempt for r in records if r.event_type == EventType.GRAPH_REQUEST] == [1]
    await _halted(svc, token, admin_conn, run_id)
    assert (await _report(sessionmaker, tenant[0])).complete  # attempt 1 was answered


# --------------------------------------------------------- after the response


async def test_audit_failure_after_response_withholds_data(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page([{"id": "SENSITIVE-USER-DATA"}]))
    svc = make_service(sessionmaker, key_path=key_path, writer=FailingWriter(writer, EventType.GRAPH_RESPONSE))

    result = await svc.handle_request(auth(token), body())

    assert (result.status_code, result.body) == (503, {"status": "error", "reason": "audit_unavailable"})
    assert "SENSITIVE-USER-DATA" not in json.dumps(result.body)
    assert graph.call_count == 1  # the read happened; it cannot be undone
    await _halted(svc, token, admin_conn, run_id)
    report = await _report(sessionmaker, tenant[0])
    request = [r for r in await run_records(sessionmaker, tenant[0], run_id) if r.event_type == "GRAPH_REQUEST"][0]
    assert report.intents_without_outcome == (request.seq,)


async def test_audit_failure_on_a_later_page_withholds_every_page(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                  graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    url = "https://graph.microsoft.com/v1.0/users?$select=id,signInActivity&$top=50&$skiptoken=p2"
    graph.side_effect = [page([{"id": "PAGE-ONE"}], url), page([{"id": "PAGE-TWO"}])]
    svc = make_service(sessionmaker, key_path=key_path, writer=FailingWriter(writer, EventType.GRAPH_RESPONSE, nth=2))
    result = await svc.handle_request(auth(token), body())
    assert result.status_code == 503 and "PAGE-ONE" not in json.dumps(result.body)
    assert len((await _report(sessionmaker, tenant[0])).intents_without_outcome) == 1


async def test_audit_failure_recording_the_run_failure(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    from tests.db.broker_fixtures import FakeMsal

    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=FailingWriter(writer, EventType.RUN_FAILED),
                       factory=FakeMsal(roles=["User.Read.All"]))

    result = await svc.handle_request(auth(token), body())

    assert result.status_code == 503 and graph.call_count == 0
    # The run row already says failed and the token is revoked; the chain lacks
    # RUN_FAILED. That gap is visible (no terminal record) and recoverable from
    # runs.outcome; the run cannot continue either way.
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("failed", "permissions_missing", None)
    assert kinds(await run_records(sessionmaker, tenant[0], run_id))[-1] == EventType.CREDENTIAL_REJECTED
    assert (await svc.handle_request(auth(token), body())).body["reason"] in ("run_halted", "run_token_invalid")


# ------------------------------------------------- run state and the database


async def test_run_state_write_failure_halts_in_memory(sessionmaker, writer, admin_conn, tenant, key_path, graph,
                                                       monkeypatch):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=httpx.Response(400))
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)

    async def broken(*args, **kwargs):
        raise ConnectionError("database lost")

    monkeypatch.setattr(svc, "_set_status", broken)
    result = await svc.handle_request(auth(token), body())

    assert (result.status_code, result.body) == (503, {"status": "error", "reason": "broker_unavailable"})
    assert (await svc.handle_request(auth(token), body())).body == {"status": "denied", "reason": "run_halted"}
    assert graph.call_count == 1  # the second operation never reached Graph
    assert (await run_row(admin_conn, run_id))["status"] == "running"  # left for the reconciler (Task 14)


async def test_unreadable_run_status_in_the_lock_sends_and_records_nothing(sessionmaker, writer, admin_conn, tenant,
                                                                          key_path, graph, monkeypatch):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)

    async def unreadable(run):
        raise ConnectionError("database lost")

    monkeypatch.setattr(svc, "_status", unreadable)
    result = await svc.handle_request(auth(token), body())
    assert (result.status_code, result.body) == (503, {"status": "error", "reason": "broker_unavailable"})
    assert graph.call_count == 0
    assert kinds(await run_records(sessionmaker, tenant[0], run_id))[-1] == EventType.RUN_STARTED


async def test_database_unreachable_at_resolution_sends_nothing(unreachable_sessionmaker, sessionmaker, writer,
                                                                admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(unreachable_sessionmaker, key_path=key_path, writer=writer)
    result = await svc.handle_request(auth(token), body())
    assert (result.status_code, result.body) == (503, {"status": "error", "reason": "broker_unavailable"})
    assert graph.call_count == 0
    assert kinds(await run_records(sessionmaker, tenant[0], run_id))[-1] == EventType.RUN_STARTED


async def test_cancellation_mid_request_halts_and_leaves_the_intent_visible(sessionmaker, writer, admin_conn, tenant,
                                                                            key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    sent = asyncio.Event()

    async def hang(request):
        sent.set()
        await asyncio.sleep(3600)

    graph.side_effect = hang
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)

    task = asyncio.create_task(svc.handle_request(auth(token), body()))
    await asyncio.wait_for(sent.wait(), 30)
    task.cancel()  # e.g. broker shutdown while Graph is answering
    with pytest.raises(asyncio.CancelledError):
        await task

    assert (await svc.handle_request(auth(token), body())).body == {"status": "denied", "reason": "run_halted"}
    report = await _report(sessionmaker, tenant[0])
    assert len(report.intents_without_outcome) == 1  # "authorized and possibly sent" (RR-4)


async def test_compromised_chain_refuses_and_sends_nothing(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    await admin_conn.execute("SET session_replication_role = replica")  # set-up: a superuser edits evidence
    try:
        await admin_conn.execute("UPDATE audit_events SET status = 'requested', task_id = 'tampered' "
                                 "WHERE chain_id = $1 AND seq = 1", tenant[0])
    finally:
        await admin_conn.execute("SET session_replication_role = DEFAULT")
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path, writer=AuditWriter(sessionmaker))

    result = await svc.handle_request(auth(token), body())

    assert result.body == {"status": "error", "reason": "audit_unavailable"}
    assert graph.call_count == 0
    report = await _report(sessionmaker, tenant[0])
    assert (1, "hash_mismatch") in {(e.seq, e.issue) for e in report.errors}


async def test_writer_integrity_refusal_is_an_audit_failure():
    assert issubclass(AuditChainCompromised, AuditUnavailable)


async def test_unexpected_writer_error_is_treated_as_audit_failure(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                   graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path,
                       writer=FailingWriter(writer, EventType.GRAPH_REQUEST, error=RuntimeError("bug")))
    result = await svc.handle_request(auth(token), body())
    assert result.body == {"status": "error", "reason": "audit_unavailable"} and graph.call_count == 0


async def test_a_failed_run_cannot_later_be_completed(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=httpx.Response(400))
    await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    import asyncpg

    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute("UPDATE runs SET status = 'completed', result = '{}'::jsonb WHERE id = $1",
                                 uuid.UUID(run_id))
    assert (await run_row(admin_conn, run_id))["status"] == "failed"


async def test_successful_data_is_released_only_after_its_response_record(sessionmaker, writer, admin_conn, tenant,
                                                                          key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    order = []

    class Observing:
        async def append(self, *, chain_id, event):
            record = await writer.append(chain_id=chain_id, event=event)
            order.append(record.event_type)
            return record

    result = await make_service(sessionmaker, key_path=key_path, writer=Observing()).handle_request(auth(token), body())
    assert result.body["data"] == USERS and order[-1] == EventType.GRAPH_RESPONSE
