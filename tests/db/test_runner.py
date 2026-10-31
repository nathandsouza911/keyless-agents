"""The launcher and the reconciler against PostgreSQL (Task 14; SD-008, SD-014, SD-032, SD-034).

Real: the runs table and its trigger, the audit writer and verifier, run
tokens, the lifecycle, result validation and, where a broker is involved,
the Task 12 broker service. Fake: the container backend (scripted stdout,
exit codes and kills; no Docker), Graph (respx) and MSAL. The order of
concurrent steps is set with events and hooks, never with sleeps.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import httpx
import pytest
import respx

from clw.audit.canonical import canonical_json
from clw.audit.chain import verify_run_result
from clw.audit.events import EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.broker.capability import run_token_sha256
from clw.runner.lifecycle import Ended, RunKey, RunLifecycle
from clw.runner.launcher import Launcher
from clw.runner.reconciler import Reconciler
from clw.runner.sandbox_spec import MAX_RESULT_BYTES, SandboxConfig
from tests.db.broker_fixtures import (
    CATALOG, MANIFEST, add_tenant, auth, body, make_service, page, run_row, start_run, write_key,
)
from tests.db.runner_fixtures import end_stray_queued_runs, RESULT, FailingWriter, FakeBackend, FakeProcess, on_loop, queue_run, result_line

pytestmark = pytest.mark.pg

CONFIG = SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080")


def never(deadline):
    return asyncio.Event().wait()


async def at_once(deadline):
    return None


@pytest.fixture(scope="module")
def key_path(tmp_path_factory):
    return write_key(tmp_path_factory.mktemp("profile-key"))


@pytest.fixture(autouse=True)
async def _no_stray_queued_runs(admin_conn):
    await end_stray_queued_runs(admin_conn)


@pytest.fixture
async def tenant(admin_conn):
    return await add_tenant(admin_conn)


@pytest.fixture
def writer(runner_sessionmaker):
    return AuditWriter(runner_sessionmaker)


@pytest.fixture
def launcher_for(runner_sessionmaker, writer):
    def make(backend, *, timer=never, writer_override=None, kill_grace_seconds=5.0) -> Launcher:
        return Launcher(sessionmaker=runner_sessionmaker, writer=writer_override or writer, backend=backend,
                        catalog=CATALOG, config=CONFIG, timer=timer, kill_grace_seconds=kill_grace_seconds)
    return make


@pytest.fixture
def graph():
    with respx.mock(assert_all_called=False) as mock:
        yield mock.route(host="graph.microsoft.com")


async def records(sessionmaker, tid, run_id):
    async with sessionmaker() as session:
        return [r for r in await load_chain(session, chain_id=tid) if r.run_id == run_id]


async def kinds(sessionmaker, tid, run_id):
    return [r.event_type for r in await records(sessionmaker, tid, run_id)]


async def report(sessionmaker, tid):
    async with sessionmaker() as session:
        return await verify_chain(session, chain_id=tid)


START = [EventType.RUN_REQUESTED, EventType.RUN_STARTED]


async def assert_failed(sessionmaker, admin_conn, tid, run_id, reason):
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"], row["run_token_sha256"]) == ("failed", reason, None, None)
    assert row["ended_at"] is not None
    recs = await records(sessionmaker, tid, run_id)
    assert recs[-1].event_type == EventType.RUN_FAILED and recs[-1].reason == reason
    assert (await report(sessionmaker, tid)).valid
    return recs


# ------------------------------------------------------------- a valid result


async def test_valid_result_completes_the_run_with_its_sha256(runner_sessionmaker, writer, admin_conn, tenant,
                                                               launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    backend = FakeBackend(FakeProcess([result_line()[:7], result_line()[7:]]))  # arrives in pieces

    outcome = await launcher_for(backend).run_once()

    assert (outcome.run_id, outcome.status, outcome.reason, outcome.ended) == (run_id, "completed", "succeeded",
                                                                               Ended.RECORDED)
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("completed", "succeeded", None)
    stored = json.loads(row["result"])
    assert stored == RESULT
    recs = await records(runner_sessionmaker, tid, run_id)
    assert [r.event_type for r in recs] == START + [EventType.RUN_COMPLETED]
    completed = recs[-1]
    expected = hashlib.sha256(canonical_json(RESULT)).hexdigest()
    assert completed.details == {"result_sha256": expected} and completed.outcome == "succeeded"
    assert verify_run_result(completed, stored) == "ok"
    assert (await report(runner_sessionmaker, tid)).valid
    assert backend._process.removed


async def test_altering_the_stored_result_is_detected(runner_sessionmaker, writer, admin_conn, tenant,
                                                      launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    await launcher_for(FakeBackend()).run_once()
    # The trigger forbids changing a completed run; an owner can disable it (RR-2).
    await admin_conn.execute("ALTER TABLE runs DISABLE TRIGGER runs_guard_update")
    try:
        await admin_conn.execute("""UPDATE runs SET result = jsonb_set(result, '{counts,dormant}', '0')
                                    WHERE id = $1""", uuid.UUID(run_id))
    finally:
        await admin_conn.execute("ALTER TABLE runs ENABLE TRIGGER runs_guard_update")
    stored = json.loads((await run_row(admin_conn, run_id))["result"])
    completed = (await records(runner_sessionmaker, tid, run_id))[-1]
    assert verify_run_result(completed, stored) == "result_mismatch"


async def test_completed_run_cannot_be_changed(admin_conn, writer, tenant, launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    await launcher_for(FakeBackend()).run_once()
    with pytest.raises(Exception, match="cannot change"):
        await admin_conn.execute("UPDATE runs SET result = '{}'::jsonb WHERE id = $1", uuid.UUID(run_id))


# ------------------------------------------------------------- start and token


async def test_token_is_stored_only_as_its_hash_and_revoked_at_the_end(runner_sessionmaker, writer, admin_conn,
                                                                       tenant, launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    loop = asyncio.get_running_loop()
    seen = {}

    def inspect(process):
        seen["row"] = on_loop(loop, run_row(admin_conn, run_id))

    process = FakeProcess([inspect, result_line()])
    await launcher_for(FakeBackend(process)).run_once()

    token = process.kwargs["environment"]["CLW_RUN_TOKEN"]
    during = seen["row"]
    assert during["status"] == "running" and during["run_token_sha256"] == run_token_sha256(token)
    assert during["deadline_at"] - during["started_at"] == timedelta(seconds=MANIFEST.timeout_seconds)
    after = await run_row(admin_conn, run_id)
    assert after["run_token_sha256"] is None
    for value in after.values():
        assert token not in str(value)
    for record in await records(runner_sessionmaker, tid, run_id):
        assert token not in str(record.stored())


async def test_container_gets_exactly_the_sandbox_spec(admin_conn, writer, tenant, launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    backend = FakeBackend()
    await launcher_for(backend).run_once()
    (kwargs,) = backend.started
    assert set(kwargs["environment"]) == {"CLW_RUN_TOKEN", "CLW_BROKER_URL"}
    assert kwargs["environment"]["CLW_BROKER_URL"] == "http://broker:8080"
    assert kwargs["image"] == "clw-task:phase1" and kwargs["network"] == "clw_tasknet"
    assert kwargs["labels"]["clw.run_id"] == run_id


@pytest.mark.parametrize("params, expected", [({"inactive_days": 45}, "45"), ({}, "90"), ({"inactive_days": 365}, "365")])
async def test_inactive_days_is_passed_to_the_task(admin_conn, writer, tenant, launcher_for, params, expected):
    await queue_run(admin_conn, writer, tenant, params=params)
    backend = FakeBackend()
    await launcher_for(backend).run_once()
    assert backend.started[0]["command"] == ["python", "-m", "tasks.dormant_account_investigation.task",
                                             "--inactive-days", expected]


@pytest.mark.parametrize("params", [
    {"inactive_days": 10}, {"inactive_days": True}, {"inactive_days": "90"}, {"inactive_days": 90, "extra": 1},
    {"broker_url": "http://evil:1"}, {"CLW_RUN_TOKEN": "x"}, {"image": "evil"}, {"inactive_days": 90, "command": "sh"},
])
async def test_params_that_try_to_shape_execution_fail_the_run_before_start(
        runner_sessionmaker, writer, admin_conn, tenant, launcher_for, params):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant, params=params)
    backend = FakeBackend()
    outcome = await launcher_for(backend).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "params_invalid") and backend.started == []
    recs = await assert_failed(runner_sessionmaker, admin_conn, tid, run_id, "params_invalid")
    assert [r.event_type for r in recs] == [EventType.RUN_REQUESTED, EventType.RUN_FAILED]
    assert (await run_row(admin_conn, run_id))["deadline_at"] is None


@pytest.mark.parametrize("row", [{"task_manifest_sha256": "b" * 64}, {"profile_sha256": "c" * 64},
                                 {"profile_version": 99}, {"auth_mode": "delegated"}, {"task_id": "no-such-task"}])
async def test_run_whose_manifest_changed_fails_before_start(runner_sessionmaker, writer, admin_conn, tenant,
                                                             launcher_for, row):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant, row=row)
    backend = FakeBackend()
    outcome = await launcher_for(backend).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "manifest_invalid") and backend.started == []
    await assert_failed(runner_sessionmaker, admin_conn, tid, run_id, "manifest_invalid")


async def test_run_started_audit_failure_starts_nothing(runner_sessionmaker, writer, admin_conn, tenant,
                                                        launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    backend = FakeBackend()
    outcome = await launcher_for(backend, writer_override=FailingWriter(writer, EventType.RUN_STARTED)).run_once()
    assert (outcome.status, outcome.reason) == ("not_started", "audit_unavailable") and backend.started == []
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["run_token_sha256"], row["deadline_at"]) == ("queued", None, None)
    assert await kinds(runner_sessionmaker, tid, run_id) == [EventType.RUN_REQUESTED]
    # Once the audit is back, the same run starts normally.
    assert (await launcher_for(FakeBackend()).run_once()).status == "completed"


async def test_launch_failure_fails_the_run(runner_sessionmaker, writer, admin_conn, tenant, launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    outcome = await launcher_for(FakeBackend(start_fails=True)).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "launch_failed")
    await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, "launch_failed")


async def test_the_task_reaches_the_broker_by_its_looked_up_address(writer, admin_conn, tenant, launcher_for):
    await queue_run(admin_conn, writer, tenant)
    backend = FakeBackend()
    assert (await launcher_for(backend).run_once()).status == "completed"
    # Not through Docker's DNS, which gVisor's network stack cannot reach (SD-044).
    assert backend.peer_lookups == [("clw_tasknet", "broker")]
    assert backend.started[0]["extra_hosts"] == {"broker": "172.30.0.2"}


async def test_without_exactly_one_broker_on_tasknet_nothing_starts(runner_sessionmaker, writer, admin_conn, tenant,
                                                                     launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    backend = FakeBackend(peer=None)
    outcome = await launcher_for(backend).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "peer_unavailable") and backend.started == []
    await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, "peer_unavailable")


async def test_no_queued_run(launcher_for):
    assert await launcher_for(FakeBackend()).run_once() is None


async def test_two_launchers_never_start_the_same_run(admin_conn, writer, tenant, launcher_for):
    await queue_run(admin_conn, writer, tenant)
    first, second = FakeBackend(), FakeBackend()
    outcomes = await asyncio.gather(launcher_for(first).run_once(), launcher_for(second).run_once())
    assert sorted(o is None for o in outcomes) == [False, True]
    assert len(first.started) + len(second.started) == 1


# ------------------------------------------------------------- invalid output


@pytest.mark.parametrize("chunks, reason", [
    ([], "result_missing"),
    ([b"no result here\n"], "result_missing"),
    ([result_line(), result_line()], "result_duplicate"),
    ([b"CLW_RESULT {not json}\n"], "result_malformed"),
    ([b"CLW_RESULT {\"a\":1.5}\n"], "result_malformed"),
    ([b"debug line\n", result_line()], "unexpected_output"),
    ([result_line().rstrip(b"\n")], "unexpected_output"),
])
async def test_invalid_result_fails_the_run(runner_sessionmaker, writer, admin_conn, tenant, launcher_for,
                                            chunks, reason):
    run_id = await queue_run(admin_conn, writer, tenant)
    outcome = await launcher_for(FakeBackend(FakeProcess(chunks))).run_once()
    assert (outcome.status, outcome.reason) == ("failed", reason)
    await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, reason)


async def test_oversized_output_is_cut_off_and_fails_the_run(runner_sessionmaker, writer, admin_conn, tenant,
                                                             launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    block = b"x" * (1024 * 1024)
    process = FakeProcess([block] * 5 + [b"x", result_line()], hang=True)
    outcome = await launcher_for(FakeBackend(process)).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "result_too_large")
    assert process.kill_calls == 1 and 5 * len(block) == MAX_RESULT_BYTES
    await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, "result_too_large")


async def test_result_from_a_failed_task_is_discarded(runner_sessionmaker, writer, admin_conn, tenant, launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    outcome = await launcher_for(FakeBackend(FakeProcess([result_line()], exit_code=1))).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "task_error")
    recs = await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, "task_error")
    assert recs[-1].details == {"exit_code": 1}


async def test_successful_exit_without_a_result_fails(runner_sessionmaker, writer, admin_conn, tenant, launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    outcome = await launcher_for(FakeBackend(FakeProcess([], exit_code=0))).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "result_missing")
    await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, "result_missing")


# ------------------------------------------------------------- timeouts


async def test_timeout_before_any_broker_operation(runner_sessionmaker, writer, admin_conn, tenant, launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    # The task would print a valid result only after being killed: never used.
    process = FakeProcess(hang=True, after_kill=result_line())
    outcome = await launcher_for(FakeBackend(process), timer=at_once).run_once()
    assert (outcome.status, outcome.reason, outcome.ended) == ("timed_out", "timeout", Ended.RECORDED)
    assert process.kill_calls == 1 and process.removed
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"], row["run_token_sha256"]) == ("timed_out", "timeout",
                                                                                      None, None)
    recs = await records(runner_sessionmaker, tid, run_id)
    assert [r.event_type for r in recs] == START + [EventType.RUN_TIMED_OUT]
    assert (recs[-1].reason, recs[-1].details) == ("timeout", {})
    assert (await report(runner_sessionmaker, tid)).valid


async def test_kill_failure_is_recorded_and_the_token_still_revoked(runner_sessionmaker, writer, admin_conn,
                                                                     tenant, launcher_for):
    run_id = await queue_run(admin_conn, writer, tenant)
    process = FakeProcess(hang=True, kill_fails=True)
    try:
        outcome = await launcher_for(FakeBackend(process), timer=at_once, kill_grace_seconds=0.05).run_once()
    finally:
        process.killed.set()  # let the reader thread finish
    assert (outcome.status, outcome.reason) == ("timed_out", "timeout")
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["run_token_sha256"]) == ("timed_out", None)
    assert (await records(runner_sessionmaker, tenant[0], run_id))[-1].details == {"kill": "failed"}


async def test_timeout_while_a_broker_operation_is_in_flight(
        sessionmaker, runner_sessionmaker, writer, admin_conn, tenant, launcher_for, key_path, graph):
    """The documented race (SD-032): the broker sent a request, then the run
    times out. Killing the task does not stop the broker; its late response
    record is refused, its data withheld, and the chain ends at RUN_TIMED_OUT."""
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    in_graph, release, deadline_passes = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def slow_graph(request):
        in_graph.set()
        await release.wait()
        return page()

    graph.mock(side_effect=slow_graph)
    service = make_service(sessionmaker, key_path=key_path)
    process = FakeProcess(hang=True)

    async def timer(deadline):
        await deadline_passes.wait()

    launch = asyncio.create_task(launcher_for(FakeBackend(process), timer=timer).run_once())
    await asyncio.to_thread(process.reading.wait, 30)
    token = process.kwargs["environment"]["CLW_RUN_TOKEN"]
    operation = asyncio.create_task(service.handle_request(auth(token), body()))
    await asyncio.wait_for(in_graph.wait(), 30)  # GRAPH_REQUEST is committed; the request is at Graph

    deadline_passes.set()
    outcome = await launch
    assert (outcome.status, outcome.reason) == ("timed_out", "timeout")
    release.set()
    reply = await operation

    assert (reply.status_code, reply.body) == (503, {"status": "error", "reason": "audit_unavailable"})
    recs = await records(runner_sessionmaker, tid, run_id)
    assert [r.event_type for r in recs][-2:] == [EventType.GRAPH_REQUEST, EventType.RUN_TIMED_OUT]
    final = await report(runner_sessionmaker, tid)
    assert final.valid and final.intents_without_outcome == (recs[-2].seq,)
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("timed_out", "timeout", None)
    # The token is dead for any later operation.
    later = await service.handle_request(auth(token), body())
    assert (later.status_code, later.body["reason"]) == (401, "run_token_invalid")
    assert graph.call_count == 1


# ------------------------------------------------------------- ended elsewhere


async def test_late_result_after_the_run_ended_is_discarded(runner_sessionmaker, writer, admin_conn, tenant,
                                                            launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    loop = asyncio.get_running_loop()
    lifecycle = RunLifecycle(runner_sessionmaker, writer)

    def ended_elsewhere(process):  # e.g. the reconciler, before the task prints its result
        on_loop(loop, lifecycle.end(RunKey(run_id, tid), "timed_out", "outcome_unrecorded"))

    outcome = await launcher_for(FakeBackend(FakeProcess([ended_elsewhere, result_line()]))).run_once()

    assert (outcome.status, outcome.ended) == ("already_ended", Ended.NOT_ENDED)
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"]) == ("timed_out", "outcome_unrecorded", None)
    assert await kinds(runner_sessionmaker, tid, run_id) == START + [EventType.RUN_TIMED_OUT]
    assert (await report(runner_sessionmaker, tid)).valid


async def test_run_failed_by_the_broker_is_not_overwritten(sessionmaker, runner_sessionmaker, writer, admin_conn,
                                                           tenant, launcher_for, key_path, graph):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    loop = asyncio.get_running_loop()
    service = make_service(sessionmaker, key_path=key_path)
    graph.mock(return_value=httpx.Response(403, json={"error": {
        "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "message": "x"}}))
    replies = []

    def call_broker(process):
        token = process.kwargs["environment"]["CLW_RUN_TOKEN"]
        replies.append(on_loop(loop, service.handle_request(auth(token), body())))

    outcome = await launcher_for(FakeBackend(FakeProcess([call_broker], exit_code=1))).run_once()

    assert replies[0].status_code == 502 and outcome.status == "already_ended"
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"]) == ("failed", "licence_required")
    run_kinds = await kinds(runner_sessionmaker, tid, run_id)
    assert run_kinds[-1] == EventType.RUN_FAILED and run_kinds.count(EventType.RUN_FAILED) == 1
    assert (await report(runner_sessionmaker, tid)).valid


async def test_halted_run_ends_failed_audit_unavailable(runner_sessionmaker, writer, admin_conn, tenant,
                                                        launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    loop = asyncio.get_running_loop()

    def broker_halts(process):  # as the broker does after an audit failure (SD-032)
        on_loop(loop, admin_conn.execute("UPDATE runs SET status = 'halted', outcome = 'audit_unavailable' "
                                         "WHERE id = $1", uuid.UUID(run_id)))

    outcome = await launcher_for(FakeBackend(FakeProcess([broker_halts, result_line()]))).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "audit_unavailable")
    await assert_failed(runner_sessionmaker, admin_conn, tid, run_id, "audit_unavailable")


async def _wait_for_lock_waiter(pg_dsn) -> None:
    """Poll (not sleep for a fixed time) until some session waits on a row lock."""
    observer = await asyncpg.connect(pg_dsn)
    try:
        for _ in range(500):
            if await observer.fetchval("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                                       "AND datname = current_database()"):
                return
            await asyncio.sleep(0.01)
        raise AssertionError("no session ever waited on the run row")
    finally:
        await observer.close()


async def test_ending_waits_for_a_concurrent_status_change_and_does_not_overwrite_it(
        runner_sessionmaker, writer, admin_conn, tenant, pg_dsn):
    # The broker fails the run while the runner times it out: the runner waits
    # on the row lock, then sees the run ended and records nothing.
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant)
    lifecycle = RunLifecycle(runner_sessionmaker, writer)
    broker = admin_conn.transaction()
    await broker.start()
    await admin_conn.execute("UPDATE runs SET status = 'failed', outcome = 'licence_required', "
                             "run_token_sha256 = NULL, ended_at = now() WHERE id = $1", uuid.UUID(run_id))
    ending = asyncio.create_task(lifecycle.end(RunKey(run_id, tid), "timed_out", "timeout"))
    try:
        await _wait_for_lock_waiter(pg_dsn)
    finally:
        await broker.commit()
    assert await ending is Ended.NOT_ENDED
    assert EventType.RUN_TIMED_OUT not in await kinds(runner_sessionmaker, tid, run_id)
    assert (await run_row(admin_conn, run_id))["outcome"] == "licence_required"


async def test_a_second_launcher_takes_the_next_run_while_the_first_is_starting(
        runner_sessionmaker, writer, admin_conn, tenant):
    first_run = await queue_run(admin_conn, writer, tenant)
    second_run = await queue_run(admin_conn, writer, tenant)
    holding, released = asyncio.Event(), asyncio.Event()
    waited_out = []

    class SlowStart:  # holds the first claim's row lock inside RUN_STARTED
        async def append(self, *, chain_id, event):
            if event["event_type"] == EventType.RUN_STARTED:
                holding.set()
                try:
                    await asyncio.wait_for(released.wait(), 5)
                except TimeoutError:  # the second launcher was blocked behind this lock
                    waited_out.append(True)
            return await writer.append(chain_id=chain_id, event=event)

    def launcher(backend, w):
        return Launcher(sessionmaker=runner_sessionmaker, writer=w, backend=backend, catalog=CATALOG,
                        config=CONFIG, timer=never)

    first_backend, second_backend = FakeBackend(), FakeBackend()
    first = asyncio.create_task(launcher(first_backend, SlowStart()).run_once())
    await asyncio.wait_for(holding.wait(), 30)
    second = await launcher(second_backend, writer).run_once()  # must not wait for the first lock
    released.set()
    first_outcome = await first
    assert {first_outcome.run_id, second.run_id} == {first_run, second_run}
    assert first_outcome.status == second.status == "completed"
    assert waited_out == []  # the second claim skipped the locked run instead of waiting for it


# ------------------------------------------------------------- recording failures


async def test_completion_record_failure_fails_the_run(runner_sessionmaker, writer, admin_conn, tenant,
                                                       launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    failing = FailingWriter(writer, EventType.RUN_COMPLETED)
    outcome = await launcher_for(FakeBackend(), writer_override=failing).run_once()
    assert (outcome.status, outcome.reason) == ("failed", "audit_unavailable")
    recs = await assert_failed(runner_sessionmaker, admin_conn, tid, run_id, "audit_unavailable")
    assert EventType.RUN_COMPLETED not in [r.event_type for r in recs]


async def test_no_terminal_record_possible_still_ends_the_row(runner_sessionmaker, writer, admin_conn, tenant,
                                                              launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    failing = FailingWriter(writer, EventType.RUN_COMPLETED, EventType.RUN_FAILED)
    outcome = await launcher_for(FakeBackend(), writer_override=failing).run_once()
    assert (outcome.status, outcome.reason, outcome.ended) == ("failed", "audit_unavailable", Ended.ROW_ONLY)
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"], row["run_token_sha256"]) == (
        "failed", "audit_unavailable", None, None)
    assert await kinds(runner_sessionmaker, tid, run_id) == START  # the gap stays visible


async def test_result_persistence_failure_fails_the_run(runner_sessionmaker, writer, admin_conn, tenant,
                                                        launcher_for):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    await admin_conn.execute(f"""
        CREATE FUNCTION public.test_refuse_completion() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.status = 'completed' AND NEW.id = '{run_id}' THEN
                RAISE EXCEPTION 'storage refused';
            END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER zz_test_refuse_completion BEFORE UPDATE ON runs
            FOR EACH ROW EXECUTE FUNCTION public.test_refuse_completion();""")
    try:
        outcome = await launcher_for(FakeBackend()).run_once()
    finally:
        await admin_conn.execute("DROP TRIGGER zz_test_refuse_completion ON runs; "
                                 "DROP FUNCTION public.test_refuse_completion()")
    assert (outcome.status, outcome.reason) == ("failed", "result_unpersisted")
    recs = await assert_failed(runner_sessionmaker, admin_conn, tid, run_id, "result_unpersisted")
    assert EventType.RUN_COMPLETED not in [r.event_type for r in recs]


async def test_completion_refused_while_a_request_is_unanswered(
        sessionmaker, runner_sessionmaker, writer, admin_conn, tenant, launcher_for, key_path, graph):
    """A task that exits 0 while its broker operation is still in flight
    (for example from a thread) cannot complete the run."""
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    loop = asyncio.get_running_loop()
    in_graph, release = asyncio.Event(), asyncio.Event()

    async def slow_graph(request):
        in_graph.set()
        await release.wait()
        return page()

    graph.mock(side_effect=slow_graph)
    service = make_service(sessionmaker, key_path=key_path)
    operations = []

    def start_operation_and_exit(process):
        token = process.kwargs["environment"]["CLW_RUN_TOKEN"]
        operations.append(asyncio.run_coroutine_threadsafe(service.handle_request(auth(token), body()), loop))
        on_loop(loop, asyncio.wait_for(in_graph.wait(), 30))

    outcome = await launcher_for(FakeBackend(FakeProcess([start_operation_and_exit, result_line()]))).run_once()
    release.set()
    reply = await asyncio.wrap_future(operations[0])

    assert (outcome.status, outcome.reason) == ("failed", "outstanding_requests")
    assert reply.status_code == 503  # its response record came after the end: data withheld
    recs = await assert_failed(runner_sessionmaker, admin_conn, tid, run_id, "outstanding_requests")
    assert EventType.RUN_COMPLETED not in [r.event_type for r in recs]
    assert len((await report(runner_sessionmaker, tid)).intents_without_outcome) == 1


# ------------------------------------------------------------- reconciler


def mine(done, *run_ids):
    # The reconciler sweeps every tenant; earlier tests' runs share the database.
    return [d for d in done if d.run_id in run_ids]


@pytest.fixture
def reconciler(runner_sessionmaker, writer):
    def make(**kwargs) -> Reconciler:
        return Reconciler(sessionmaker=runner_sessionmaker, writer=kwargs.pop("writer", writer),
                          grace=kwargs.pop("grace", timedelta(0)), **kwargs)
    return make


async def test_reconciler_times_out_runs_past_their_deadline(runner_sessionmaker, writer, admin_conn, tenant,
                                                             reconciler):
    tid = tenant[0]
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    overdue, _ = await start_run(admin_conn, writer, tenant, deadline=past)
    current, _ = await start_run(admin_conn, writer, tenant)
    backend = FakeBackend()

    done = mine(await reconciler(backend=backend).sweep(), overdue, current)

    assert [(d.run_id, d.status, d.reason, d.ended) for d in done] == [
        (overdue, "timed_out", "outcome_unrecorded", Ended.RECORDED)]
    row = await run_row(admin_conn, overdue)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("timed_out", "outcome_unrecorded", None)
    recs = await records(runner_sessionmaker, tid, overdue)
    assert (recs[-1].event_type, recs[-1].reason) == (EventType.RUN_TIMED_OUT, "outcome_unrecorded")
    assert (await run_row(admin_conn, current))["status"] == "running"
    assert overdue in backend.killed_runs and current not in backend.killed_runs
    assert mine(await reconciler().sweep(), overdue, current) == []  # nothing twice


async def test_reconciler_fails_halted_runs_past_their_deadline(runner_sessionmaker, writer, admin_conn, tenant,
                                                                reconciler):
    run_id, _ = await start_run(admin_conn, writer, tenant, deadline=datetime.now(timezone.utc) - timedelta(minutes=5))
    await admin_conn.execute("UPDATE runs SET status = 'halted' WHERE id = $1", uuid.UUID(run_id))
    done = mine(await reconciler().sweep(), run_id)
    assert [(d.status, d.reason) for d in done] == [("failed", "audit_unavailable")]
    await assert_failed(runner_sessionmaker, admin_conn, tenant[0], run_id, "audit_unavailable")


async def test_reconciler_leaves_the_grace_period_to_the_launcher(admin_conn, writer, tenant, reconciler):
    run_id, _ = await start_run(admin_conn, writer, tenant, deadline=datetime.now(timezone.utc) - timedelta(seconds=5))
    assert mine(await reconciler(grace=timedelta(minutes=1)).sweep(), run_id) == []
    assert (await run_row(admin_conn, run_id))["status"] == "running"


async def test_reconciler_revokes_the_token_when_the_audit_is_down(runner_sessionmaker, writer, admin_conn, tenant,
                                                                   reconciler):
    run_id, token = await start_run(admin_conn, writer, tenant,
                                    deadline=datetime.now(timezone.utc) - timedelta(minutes=5))
    done = mine(await reconciler(writer=FailingWriter(writer, EventType.RUN_TIMED_OUT)).sweep(), run_id)
    assert [d.ended for d in done] == [Ended.ROW_ONLY]
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["run_token_sha256"]) == ("timed_out", None)


async def test_reconciler_matches_the_row_to_a_terminal_record_already_written(
        runner_sessionmaker, writer, admin_conn, tenant, reconciler):
    # The launcher's record committed but its row update was lost: the
    # reconciler ends the row and records nothing more.
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant, deadline=datetime.now(timezone.utc) - timedelta(minutes=5))
    await writer.append(chain_id=tid, event={"tenant_id": tid, "event_type": EventType.RUN_TIMED_OUT,
                                             "status": "timed_out", "run_id": run_id, "reason": "timeout"})
    done = mine(await reconciler().sweep(), run_id)
    assert [d.ended for d in done] == [Ended.ROW_ONLY]
    assert (await kinds(runner_sessionmaker, tid, run_id)).count(EventType.RUN_TIMED_OUT) == 1
    assert (await run_row(admin_conn, run_id))["status"] == "timed_out"
    assert (await report(runner_sessionmaker, tid)).valid
