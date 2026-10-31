"""Where the run row and the audit chain can disagree (Task 14 review; SD-034).

The row and each audit record are separate transactions. These tests make
the row's commit fail after the record has committed, with a test-only
DEFERRABLE INITIALLY DEFERRED constraint trigger: it raises at COMMIT, so the
failure lands exactly between the two commits. The trigger names one run
and one status, and is dropped before the test ends.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import respx

from clw.audit.chain import verify_run_result
from clw.audit.events import AuditUnavailable, EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.runner.launcher import Launcher
from clw.runner.lifecycle import Ended, RunKey, RunLifecycle
from clw.runner.reconciler import Reconciler
from clw.runner.sandbox_spec import SandboxConfig
from tests.db.broker_fixtures import CATALOG, add_tenant, auth, body, make_service, run_row, start_run, write_key
from tests.db.runner_fixtures import FakeBackend, end_stray_queued_runs, queue_run

pytestmark = pytest.mark.pg

CONFIG = SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080")


def never(deadline):
    import asyncio

    return asyncio.Event().wait()


@contextlib.asynccontextmanager
async def row_commit_fails(admin_conn, run_id: str, status: str):
    """Any transaction that leaves this run's row with `status` fails at COMMIT."""
    uuid.UUID(run_id)  # only a UUID is ever put into the trigger body
    assert status in ("running", "completed", "failed", "timed_out")
    await admin_conn.execute(f"""
        CREATE FUNCTION public.test_row_commit_fails() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.id = '{run_id}' AND NEW.status = '{status}' THEN
                RAISE EXCEPTION 'commit lost (test)';
            END IF;
            RETURN NULL;
        END $$;
        CREATE CONSTRAINT TRIGGER zz_test_row_commit_fails AFTER UPDATE ON runs
            DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.test_row_commit_fails();""")
    try:
        yield
    finally:
        await admin_conn.execute("DROP TRIGGER zz_test_row_commit_fails ON runs; "
                                 "DROP FUNCTION public.test_row_commit_fails()")


@pytest.fixture(autouse=True)
async def _no_stray_queued_runs(admin_conn):
    await end_stray_queued_runs(admin_conn)


@pytest.fixture
async def tenant(admin_conn):
    return await add_tenant(admin_conn)


@pytest.fixture
def writer(runner_sessionmaker):
    return AuditWriter(runner_sessionmaker)


@pytest.fixture(scope="module")
def key_path(tmp_path_factory):
    return write_key(tmp_path_factory.mktemp("profile-key"))


def launcher(runner_sessionmaker, writer, backend) -> Launcher:
    return Launcher(sessionmaker=runner_sessionmaker, writer=writer, backend=backend, catalog=CATALOG,
                    config=CONFIG, timer=never)


async def run_records(sessionmaker, tid, run_id):
    async with sessionmaker() as session:
        return [r for r in await load_chain(session, chain_id=tid) if r.run_id == run_id]


async def chain_report(sessionmaker, tid):
    async with sessionmaker() as session:
        return await verify_chain(session, chain_id=tid)


# ------------------------------------------------------------- RUN_STARTED committed, row not


async def test_start_recorded_but_row_commit_lost_is_failed_not_restarted(runner_sessionmaker, writer, admin_conn,
                                                                          tenant):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    backend = FakeBackend()

    async with row_commit_fails(admin_conn, run_id, "running"):
        with pytest.raises(Exception, match="commit lost"):
            await launcher(runner_sessionmaker, writer, backend).run_once()

    # The window: the chain says started, the row says queued, nothing ran.
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["run_token_sha256"], row["deadline_at"]) == ("queued", None, None)
    assert [r.event_type for r in await run_records(runner_sessionmaker, tid, run_id)] == [
        EventType.RUN_REQUESTED, EventType.RUN_STARTED]
    assert backend.started == []

    # Recovery: the next attempt does not start it again.
    outcome = await launcher(runner_sessionmaker, writer, backend).run_once()

    assert (outcome.run_id, outcome.status, outcome.reason, outcome.ended) == (
        run_id, "failed", "start_unrecorded", Ended.RECORDED)
    assert backend.started == []
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("failed", "start_unrecorded", None)
    recs = await run_records(runner_sessionmaker, tid, run_id)
    assert [r.event_type for r in recs] == [EventType.RUN_REQUESTED, EventType.RUN_STARTED, EventType.RUN_FAILED]
    assert recs[-1].reason == "start_unrecorded"
    report = await chain_report(runner_sessionmaker, tid)
    assert report.valid and report.errors == ()  # no run_already_started finding


async def test_start_recorded_but_its_acknowledgement_lost_is_failed_not_restarted(runner_sessionmaker, writer,
                                                                                   admin_conn, tenant):
    # RR-4: the record committed, but the writer reported a failure.
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)

    class AckLost:
        async def append(self, *, chain_id, event):
            record = await writer.append(chain_id=chain_id, event=event)
            if event["event_type"] == EventType.RUN_STARTED:
                raise AuditUnavailable("connection dropped after COMMIT")
            return record

    backend = FakeBackend()
    first = await launcher(runner_sessionmaker, AckLost(), backend).run_once()
    assert (first.status, first.reason) == ("not_started", "audit_unavailable")
    assert (await run_row(admin_conn, run_id))["status"] == "queued" and backend.started == []

    second = await launcher(runner_sessionmaker, writer, backend).run_once()
    assert (second.status, second.reason) == ("failed", "start_unrecorded") and backend.started == []
    kinds = [r.event_type for r in await run_records(runner_sessionmaker, tid, run_id)]
    assert kinds.count(EventType.RUN_STARTED) == 1 and kinds[-1] == EventType.RUN_FAILED
    assert (await chain_report(runner_sessionmaker, tid)).valid


async def test_a_run_ended_in_the_chain_but_still_queued_is_ended_without_another_record(
        runner_sessionmaker, writer, admin_conn, tenant):
    # A queued run whose RUN_FAILED committed but whose row commit was lost.
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)
    await writer.append(chain_id=tid, event={"tenant_id": tid, "event_type": EventType.RUN_FAILED,
                                             "status": "failed", "run_id": run_id, "reason": "params_invalid"})
    backend = FakeBackend()
    outcome = await launcher(runner_sessionmaker, writer, backend).run_once()
    assert (outcome.status, outcome.reason, outcome.ended) == ("failed", "start_unrecorded", Ended.ROW_ONLY)
    assert backend.started == []
    kinds = [r.event_type for r in await run_records(runner_sessionmaker, tid, run_id)]
    assert kinds == [EventType.RUN_REQUESTED, EventType.RUN_FAILED]
    assert (await run_row(admin_conn, run_id))["status"] == "failed"
    assert (await chain_report(runner_sessionmaker, tid)).valid


# ------------------------------------------------------------- terminal record committed, row not


async def test_terminal_record_committed_before_a_failed_row_commit(sessionmaker, runner_sessionmaker, writer,
                                                                    admin_conn, tenant, key_path):
    tid = tenant[0]
    run_id, token = await start_run(admin_conn, writer, tenant)
    lifecycle = RunLifecycle(runner_sessionmaker, writer)

    async with row_commit_fails(admin_conn, run_id, "timed_out"):
        with pytest.raises(Exception, match="commit lost"):
            await lifecycle.end(RunKey(run_id, tid), "timed_out", "timeout")

    row = await run_row(admin_conn, run_id)
    assert row["status"] == "running" and row["run_token_sha256"] is not None  # the token still resolves
    recs = await run_records(runner_sessionmaker, tid, run_id)
    assert recs[-1].event_type == EventType.RUN_TIMED_OUT

    # Fail closed meanwhile: an operation with the still-resolving token
    # records nothing (refused after the end), reaches no Graph and gets no data.
    with respx.mock(assert_all_called=False) as mock:
        graph = mock.route(host="graph.microsoft.com")
        reply = await make_service(sessionmaker, key_path=key_path).handle_request(auth(token), body())
    assert reply.status_code == 503 and "data" not in reply.body and graph.call_count == 0
    assert (await run_records(runner_sessionmaker, tid, run_id))[-1].seq == recs[-1].seq
    report = await chain_report(runner_sessionmaker, tid)
    assert report.valid


async def test_reconciler_ends_a_row_whose_terminal_record_already_committed(runner_sessionmaker, writer, admin_conn,
                                                                             tenant):
    tid = tenant[0]
    run_id, _ = await start_run(admin_conn, writer, tenant,
                                deadline=datetime.now(timezone.utc) - timedelta(minutes=5))
    lifecycle = RunLifecycle(runner_sessionmaker, writer)
    async with row_commit_fails(admin_conn, run_id, "timed_out"):
        with pytest.raises(Exception, match="commit lost"):
            await lifecycle.end(RunKey(run_id, tid), "timed_out", "timeout")

    done = [d for d in await Reconciler(sessionmaker=runner_sessionmaker, writer=writer, grace=timedelta(0)).sweep()
            if d.run_id == run_id]

    assert [(d.status, d.ended) for d in done] == [("timed_out", Ended.ROW_ONLY)]
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["run_token_sha256"]) == ("timed_out", None)
    kinds = [r.event_type for r in await run_records(runner_sessionmaker, tid, run_id)]
    assert kinds.count(EventType.RUN_TIMED_OUT) == 1
    assert (await chain_report(runner_sessionmaker, tid)).valid


async def test_completion_recorded_but_result_not_stored_stays_visible(runner_sessionmaker, writer, admin_conn,
                                                                       tenant):
    tid = tenant[0]
    run_id = await queue_run(admin_conn, writer, tenant)

    async with row_commit_fails(admin_conn, run_id, "completed"):
        outcome = await launcher(runner_sessionmaker, writer, FakeBackend()).run_once()

    # The completion committed; the row could not store the result. The run
    # is failed on the row alone (a RUN_FAILED after RUN_COMPLETED is refused),
    # and the mismatch is what verify_run_result reports.
    assert (outcome.status, outcome.reason, outcome.ended) == ("failed", "result_unpersisted", Ended.ROW_ONLY)
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["result"], row["run_token_sha256"]) == (
        "failed", "result_unpersisted", None, None)
    recs = await run_records(runner_sessionmaker, tid, run_id)
    assert recs[-1].event_type == EventType.RUN_COMPLETED
    assert verify_run_result(recs[-1], row["result"]) == "result_mismatch"
    assert (await chain_report(runner_sessionmaker, tid)).valid
