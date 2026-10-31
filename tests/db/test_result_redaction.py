"""Audited result redaction (SD-037; migration 20261025_result_redaction):
the runs trigger, the procedure, the CLI, and the API view."""

from __future__ import annotations

import asyncio
import json
import uuid

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.api.routes.runs import serialize_run
from clw.audit.chain import result_sha256, verify_run_result
from clw.audit.events import AuditUnavailable, EventType
from clw.audit.redaction import RedactionRefused, redact_result
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.cli import FAILED, OK, main
from clw.db.models.run import Run
from clw.runner.lifecycle import RunKey, RunLifecycle
from tests.db.broker_fixtures import add_tenant, start_run

pytestmark = pytest.mark.pg

RESULT = {"dormant": [{"id": "u1", "userPrincipalName": "person@contoso.test"}], "counts": {"dormant": 1}}
REASON = "personal data in a test tenant"


@pytest.fixture
async def operator_maker(pg_dsn):
    """The deployment's owner role, which the operator procedure uses (never an application role)."""
    engine = create_async_engine(pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def completed(admin_conn, operator_maker):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(operator_maker)
    run_id, _ = await start_run(admin_conn, writer, tenant)
    await RunLifecycle(operator_maker, writer).complete(RunKey(run_id, tenant[0]), RESULT, result_sha256(RESULT))
    return run_id, tenant[0]


async def _row(admin_conn, run_id):
    return await admin_conn.fetchrow("SELECT status, outcome, result, result_redacted_at FROM runs WHERE id = $1",
                                     uuid.UUID(run_id))


async def _redactions(maker, tid):
    async with maker() as session:
        return [r for r in await load_chain(session, chain_id=tid) if r.event_type == EventType.RESULT_REDACTED]


# ----------------------------------------------------------------- procedure


async def test_redaction_removes_the_result_and_keeps_the_chain_valid(admin_conn, operator_maker, completed):
    run_id, tid = completed
    done = await redact_result(operator_maker, AuditWriter(operator_maker), chain_id=tid, run_id=run_id,
                               operator="operator-1", reason=REASON)
    assert done.result_sha256 == result_sha256(RESULT) and not done.resumed
    row = await _row(admin_conn, run_id)
    assert row["result"] is None and row["result_redacted_at"] is not None
    assert (row["status"], row["outcome"]) == ("completed", "succeeded")

    async with operator_maker() as session:
        report = await verify_chain(session, chain_id=tid)
        records = await load_chain(session, chain_id=tid)
    assert report.valid and report.intents_without_outcome == ()
    completion = next(r for r in records if r.event_type == EventType.RUN_COMPLETED)
    (redaction,) = [r for r in records if r.event_type == EventType.RESULT_REDACTED]
    assert redaction.seq == done.redaction_seq and redaction.run_id is None
    assert redaction.details == {"redacted_run_id": run_id, "result_sha256": result_sha256(RESULT)}
    assert (redaction.actor_oid, redaction.reason) == ("operator-1", REASON)
    assert verify_run_result(completion, None, redaction=redaction) == "redacted"


async def test_the_api_view_shows_the_result_as_redacted(operator_maker, completed):
    run_id, tid = completed
    await redact_result(operator_maker, AuditWriter(operator_maker), chain_id=tid, run_id=run_id,
                        operator="operator-1", reason=REASON)
    async with operator_maker() as session:
        run = await session.get(Run, uuid.UUID(run_id))
    view = serialize_run(run)
    assert view["result"] is None and view["result_redacted"] is True


async def test_a_second_redaction_is_refused(operator_maker, completed):
    run_id, tid = completed
    writer = AuditWriter(operator_maker)
    await redact_result(operator_maker, writer, chain_id=tid, run_id=run_id, operator="op", reason=REASON)
    with pytest.raises(RedactionRefused, match="already redacted"):
        await redact_result(operator_maker, writer, chain_id=tid, run_id=run_id, operator="op", reason=REASON)
    assert len(await _redactions(operator_maker, tid)) == 1


async def test_a_run_of_another_tenant_cannot_be_redacted_through_this_chain(admin_conn, operator_maker, completed):
    run_id, _ = completed
    other = (await add_tenant(admin_conn))[0]
    with pytest.raises(RedactionRefused, match="no such run"):
        await redact_result(operator_maker, AuditWriter(operator_maker), chain_id=other, run_id=run_id,
                            operator="op", reason=REASON)
    assert (await _row(admin_conn, run_id))["result"] is not None


async def test_a_run_that_did_not_complete_cannot_be_redacted(admin_conn, operator_maker):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(operator_maker)
    run_id, _ = await start_run(admin_conn, writer, tenant)
    await RunLifecycle(operator_maker, writer).end(RunKey(run_id, tenant[0]), "failed", "task_error")
    with pytest.raises(RedactionRefused, match="not completed"):
        await redact_result(operator_maker, writer, chain_id=tenant[0], run_id=run_id, operator="op", reason=REASON)


async def test_a_tampered_result_is_not_redacted(admin_conn, operator_maker, completed):
    # Evidence of tampering must survive: the procedure refuses and records nothing.
    run_id, tid = completed
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        await admin_conn.execute("UPDATE runs SET result = $2::jsonb WHERE id = $1", uuid.UUID(run_id),
                                 json.dumps({"forged": True}))
    finally:
        await admin_conn.execute("SET session_replication_role = origin")
    with pytest.raises(RedactionRefused, match="does not match"):
        await redact_result(operator_maker, AuditWriter(operator_maker), chain_id=tid, run_id=run_id,
                            operator="op", reason=REASON)
    assert await _redactions(operator_maker, tid) == []
    assert (await _row(admin_conn, run_id))["result"] is not None


async def test_nothing_is_removed_when_the_record_cannot_be_written(admin_conn, operator_maker, completed):
    run_id, tid = completed

    class DownWriter:
        async def append(self, **_):
            raise AuditUnavailable("audit store down")

    with pytest.raises(AuditUnavailable):
        await redact_result(operator_maker, DownWriter(), chain_id=tid, run_id=run_id, operator="op", reason=REASON)
    row = await _row(admin_conn, run_id)
    assert row["result"] is not None and row["result_redacted_at"] is None


async def test_a_recorded_redaction_whose_row_change_was_lost_is_resumed(admin_conn, operator_maker, completed):
    run_id, tid = completed
    writer = AuditWriter(operator_maker)
    await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.RESULT_REDACTED, "status": "recorded", "reason": REASON,
        "actor_oid": "op", "details": {"redacted_run_id": run_id, "result_sha256": result_sha256(RESULT)}})
    done = await redact_result(operator_maker, writer, chain_id=tid, run_id=run_id, operator="op", reason=REASON)
    assert done.resumed
    assert len(await _redactions(operator_maker, tid)) == 1
    assert (await _row(admin_conn, run_id))["result"] is None


@pytest.mark.parametrize("field, value", [("operator", ""), ("operator", "x" * 257), ("reason", ""),
                                          ("reason", "line\nbreak"), ("run_id", "not-a-uuid")])
async def test_bad_arguments_are_refused_before_anything_happens(operator_maker, completed, field, value):
    run_id, tid = completed
    args = {"operator": "op", "reason": REASON, "run_id": run_id} | {field: value}
    with pytest.raises(RedactionRefused):
        await redact_result(operator_maker, AuditWriter(operator_maker), chain_id=tid, **args)
    assert await _redactions(operator_maker, tid) == []


# -------------------------------------------------------------------- trigger


@pytest.mark.parametrize("change", [
    "result = NULL",  # without result_redacted_at
    "result_redacted_at = now()",  # without clearing the result
    "result = NULL, result_redacted_at = now(), outcome = 'rewritten'",
    "result = NULL, result_redacted_at = now(), status = 'failed'",
    "result = NULL, result_redacted_at = now(), ended_at = now() + interval '1 day'",
    "result = '{}'::jsonb, result_redacted_at = now()",
    "result = 'null'::jsonb, result_redacted_at = now()",  # JSON null is not a removed result
])
async def test_an_ended_run_takes_only_the_exact_redaction_change(admin_conn, completed, change):
    run_id, _ = completed
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute(f"UPDATE runs SET {change} WHERE id = $1", uuid.UUID(run_id))


async def test_the_exact_redaction_change_is_accepted_once(admin_conn, completed):
    run_id, _ = completed
    await admin_conn.execute("UPDATE runs SET result = NULL, result_redacted_at = now() WHERE id = $1",
                             uuid.UUID(run_id))
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute("UPDATE runs SET result_redacted_at = now() + interval '1 second' WHERE id = $1",
                                 uuid.UUID(run_id))


@pytest.mark.parametrize("terminal", ["failed", "timed_out"])
async def test_only_completed_runs_can_take_a_redaction(admin_conn, operator_maker, terminal):
    tenant = await add_tenant(admin_conn)
    run_id, _ = await start_run(admin_conn, AuditWriter(operator_maker), tenant)
    await admin_conn.execute("UPDATE runs SET status = $2, run_token_sha256 = NULL WHERE id = $1",
                             uuid.UUID(run_id), terminal)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute("UPDATE runs SET result = NULL, result_redacted_at = now() WHERE id = $1",
                                 uuid.UUID(run_id))


async def test_a_running_run_cannot_be_marked_redacted(admin_conn, operator_maker):
    tenant = await add_tenant(admin_conn)
    run_id, _ = await start_run(admin_conn, AuditWriter(operator_maker), tenant)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute("UPDATE runs SET result_redacted_at = now() WHERE id = $1", uuid.UUID(run_id))


async def test_the_application_roles_cannot_redact(app_conn, completed):
    run_id, _ = completed
    with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
        await app_conn.execute("UPDATE runs SET result = NULL, result_redacted_at = now() WHERE id = $1",
                               uuid.UUID(run_id))


# ------------------------------------------------------------------------ CLI


@pytest.fixture
def cli_env(monkeypatch, pg_dsn):
    from clw.common import config
    from clw.db import session

    monkeypatch.setenv("DATABASE_URL", pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()
    yield
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()


async def test_the_cli_redacts_and_reports(admin_conn, cli_env, completed, capsys):
    run_id, tid = completed
    argv = ["audit-redact-result", "--chain", tid, "--run", run_id, "--operator", "op", "--reason", REASON]
    assert await asyncio.to_thread(main, argv) == OK
    out = json.loads(capsys.readouterr().out)
    assert out["run_id"] == run_id and out["result_sha256"] == result_sha256(RESULT) and out["resumed"] is False
    assert (await _row(admin_conn, run_id))["result"] is None
    assert await asyncio.to_thread(main, argv) == FAILED  # a second time: refused, nothing written
    assert "already redacted" in capsys.readouterr().err


async def test_a_failed_run_holding_a_result_is_still_refused_as_not_completed(admin_conn, operator_maker):
    # A failed run never stores a result; one planted there is still not redactable.
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(operator_maker)
    run_id, _ = await start_run(admin_conn, writer, tenant)
    await RunLifecycle(operator_maker, writer).end(RunKey(run_id, tenant[0]), "failed", "task_error")
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        await admin_conn.execute("UPDATE runs SET result = $2::jsonb WHERE id = $1", uuid.UUID(run_id),
                                 json.dumps(RESULT))
    finally:
        await admin_conn.execute("SET session_replication_role = origin")
    with pytest.raises(RedactionRefused, match="not completed"):
        await redact_result(operator_maker, writer, chain_id=tenant[0], run_id=run_id, operator="op", reason=REASON)


async def test_a_run_cannot_be_inserted_already_marked_redacted(admin_conn):
    tid, user_id, oid = await add_tenant(admin_conn)
    from tests.db.broker_fixtures import MANIFEST

    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute(
            """INSERT INTO runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,
                                 profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status,
                                 result_redacted_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, 'app_only', $8, $9, $2, '{}'::jsonb, 'queued', now())""",
            uuid.uuid4(), tid, MANIFEST.id, MANIFEST.sha256, MANIFEST.profile.id, MANIFEST.profile.version,
            MANIFEST.profile.sha256, user_id, oid)
