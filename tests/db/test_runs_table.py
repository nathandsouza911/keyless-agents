"""runs table constraints and the runs_guard_update trigger (migration
20261021_runs, SD-032). Run as admin, so only the schema stands in the way."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from clw.audit.writer import AuditWriter
from tests.db.broker_fixtures import MANIFEST, add_tenant, start_run

pytestmark = pytest.mark.pg

REFUSED = (asyncpg.exceptions.CheckViolationError, asyncpg.exceptions.ForeignKeyViolationError,
           asyncpg.exceptions.UniqueViolationError, asyncpg.exceptions.NotNullViolationError)


@pytest.fixture
async def run(admin_conn, sessionmaker):
    tenant = await add_tenant(admin_conn)
    run_id, _ = await start_run(admin_conn, AuditWriter(sessionmaker), tenant)
    return uuid.UUID(run_id), tenant


async def _status(admin_conn, run_id):
    return await admin_conn.fetchval("SELECT status FROM runs WHERE id = $1", run_id)


async def _set(admin_conn, run_id, sql: str, *args):
    await admin_conn.execute(f"UPDATE runs SET {sql} WHERE id = $1", run_id, *args)


@pytest.mark.parametrize("assignment, value", [
    ("tenant_id = $2", None), ("task_id = $2", "other-task"), ("task_manifest_sha256 = $2", "1" * 64),
    ("profile_id = $2", "other-profile"), ("profile_version = $2", 2), ("profile_sha256 = $2", "2" * 64),
    ("auth_mode = $2", "delegated"), ("actor_oid = $2", None), ("actor_tid = $2", None),
    ("params = $2::jsonb", '{"inactive_days": 30}'), ("created_at = $2", datetime(2020, 1, 1, tzinfo=timezone.utc)),
    ("actor_user_id = $2", None),
])
async def test_run_identity_cannot_change(admin_conn, run, assignment, value):
    run_id, tenant = run
    if value is None:
        other = await add_tenant(admin_conn)
        value = {"tenant_id": other[0], "actor_oid": other[2], "actor_tid": other[0],
                 "actor_user_id": other[1]}[assignment.split(" ")[0]]
    with pytest.raises(REFUSED):
        await _set(admin_conn, run_id, assignment, value)


@pytest.mark.parametrize("path, allowed", [
    (("halted",), True), (("completed",), True), (("failed",), True), (("timed_out",), True),
    (("halted", "failed"), True), (("halted", "timed_out"), True),
    (("queued",), False), (("halted", "running"), False), (("halted", "completed"), False),
])
async def test_status_transitions_from_running(admin_conn, run, path, allowed):
    run_id, _ = run
    *prefix, last = path
    for status in prefix:
        await _set(admin_conn, run_id, "status = $2", status)
    clear = ", run_token_sha256 = NULL" if last in ("completed", "failed", "timed_out") else ""
    if allowed:
        await _set(admin_conn, run_id, f"status = $2{clear}", last)
        assert await _status(admin_conn, run_id) == last
    else:
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await _set(admin_conn, run_id, f"status = $2{clear}", last)


@pytest.mark.parametrize("terminal", ["completed", "failed", "timed_out"])
@pytest.mark.parametrize("change", ["status = 'running', run_token_sha256 = repeat('a', 64)", "outcome = 'rewritten'",
                                    "result = '{}'::jsonb", "status = 'completed'"])
async def test_terminal_runs_are_final(admin_conn, run, terminal, change):
    run_id, _ = run
    await _set(admin_conn, run_id, "status = $2, run_token_sha256 = NULL", terminal)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute(f"UPDATE runs SET {change} WHERE id = $1", run_id)


async def test_deadline_of_a_started_run_cannot_change(admin_conn, run):
    run_id, _ = run
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await _set(admin_conn, run_id, "deadline_at = deadline_at + interval '1 hour'")


async def test_token_of_a_started_run_can_only_be_revoked(admin_conn, run):
    run_id, _ = run
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await _set(admin_conn, run_id, "run_token_sha256 = $2", "b" * 64)
    await _set(admin_conn, run_id, "status = 'failed', run_token_sha256 = NULL")
    assert await _status(admin_conn, run_id) == "failed"


@pytest.mark.parametrize("change", ["run_token_sha256 = NULL", "deadline_at = NULL"])
async def test_a_running_run_has_a_token_and_a_deadline(admin_conn, run, change):
    run_id, _ = run
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await _set(admin_conn, run_id, change)


@pytest.mark.parametrize("terminal", ["completed", "failed", "timed_out"])
async def test_an_ended_run_has_no_token(admin_conn, run, terminal):
    run_id, _ = run
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await _set(admin_conn, run_id, "status = $2", terminal)


async def _insert(admin_conn, tenant, **changes):
    tid, user_id, oid = tenant
    values = {"id": uuid.uuid4(), "tenant_id": tid, "task_id": MANIFEST.id,
              "task_manifest_sha256": MANIFEST.sha256, "profile_id": MANIFEST.profile.id, "profile_version": 1,
              "profile_sha256": MANIFEST.profile.sha256, "auth_mode": "app_only", "actor_user_id": user_id,
              "actor_oid": oid, "actor_tid": tid, "params": "{}", "status": "queued", "run_token_sha256": None,
              "deadline_at": None} | changes
    columns = ", ".join(values)
    placeholders = ", ".join(f"${i}" + ("::jsonb" if k == "params" else "") for i, k in enumerate(values, 1))
    await admin_conn.execute(f"INSERT INTO runs ({columns}) VALUES ({placeholders})", *values.values())


async def test_a_valid_queued_run_inserts(admin_conn):
    await _insert(admin_conn, await add_tenant(admin_conn))


@pytest.mark.parametrize("changes", [
    {"status": "pending"}, {"auth_mode": "both"}, {"task_manifest_sha256": "A" * 64},
    {"task_manifest_sha256": "a" * 63}, {"profile_sha256": "x" * 64}, {"run_token_sha256": "a" * 65},
    {"profile_version": 0}, {"params": "[]"}, {"status": "running"},
    {"status": "running", "run_token_sha256": "c" * 64},
    {"tenant_id": "not-a-registered-tenant"},
])
async def test_malformed_runs_are_refused(admin_conn, changes):
    with pytest.raises(REFUSED + (asyncpg.exceptions.StringDataRightTruncationError,)):
        await _insert(admin_conn, await add_tenant(admin_conn), **changes)


async def test_the_actor_must_belong_to_the_runs_tenant(admin_conn):
    a, b = await add_tenant(admin_conn), await add_tenant(admin_conn)
    with pytest.raises(REFUSED):  # actor_tid differs from the tenant
        await _insert(admin_conn, a, actor_tid=b[0])
    with pytest.raises(REFUSED):  # a member of another tenant
        await _insert(admin_conn, a, actor_oid=b[2], actor_user_id=b[1])


async def test_run_tokens_are_unique(admin_conn):
    tenant = await add_tenant(admin_conn)
    deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
    await _insert(admin_conn, tenant, status="running", run_token_sha256="d" * 64, deadline_at=deadline)
    with pytest.raises(asyncpg.exceptions.UniqueViolationError):
        await _insert(admin_conn, tenant, status="running", run_token_sha256="d" * 64, deadline_at=deadline)


async def test_queued_run_may_start_or_fail(admin_conn):
    tenant = await add_tenant(admin_conn)
    started, failed = uuid.uuid4(), uuid.uuid4()
    await _insert(admin_conn, tenant, id=started)
    await _insert(admin_conn, tenant, id=failed)
    await _set(admin_conn, started, "status = 'running', run_token_sha256 = $2, deadline_at = now()", "e" * 64)
    await _set(admin_conn, failed, "status = 'failed'")
    assert (await _status(admin_conn, started), await _status(admin_conn, failed)) == ("running", "failed")


@pytest.mark.parametrize("target", ["halted", "completed", "timed_out"])
async def test_queued_run_cannot_skip_running(admin_conn, target):
    tenant = await add_tenant(admin_conn)
    run_id = uuid.uuid4()
    await _insert(admin_conn, tenant, id=run_id)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await _set(admin_conn, run_id, "status = $2", target)
