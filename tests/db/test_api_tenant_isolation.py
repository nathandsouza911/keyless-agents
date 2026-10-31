"""The public API binds every run and every view to the caller's verified
tenant, never to the request (Task 16; architecture.md §5; threat-model T5,
T7, T9). Real Postgres; the app's own database work runs under the
least-privileged application role in the db-app job (the `sessionmaker`
fixture). Sign-in is not exercised here (tests/db/test_signin.py does that);
sessions are minted directly from a verified identity.

Covered: unauthenticated requests are refused; a caller-supplied tenant_id (or
actor) is rejected before anything is created; a created run's tenant and
actor are the session's; RUN_REQUESTED is audited with the actor oid; one
tenant cannot read, audit or verify another tenant's runs or chain; unknown
tasks and out-of-range params are refused before a run exists; a run whose
actor is no longer a member is refused with nothing written; a run view never
leaks the run token; and POST /runs is rate limited.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from clw.api.main import create_app
from clw.audit.verifier import load_chain
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.broker_fixtures import CATALOG, MANIFEST, add_tenant, run_row

pytestmark = pytest.mark.pg

TASK_ID = MANIFEST.id


@pytest.fixture
def writer(sessionmaker) -> AuditWriter:
    return AuditWriter(sessionmaker)


def make_app(sessionmaker, writer, *, rate_limited: bool = False):
    return create_app(sessionmaker=sessionmaker, writer=writer, catalog=CATALOG, rate_limited=rate_limited)


def client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000")


def cookie_for(tenant) -> dict[str, str]:
    tid, user_id, oid = tenant
    token = issue_session(user_id=user_id, oid=oid, tid=tid, role="analyst")
    return {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}


async def _create(c, headers, *, task_id: str = TASK_ID, params: dict | None = None, **extra) -> httpx.Response:
    body: dict = {"task_id": task_id, "params": {} if params is None else params, **extra}
    return await c.post("/runs", json=body, headers=headers)


# ---------------------------------------------------------------- authentication


async def test_every_route_requires_a_session(auth_env, sessionmaker, writer):
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        rid = str(uuid.uuid4())
        responses = [
            await c.get("/tasks"),
            await c.get(f"/tasks/{TASK_ID}"),
            await c.get(f"/runs/{rid}"),
            await c.get(f"/runs/{rid}/audit"),
            await c.get("/audit/verify"),
            await _create(c, {}),
        ]
    assert [r.status_code for r in responses] == [401, 401, 401, 401, 401, 401]


# ---------------------------------------------------------------- no tenant/actor from the request


@pytest.mark.parametrize("extra", [{"tenant_id": None}, {"actor_oid": None}, {"status": "running"}, {"image": "x"}])
async def test_body_rejects_any_field_but_task_id_and_params(auth_env, sessionmaker, writer, admin_conn, extra):
    tenant = await add_tenant(admin_conn)
    tid = tenant[0]
    # A concrete value for the smuggled field (another tenant for tenant_id).
    value = str(uuid.uuid4()) if extra.get(next(iter(extra))) is None else extra[next(iter(extra))]
    extra = {next(iter(extra)): value}
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        response = await _create(c, cookie_for(tenant), **extra)
    assert response.status_code == 422 and response.json() == {"detail": "invalid_request"}
    # Nothing was created for the tenant.
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1", tid) == 0


async def test_created_run_binds_the_session_tenant_and_actor(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    tid, user_id, oid = tenant
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        response = await _create(c, cookie_for(tenant))
    assert response.status_code == 201, response.text
    created = response.json()
    assert created["status"] == "queued" and created["task_id"] == TASK_ID
    assert created["params"] == {"inactive_days": 90}  # the manifest default, filled in
    assert "run_token_sha256" not in created and "deadline_at" not in created
    row = await run_row(admin_conn, created["id"])
    assert (row["tenant_id"], row["actor_tid"], row["actor_oid"], row["actor_user_id"]) == (tid, tid, oid, user_id)
    assert row["task_manifest_sha256"] == MANIFEST.sha256 and row["profile_sha256"] == MANIFEST.profile.sha256
    assert row["run_token_sha256"] is None and row["deadline_at"] is None


async def test_run_requested_is_audited_with_the_actor_oid(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    tid, _user_id, oid = tenant
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        created = (await _create(c, cookie_for(tenant))).json()
    async with sessionmaker() as session:
        records = await load_chain(session, chain_id=tid)
    requested = [r for r in records if r.run_id == created["id"]]
    assert [r.event_type for r in requested] == ["RUN_REQUESTED"]
    assert (requested[0].actor_oid, requested[0].actor_tid, requested[0].task_id) == (oid, tid, TASK_ID)


# ---------------------------------------------------------------- cross-tenant isolation


async def test_one_tenant_cannot_read_or_audit_another_tenants_run(auth_env, sessionmaker, writer, admin_conn):
    a, b = await add_tenant(admin_conn), await add_tenant(admin_conn)
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        run_id = (await _create(c, cookie_for(a))).json()["id"]
        # The owner sees it; the other tenant gets an indistinguishable 404.
        assert (await c.get(f"/runs/{run_id}", headers=cookie_for(a))).status_code == 200
        other_get = await c.get(f"/runs/{run_id}", headers=cookie_for(b))
        other_audit = await c.get(f"/runs/{run_id}/audit", headers=cookie_for(b))
    assert other_get.status_code == 404 and other_get.json() == {"detail": "run_not_found"}
    assert other_audit.status_code == 404


async def test_audit_verify_covers_only_the_callers_chain(auth_env, sessionmaker, writer, admin_conn):
    a, b = await add_tenant(admin_conn), await add_tenant(admin_conn)
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        await _create(c, cookie_for(a))
        await _create(c, cookie_for(b))
        await _create(c, cookie_for(b))
        verify_a = (await c.get("/audit/verify", headers=cookie_for(a))).json()
        verify_b = (await c.get("/audit/verify", headers=cookie_for(b))).json()
    assert verify_a["valid"] and verify_b["valid"]
    # Each chain holds only that tenant's own RUN_REQUESTED records.
    assert (verify_a["total"], verify_a["head_seq"]) == (1, 1)
    assert (verify_b["total"], verify_b["head_seq"]) == (2, 2)
    assert verify_a["errors"] == [] and verify_a["intents_without_outcome"] == []


async def test_audit_verify_reports_a_tampered_chain_as_invalid(auth_env, sessionmaker, writer, admin_conn):
    # The reported validity is the real verification result, not a constant:
    # a superuser edits a committed record and /audit/verify must say invalid.
    tenant = await add_tenant(admin_conn)
    tid = tenant[0]
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        await _create(c, cookie_for(tenant))
        await admin_conn.execute("SET session_replication_role = replica")
        try:
            await admin_conn.execute("UPDATE audit_events SET task_id = 'tampered' WHERE chain_id = $1 AND seq = 1", tid)
        finally:
            await admin_conn.execute("SET session_replication_role = DEFAULT")
        report = (await c.get("/audit/verify", headers=cookie_for(tenant))).json()
    assert report["valid"] is False
    assert any(e["seq"] == 1 and e["issue"] == "hash_mismatch" for e in report["errors"])


async def test_run_audit_view_is_the_runs_events_and_chain_validity(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        run_id = (await _create(c, cookie_for(tenant))).json()["id"]
        audit = (await c.get(f"/runs/{run_id}/audit", headers=cookie_for(tenant))).json()
    assert audit["run_id"] == run_id
    assert [e["event_type"] for e in audit["events"]] == ["RUN_REQUESTED"]
    assert audit["chain"] == {"valid": True, "head_seq": 1}
    # No chain-internal or token-like field leaks into an event view.
    for event in audit["events"]:
        assert "record_hash" not in event and "previous_hash" not in event


# ---------------------------------------------------------------- not found, unknown task, bad params


async def test_unknown_or_malformed_run_id_is_404(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        missing = await c.get(f"/runs/{uuid.uuid4()}", headers=cookie_for(tenant))
        malformed = await c.get("/runs/not-a-uuid", headers=cookie_for(tenant))
    assert missing.status_code == 404 and malformed.status_code == 404


async def test_unknown_task_is_refused_before_a_run_exists(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    tid = tenant[0]
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        response = await _create(c, cookie_for(tenant), task_id="no-such-task")
    assert response.status_code == 404 and response.json() == {"detail": "task_not_found"}
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1", tid) == 0


@pytest.mark.parametrize("params,detail", [
    ({"inactive_days": 5}, "params_invalid"),       # below the manifest minimum (30)
    ({"inactive_days": 9000}, "params_invalid"),     # above the maximum (365)
    ({"unknown_key": 1}, "params_invalid"),          # not a manifest param
    ({"inactive_days": 1.5}, "invalid_request"),     # not an integer (rejected by the body schema)
])
async def test_out_of_range_or_unknown_params_refused(auth_env, sessionmaker, writer, admin_conn, params, detail):
    tenant = await add_tenant(admin_conn)
    tid = tenant[0]
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        response = await _create(c, cookie_for(tenant), params=params)
    assert response.status_code == 422 and response.json() == {"detail": detail}
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1", tid) == 0


# ---------------------------------------------------------------- membership revoked mid-session


async def test_run_refused_when_the_actor_is_no_longer_a_member(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    tid, user_id, _oid = tenant
    headers = cookie_for(tenant)  # a session issued while the person was a member
    await admin_conn.execute("DELETE FROM workbench_users WHERE id = $1", user_id)
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        response = await _create(c, headers)
    assert response.status_code == 403 and response.json() == {"detail": "access_denied"}
    # Fail closed: no run row, and no RUN_REQUESTED was written to the chain.
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1", tid) == 0
    async with sessionmaker() as session:
        assert await load_chain(session, chain_id=tid) == []


# ---------------------------------------------------------------- the run view hides the token


async def test_run_view_never_shows_the_run_token_or_deadline(auth_env, sessionmaker, writer, admin_conn):
    tenant = await add_tenant(admin_conn)
    tid = tenant[0]
    app = make_app(sessionmaker, writer)
    async with client(app) as c:
        run_id = (await _create(c, cookie_for(tenant))).json()["id"]
    # Promote the run to running with a token and deadline (as the runner would).
    token_hash = "a" * 64
    await admin_conn.execute(
        "UPDATE runs SET status = 'running', run_token_sha256 = $2, deadline_at = now() + interval '5 minutes', "
        "started_at = now() WHERE id = $1", uuid.UUID(run_id), token_hash)
    async with client(app) as c:
        view = (await c.get(f"/runs/{run_id}", headers=cookie_for(tenant))).json()
    assert view["status"] == "running"
    assert token_hash not in view.values() and set(view) == {
        "id", "task_id", "status", "params", "outcome", "result", "result_redacted", "kind", "created_at",
        "started_at", "ended_at"}


# ---------------------------------------------------------------- rate limiting (SD-027)


async def test_runs_create_is_rate_limited(auth_env, sessionmaker, writer, admin_conn):
    # No Redis in the test env: the limiter uses its in-memory fallback. The
    # per-user limit for runs_create is 10 in the window; the 11th is refused.
    tenant = await add_tenant(admin_conn)
    headers = cookie_for(tenant)
    app = make_app(sessionmaker, writer, rate_limited=True)
    async with client(app) as c:
        statuses = [(await _create(c, headers)).status_code for _ in range(11)]
    assert statuses[:10] == [201] * 10 and statuses[10] == 429
