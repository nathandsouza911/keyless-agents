"""Agent sessions through the api and the broker's capability resolution (SD-048, SD-049).

Starting needs a verified browser session and an explicit profile; it is
write-ahead audited, and no capability exists unless the records committed.
Revoking is the starter's or a security lead's, and only ever ends an agent
session. The capability resolves only as an agent session, only until its
deadline, only while its profile is unchanged, and never after revocation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from clw.api.catalog import load_agent_catalog
from clw.api.main import create_app
from clw.audit.events import AuditRunStateRefused, AuditUnavailable, EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from clw.broker.capability import RunRefused, resolve_run
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.broker_fixtures import CATALOG, add_tenant, start_run

pytestmark = pytest.mark.pg

AGENT_CATALOG = load_agent_catalog()
PROFILE = "dormant-accounts"  # analysts may start it; read-only-investigation is security leads only (SD-055)


class FlakyWriter:
    """The real writer, except that the named event types fail as told."""

    def __init__(self, inner: AuditWriter, fail: dict[str, Exception]):
        self.inner, self.fail = inner, fail

    async def append(self, *, chain_id, event):
        error = self.fail.get(str(event["event_type"]))
        if error is not None:
            raise error
        return await self.inner.append(chain_id=chain_id, event=event)


@pytest.fixture
async def org(admin_conn, sessionmaker, auth_env):
    auth_env()
    tid, analyst_id, analyst_oid = await add_tenant(admin_conn)
    other_id, other_oid = uuid.uuid4(), str(uuid.uuid4())
    lead_id, lead_oid = uuid.uuid4(), str(uuid.uuid4())
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, 'analyst')",
                             other_id, tid, other_oid)
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) "
                             "VALUES ($1, $2, $3, 'security_lead')", lead_id, tid, lead_oid)
    stranger = await add_tenant(admin_conn)

    def cookie(user_id, oid, role, tenant=tid):
        return {"Cookie": f"{SESSION_COOKIE_NAME}={issue_session(user_id=user_id, oid=oid, tid=tenant, role=role)}"}

    return {"tid": tid, "analyst_oid": analyst_oid,
            "analyst": cookie(analyst_id, analyst_oid, "analyst"), "other": cookie(other_id, other_oid, "analyst"),
            "lead": cookie(lead_id, lead_oid, "security_lead"),
            "stranger": cookie(stranger[1], stranger[2], "analyst", stranger[0]), "stranger_tid": stranger[0]}


def _app(sessionmaker, writer=None):
    return create_app(sessionmaker=sessionmaker, writer=writer or AuditWriter(sessionmaker), catalog=CATALOG,
                      agent_catalog=AGENT_CATALOG, rate_limited=False)


async def _post(app, headers=None, json=None):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000") as c:
        return await c.post("/v1/agent-sessions", json={"profile": PROFILE} if json is None else json,
                            headers=headers or {})


async def _delete(app, session_id, headers):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000") as c:
        return await c.delete(f"/v1/agent-sessions/{session_id}", headers=headers)


async def _resolve(sessionmaker, token, *, kind="agent_session", catalog=AGENT_CATALOG, now=None):
    async with sessionmaker() as session:
        return await resolve_run(session, token, catalog=catalog, kind=kind, now=now or datetime.now(timezone.utc))


async def _records(sessionmaker, tid, run_id):
    async with sessionmaker() as session:
        return [r for r in await load_chain(session, chain_id=tid) if r.run_id == run_id]


async def _chain_ok(sessionmaker, tid):
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=tid)
        return report.valid and not report.errors


# --- starting ----------------------------------------------------------------------

async def test_starting_needs_a_browser_sign_in(sessionmaker, org):
    app = _app(sessionmaker)
    assert (await _post(app)).status_code == 401
    started = (await _post(app, org["analyst"])).json()
    # A capability is not a browser session: it cannot start another session.
    assert (await _post(app, {"Authorization": f"Bearer {started['capability']}"})).status_code == 401


@pytest.mark.parametrize("body", [
    {}, {"ttl_minutes": 60}, {"profile": ""}, {"profile": PROFILE, "ttl_minutes": 0},
    {"profile": PROFILE, "ttl_minutes": 481}, {"profile": PROFILE, "ttl_minutes": "60"},
    {"profile": PROFILE, "tenant_id": "x"}, {"profile": PROFILE, "actor_oid": "x"},
])
async def test_the_profile_must_be_chosen_and_nothing_else_may_be_set(sessionmaker, org, body):
    assert (await _post(_app(sessionmaker), org["analyst"], body)).status_code == 422


async def test_an_unknown_profile_is_refused(sessionmaker, org):
    assert (await _post(_app(sessionmaker), org["analyst"], {"profile": "dormant-account-investigation"})
            ).status_code == 404


async def test_a_started_session_is_bound_to_the_signed_in_human_and_audited_first(sessionmaker, admin_conn, org):
    reply = await _post(_app(sessionmaker), org["analyst"], {"profile": PROFILE, "ttl_minutes": 30})
    assert reply.status_code == 201 and reply.headers["cache-control"] == "no-store"
    body = reply.json()
    assert set(body) == {"id", "profile", "expires_at", "capability"} and body["profile"] == PROFILE
    row = await admin_conn.fetchrow("SELECT * FROM runs WHERE id = $1", uuid.UUID(body["id"]))
    assert (row["kind"], row["status"], row["tenant_id"], row["actor_oid"]) == (
        "agent_session", "running", org["tid"], org["analyst_oid"])
    assert row["run_token_sha256"] == hashlib.sha256(body["capability"].encode()).hexdigest()
    assert row["deadline_at"] - row["started_at"] == timedelta(minutes=30)
    manifest = AGENT_CATALOG[PROFILE]
    assert (row["task_id"], row["task_manifest_sha256"], row["profile_id"]) == (
        manifest.id, manifest.sha256, manifest.profile.id)
    records = await _records(sessionmaker, org["tid"], body["id"])
    assert [r.event_type for r in records] == [EventType.RUN_REQUESTED, EventType.RUN_STARTED]
    assert records[0].actor_oid == org["analyst_oid"]
    assert set(records[1].details) == {"kind", "ttl_seconds", "signed_in_at"}
    assert (records[1].details["kind"], records[1].details["ttl_seconds"]) == ("agent_session", 1800)
    assert all(body["capability"] not in repr(r) for r in records)
    assert await _chain_ok(sessionmaker, org["tid"])


@pytest.mark.parametrize("failing", [EventType.RUN_REQUESTED, EventType.RUN_STARTED])
async def test_no_capability_exists_unless_both_records_are_written(sessionmaker, admin_conn, org, failing):
    writer = FlakyWriter(AuditWriter(sessionmaker), {str(failing): AuditUnavailable("down")})
    reply = await _post(_app(sessionmaker, writer), org["analyst"])
    assert reply.status_code == 503 and "capability" not in reply.text
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1 AND kind = 'agent_session'",
                                     org["tid"]) == 0


# --- resolving the capability -------------------------------------------------------

async def test_the_capability_resolves_only_as_an_agent_session(sessionmaker, org):
    body = (await _post(_app(sessionmaker), org["analyst"])).json()
    ctx = await _resolve(sessionmaker, body["capability"])
    assert (ctx.run_id, ctx.tenant_id, ctx.manifest.id) == (body["id"], org["tid"], PROFILE)
    with pytest.raises(RunRefused) as refused:
        await _resolve(sessionmaker, body["capability"], kind="task", catalog=CATALOG)
    assert refused.value.reason == "not_a_task_run"


async def test_a_task_token_is_not_an_agent_session(sessionmaker, admin_conn, org):
    _, token = await start_run(admin_conn, AuditWriter(sessionmaker), await add_tenant(admin_conn))
    with pytest.raises(RunRefused) as refused:
        await _resolve(sessionmaker, token, catalog=CATALOG)
    assert refused.value.reason == "not_an_agent_session"


async def test_an_expired_capability_is_refused(sessionmaker, org):
    body = (await _post(_app(sessionmaker), org["analyst"], {"profile": PROFILE, "ttl_minutes": 1})).json()
    with pytest.raises(RunRefused) as refused:
        await _resolve(sessionmaker, body["capability"], now=datetime.now(timezone.utc) + timedelta(seconds=61))
    assert refused.value.reason == "deadline_exceeded"


async def test_a_profile_changed_after_the_session_started_is_refused(sessionmaker, org):
    body = (await _post(_app(sessionmaker), org["analyst"])).json()
    changed = {**AGENT_CATALOG, PROFILE: dataclasses.replace(AGENT_CATALOG[PROFILE], sha256="0" * 64)}
    with pytest.raises(RunRefused) as refused:
        await _resolve(sessionmaker, body["capability"], catalog=changed)
    assert refused.value.reason == "manifest_changed"


# --- revoking ----------------------------------------------------------------------

async def test_the_starter_revokes_the_session_and_the_capability_dies(sessionmaker, admin_conn, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    reply = await _delete(app, body["id"], org["analyst"])
    assert reply.status_code == 200 and reply.json() == {"id": body["id"], "status": "revoked", "audited": True}
    row = await admin_conn.fetchrow("SELECT status, outcome, run_token_sha256 FROM runs WHERE id = $1",
                                    uuid.UUID(body["id"]))
    assert tuple(row) == ("completed", "revoked", None)
    with pytest.raises(RunRefused) as refused:
        await _resolve(sessionmaker, body["capability"])
    assert refused.value.reason == "run_token_invalid"
    records = await _records(sessionmaker, org["tid"], body["id"])
    assert records[-1].event_type == EventType.RUN_COMPLETED and records[-1].outcome == "revoked"
    assert await _chain_ok(sessionmaker, org["tid"])


async def test_a_security_lead_may_revoke_another_members_session(sessionmaker, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    assert (await _delete(app, body["id"], org["lead"])).status_code == 200


async def test_another_analyst_may_not_revoke_it(sessionmaker, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    assert (await _delete(app, body["id"], org["other"])).status_code == 403


async def test_another_tenant_cannot_see_or_revoke_it(sessionmaker, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    assert (await _delete(app, body["id"], org["stranger"])).status_code == 404


async def test_a_task_run_cannot_be_revoked_as_a_session(sessionmaker, admin_conn, org):
    tenant = (org["tid"], *(await admin_conn.fetchrow(
        "SELECT id, oid FROM workbench_users WHERE tenant_id = $1 AND oid = $2", org["tid"], org["analyst_oid"])))
    run_id, _ = await start_run(admin_conn, AuditWriter(sessionmaker), tenant)
    assert (await _delete(_app(sessionmaker), run_id, org["lead"])).status_code == 404
    assert await admin_conn.fetchval("SELECT status FROM runs WHERE id = $1", uuid.UUID(run_id)) == "running"


@pytest.mark.parametrize("session_id", ["not-a-uuid", str(uuid.uuid4())])
async def test_an_unknown_session_is_not_found(sessionmaker, org, session_id):
    assert (await _delete(_app(sessionmaker), session_id, org["analyst"])).status_code == 404


async def test_a_session_ends_once(sessionmaker, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    assert (await _delete(app, body["id"], org["analyst"])).status_code == 200
    assert (await _delete(app, body["id"], org["analyst"])).status_code == 409


async def test_revoked_during_a_graph_request_ends_failed(sessionmaker, admin_conn, org):
    body = (await _post(_app(sessionmaker), org["analyst"])).json()
    writer = FlakyWriter(AuditWriter(sessionmaker),
                         {str(EventType.RUN_COMPLETED): AuditRunStateRefused(body["id"], "outstanding_requests")})
    reply = await _delete(_app(sessionmaker, writer), body["id"], org["analyst"])
    assert reply.status_code == 200 and reply.json()["audited"] is True
    row = await admin_conn.fetchrow("SELECT status, outcome, run_token_sha256 FROM runs WHERE id = $1",
                                    uuid.UUID(body["id"]))
    assert tuple(row) == ("failed", "revoked_during_request", None)
    records = await _records(sessionmaker, org["tid"], body["id"])
    assert records[-1].event_type == EventType.RUN_FAILED and records[-1].reason == "revoked_during_request"


async def test_the_token_is_revoked_even_when_the_end_cannot_be_recorded(sessionmaker, admin_conn, org):
    body = (await _post(_app(sessionmaker), org["analyst"])).json()
    writer = FlakyWriter(AuditWriter(sessionmaker), {str(EventType.RUN_COMPLETED): AuditUnavailable("down")})
    reply = await _delete(_app(sessionmaker, writer), body["id"], org["analyst"])
    assert reply.status_code == 200 and reply.json()["audited"] is False
    assert await admin_conn.fetchval("SELECT run_token_sha256 FROM runs WHERE id = $1", uuid.UUID(body["id"])) is None
    with pytest.raises(RunRefused):
        await _resolve(sessionmaker, body["capability"])


async def test_an_expired_session_is_ended_by_the_reconciler_as_expired(sessionmaker, runner_sessionmaker,
                                                                         admin_conn, org):
    from clw.runner.reconciler import Reconciler

    body = (await _post(_app(sessionmaker), org["analyst"], {"profile": PROFILE, "ttl_minutes": 1})).json()
    # A negative grace makes a session one minute from its deadline overdue; earlier tests' leftovers may be
    # swept first, so sweep until this session is reached.
    reconciler = Reconciler(sessionmaker=runner_sessionmaker, writer=AuditWriter(runner_sessionmaker),
                            grace=timedelta(minutes=-2))
    for _ in range(50):
        if any(r.run_id == body["id"] for r in await reconciler.sweep()):
            break
    row = await admin_conn.fetchrow("SELECT status, outcome, run_token_sha256 FROM runs WHERE id = $1",
                                    uuid.UUID(body["id"]))
    assert tuple(row) == ("timed_out", "session_expired", None)
    records = await _records(sessionmaker, org["tid"], body["id"])
    assert (records[-1].event_type, records[-1].reason) == (EventType.RUN_TIMED_OUT, "session_expired")


# --- the JSON routes take only this origin's JSON (security review F4, 2026-10-31) -----------

@pytest.mark.parametrize("headers, status", [
    ({"Origin": "https://evil.example"}, 403), ({"Origin": "http://localhost:8001"}, 403),
    ({"Content-Type": "text/plain"}, 415), ({"Content-Type": ""}, 415),
])
async def test_starting_refuses_another_origin_or_a_non_json_body(sessionmaker, admin_conn, org, headers, status):
    app = _app(sessionmaker)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000") as c:
        reply = await c.post("/v1/agent-sessions", content=b'{"profile": "read-only-investigation"}',
                             headers={"Content-Type": "application/json", **headers, **org["analyst"]})
    assert reply.status_code == status
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1 AND kind = 'agent_session'",
                                     org["tid"]) == 0


async def test_revoking_refuses_another_origin(sessionmaker, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000") as c:
        reply = await c.delete(f"/v1/agent-sessions/{body['id']}",
                               headers={"Origin": "https://evil.example", **org["analyst"]})
    assert reply.status_code == 403



# --- who may start a session, and how long it lasts (SD-055, 2026-10-31) -------------------------

async def test_a_profile_names_who_may_start_it(sessionmaker, org):
    app = _app(sessionmaker)
    refused = await _post(app, org["analyst"], {"profile": "read-only-investigation"})
    assert (refused.status_code, refused.json()["detail"]) == (403, "role_not_allowed")
    assert (await _post(app, org["lead"], {"profile": "read-only-investigation"})).status_code == 201


async def test_a_disabled_tenant_ends_its_sessions_at_once_and_starts_none(sessionmaker, admin_conn, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["analyst"])).json()
    await admin_conn.execute("UPDATE tenants SET status = 'disabled' WHERE id = $1", org["tid"])
    try:
        with pytest.raises(RunRefused) as refused:
            await _resolve(sessionmaker, body["capability"])
        assert refused.value.reason == "tenant_disabled"
        assert (await _post(app, org["analyst"])).status_code == 403
    finally:
        await admin_conn.execute("UPDATE tenants SET status = 'active' WHERE id = $1", org["tid"])


async def test_a_starter_whose_role_no_longer_allows_the_profile_is_refused(sessionmaker, admin_conn, org):
    app = _app(sessionmaker)
    body = (await _post(app, org["lead"], {"profile": "read-only-investigation"})).json()
    lead_oid = (await admin_conn.fetchrow("SELECT actor_oid FROM runs WHERE id = $1", uuid.UUID(body["id"])))[0]
    await admin_conn.execute("UPDATE workbench_users SET role = 'analyst' WHERE tenant_id = $1 AND oid = $2",
                             org["tid"], lead_oid)
    with pytest.raises(RunRefused) as refused:
        await _resolve(sessionmaker, body["capability"])
    assert refused.value.reason == "actor_not_allowed"


async def test_signing_out_ends_the_persons_own_agent_sessions(sessionmaker, admin_conn, org):
    from clw.api.routes.agent_sessions import end_sessions_started_by

    app = _app(sessionmaker)
    mine = [(await _post(app, org["analyst"])).json() for _ in range(2)]
    theirs = (await _post(app, org["other"])).json()
    ended = await end_sessions_started_by(sessionmaker, AuditWriter(sessionmaker), org["tid"], org["analyst_oid"])
    assert ended == 2
    for body in mine:
        with pytest.raises(RunRefused):
            await _resolve(sessionmaker, body["capability"])
    assert (await _resolve(sessionmaker, theirs["capability"])).run_id == theirs["id"]
    assert await _chain_ok(sessionmaker, org["tid"])



# --- a recent, interactive sign-in starts a session (SD-055, review F1) -------------------------------

def _cookie_signed_in(org_tid, user_id, oid, role, seconds_ago):
    from types import SimpleNamespace
    from unittest import mock

    from clw.auth import session_jwt

    real = session_jwt.time.time
    with mock.patch.object(session_jwt, "time", SimpleNamespace(time=lambda: real() - seconds_ago)):
        token = issue_session(user_id=user_id, oid=oid, tid=org_tid, role=role)
    return {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}


@pytest.mark.parametrize("seconds_ago, status", [(30, 201), (9 * 60, 201), (11 * 60, 401), (7 * 3600, 401)])
async def test_starting_needs_a_sign_in_from_the_last_ten_minutes(sessionmaker, admin_conn, org, seconds_ago,
                                                                   status):
    row = await admin_conn.fetchrow("SELECT id, oid FROM workbench_users WHERE tenant_id = $1 AND oid = $2",
                                    org["tid"], org["analyst_oid"])
    reply = await _post(_app(sessionmaker), _cookie_signed_in(org["tid"], row["id"], row["oid"], "analyst",
                                                              seconds_ago))
    assert reply.status_code == status
    if status == 401:
        assert reply.json()["detail"] == "fresh_sign_in_required"
