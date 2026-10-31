"""The broker's agent-session routes (SD-048, SD-049): POST /v1/agent/ops and /v1/agent/session.

An agent session's capability works only as `Bearer` on the agent routes, only
for its own profile's operations, and is refused (and, for a known session,
audited) once it has expired, been revoked, or its profile has changed. A
task's run token never works there, and a capability never works as a task.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import respx

from clw.api.catalog import load_agent_catalog
from clw.audit.events import EventType
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter
from clw.broker.capability import issue_run_token
from tests.db.broker_fixtures import (
    LIST, PARAMS, USERS, add_tenant, auth, body, kinds, make_service, page, run_records, run_row, start_run,
    write_key,
)

pytestmark = pytest.mark.pg

AGENTS = load_agent_catalog()
DORMANT = AGENTS["dormant-accounts"]  # on the same profile as the broker test fixtures' credential


@pytest.fixture(scope="module")
def key_path(tmp_path_factory):
    return write_key(tmp_path_factory.mktemp("profile-key"))


@pytest.fixture
def graph():
    with respx.mock(assert_all_called=False) as mock:
        yield mock.route(host="graph.microsoft.com")


async def start_session(admin_conn, writer, tenant, manifest=DORMANT, ttl=3600) -> tuple[str, str]:
    """An agent session as the api starts one (SD-049): (session id, capability)."""
    tid, user_id, oid = tenant
    session_id, issued = uuid.uuid4(), issue_run_token()
    await admin_conn.fetchval(
        "SELECT clw_start_agent_session($1, $2, $3, $4, $5, $6, $7, 'app_only', $8, $9, $10, $11)",
        session_id, tid, manifest.id, manifest.sha256, manifest.profile.id, manifest.profile.version,
        manifest.profile.sha256, user_id, oid, issued.sha256, ttl)
    rid = str(session_id)
    await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.RUN_REQUESTED, "status": "requested", "run_id": rid,
        "task_id": manifest.id, "task_manifest_sha256": manifest.sha256, "actor_oid": oid, "actor_tid": tid})
    await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.RUN_STARTED, "status": "started", "run_id": rid,
        "task_id": manifest.id, "task_manifest_sha256": manifest.sha256, "profile_id": manifest.profile.id,
        "profile_version": manifest.profile.version, "auth_mode": manifest.mode,
        "details": {"kind": "agent_session", "ttl_seconds": ttl}})
    return rid, issued.token


def bearer(token: str) -> str:
    return f"Bearer {token}"


@pytest.fixture
async def session(admin_conn, sessionmaker):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    session_id, capability = await start_session(admin_conn, writer, tenant)
    return {"tenant": tenant, "tid": tenant[0], "id": session_id, "capability": capability, "writer": writer}


def _service(sessionmaker, key_path, writer, **kw):
    return make_service(sessionmaker, key_path=key_path, writer=writer, agent_catalog=AGENTS, **kw)


async def test_a_session_reads_through_its_profile_and_is_audited(sessionmaker, key_path, graph, session):
    graph.mock(return_value=page())
    svc = _service(sessionmaker, key_path, session["writer"])
    result = await svc.handle_agent_request(bearer(session["capability"]), body())
    assert (result.status_code, result.body) == (200, {"status": "ok", "data": USERS})
    records = await run_records(sessionmaker, session["tid"], session["id"])
    assert kinds(records)[2:] == [EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_REQUEST,
                                  EventType.GRAPH_RESPONSE]
    async with sessionmaker() as s:
        report = await verify_chain(s, chain_id=session["tid"])
    assert report.valid and not report.errors


async def test_the_session_is_described_without_reaching_graph(sessionmaker, key_path, graph, session):
    result = await _service(sessionmaker, key_path, session["writer"]).describe_agent_session(
        bearer(session["capability"]))
    assert result.status_code == 200
    described = result.body["session"]
    assert (described["id"], described["profile"], described["operations"]) == (
        session["id"], "dormant-accounts", [LIST])
    assert set(described) == {"id", "expires_at", "profile", "profile_name", "operations"}
    assert not graph.calls
    assert kinds(await run_records(sessionmaker, session["tid"], session["id"])) == [
        EventType.RUN_REQUESTED, EventType.RUN_STARTED]


async def test_an_operation_outside_the_profile_is_denied_and_audited(sessionmaker, key_path, graph, session):
    result = await _service(sessionmaker, key_path, session["writer"]).handle_agent_request(
        bearer(session["capability"]), body("users.update", {}))
    assert result.status_code == 403
    decision = (await run_records(sessionmaker, session["tid"], session["id"]))[-1]
    assert (decision.event_type, decision.status, decision.operation) == (
        EventType.OP_DECISION, "denied", "users.update")
    assert not graph.calls


@pytest.mark.parametrize("scheme", ["RunToken", "bearer-x", "Basic", ""])
async def test_only_the_bearer_scheme_is_accepted(sessionmaker, key_path, graph, session, scheme):
    svc = _service(sessionmaker, key_path, session["writer"])
    header = f"{scheme} {session['capability']}".strip()
    assert (await svc.handle_agent_request(header, body())).status_code == 401
    assert (await svc.describe_agent_session(header)).status_code == 401
    assert not graph.calls


async def test_a_session_capability_is_never_a_task_token(sessionmaker, key_path, graph, session):
    result = await _service(sessionmaker, key_path, session["writer"]).handle_request(
        auth(session["capability"]), body())
    assert (result.status_code, result.body["reason"]) == (403, "not_a_task_run")
    assert not graph.calls


async def test_a_task_token_is_never_a_session(sessionmaker, admin_conn, key_path, graph):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    _, token = await start_run(admin_conn, writer, tenant)
    svc = _service(sessionmaker, key_path, writer)
    for result in (await svc.handle_agent_request(bearer(token), body()), await svc.describe_agent_session(bearer(token))):
        assert (result.status_code, result.body["reason"]) == (403, "not_an_agent_session")
    assert not graph.calls


async def test_an_expired_session_is_refused_and_audited(sessionmaker, key_path, graph, session):
    later = lambda: datetime.now(timezone.utc) + timedelta(hours=2)  # noqa: E731
    svc = _service(sessionmaker, key_path, session["writer"])
    svc._clock = later  # the broker's clock two hours on: past the one-hour session's deadline
    result = await svc.handle_agent_request(bearer(session["capability"]), body())
    assert (result.status_code, result.body["reason"]) == (403, "deadline_exceeded")
    last = (await run_records(sessionmaker, session["tid"], session["id"]))[-1]
    assert (last.event_type, last.reason) == (EventType.OP_DECISION, "deadline_exceeded")
    assert not graph.calls


async def test_a_revoked_session_is_refused(sessionmaker, admin_conn, key_path, graph, session):
    assert await admin_conn.fetchval("SELECT clw_end_agent_session($1, $2, 'completed', 'revoked')",
                                     uuid.UUID(session["id"]), session["tid"])
    svc = _service(sessionmaker, key_path, session["writer"])
    for result in (await svc.handle_agent_request(bearer(session["capability"]), body()),
                   await svc.describe_agent_session(bearer(session["capability"]))):
        assert (result.status_code, result.body["reason"]) == (401, "run_token_invalid")
    assert not graph.calls


async def test_a_profile_changed_mid_session_ends_the_session(sessionmaker, admin_conn, key_path, graph, session):
    changed = {**AGENTS, DORMANT.id: dataclasses.replace(DORMANT, sha256="0" * 64)}
    svc = make_service(sessionmaker, key_path=key_path, writer=session["writer"], agent_catalog=changed)
    result = await svc.handle_agent_request(bearer(session["capability"]), body())
    assert (result.status_code, result.body["reason"]) == (403, "manifest_changed")
    assert (await run_row(admin_conn, session["id"]))["status"] == "failed"
    assert not graph.calls


async def test_without_an_agent_catalog_every_agent_request_is_refused(sessionmaker, key_path, graph, session):
    svc = make_service(sessionmaker, key_path=key_path, writer=session["writer"])
    assert (await svc.handle_agent_request(bearer(session["capability"]), body())).status_code == 403
    assert (await svc.describe_agent_session(bearer(session["capability"]))).status_code == 403
    assert not graph.calls


async def test_the_capability_never_reaches_the_audit_chain(sessionmaker, key_path, graph, session):
    graph.mock(return_value=page())
    svc = _service(sessionmaker, key_path, session["writer"])
    await svc.describe_agent_session(bearer(session["capability"]))
    await svc.handle_agent_request(bearer(session["capability"]), body())
    await svc.handle_agent_request(bearer(session["capability"]), body("users.delete", {}))
    records = await run_records(sessionmaker, session["tid"])
    assert records and all(session["capability"] not in repr(r) for r in records)
    assert PARAMS  # the operation's params are the fixtures' (inactive_days), not the capability


async def test_role_assignments_reach_the_agent_with_only_the_four_principal_properties(
        sessionmaker, admin_conn, key_path, graph):
    from clw.broker.operations import PRINCIPAL_PROPERTIES

    # The dormant profile's credential, allowed the role-assignment read (the manifest digest stays the row's).
    profile = dataclasses.replace(DORMANT, allowed=("directory.list_role_assignments",))
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    session_id, capability = await start_session(admin_conn, writer, tenant, manifest=profile)
    principal = {"@odata.type": "#microsoft.graph.user", "id": "p-1", "displayName": "Ann",
                 "userPrincipalName": "ann@contoso.test", "mail": "ann@contoso.test", "mobilePhone": "+1 555",
                 "accountEnabled": True, "otherMails": ["x@y.test"], "onPremisesSecurityIdentifier": "S-1-5"}
    graph.mock(return_value=page([{"id": "a-1", "principalId": "p-1", "roleDefinitionId": "r-1",
                                   "directoryScopeId": "/", "resourceScope": "/", "principal": principal}]))
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, agent_catalog={DORMANT.id: profile})
    result = await svc.handle_agent_request(bearer(capability), body("directory.list_role_assignments", {}))
    assert result.status_code == 200, result.body
    (item,) = result.body["data"]
    assert set(item) == {"id", "principalId", "roleDefinitionId", "directoryScopeId", "principal"}
    assert set(item["principal"]) == PRINCIPAL_PROPERTIES
    sent = graph.calls.last.request
    assert sent.url.raw_path.decode() == "/v1.0/roleManagement/directory/roleAssignments?$expand=principal"
    assert session_id


async def test_no_graph_access_token_ever_reaches_the_agent_or_the_chain(sessionmaker, admin_conn, key_path, graph):
    """V11 leak check: every token the identity provider issued, against every answer and every record."""
    from tests.db.broker_fixtures import FakeMsal

    factory = FakeMsal()
    profile = dataclasses.replace(DORMANT, allowed=(*DORMANT.allowed, "directory.list_role_assignments"))
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    session_id, capability = await start_session(admin_conn, writer, tenant, manifest=profile)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, factory=factory,
                       agent_catalog={DORMANT.id: profile})
    graph.mock(side_effect=lambda request: page() if request.url.path == "/v1.0/users" else page(
        [{"id": "a", "principalId": "p", "roleDefinitionId": "r", "directoryScopeId": "/",
          "principal": {"id": "p", "displayName": "Ann"}}]))
    answers = [
        await svc.describe_agent_session(bearer(capability)),
        await svc.handle_agent_request(bearer(capability), body()),
        await svc.handle_agent_request(bearer(capability), body("directory.list_role_assignments", {})),
        await svc.handle_agent_request(bearer(capability), body("users.update", {})),
        await svc.handle_agent_proposal(bearer(capability), json.dumps(
            {"action": "disable_user", "user_id": "0f8fad5b-d9cb-469f-a165-70867728950e", "reason": "x"}).encode()),
    ]
    assert factory.issued, "the identity provider issued no token: the check would prove nothing"
    text = json.dumps([a.body for a in answers]) + repr(await run_records(sessionmaker, tenant[0]))
    assert not [t for t in factory.issued if t in text]
    assert "eyJ" not in json.dumps([a.body for a in answers])  # no JWT of any kind in what the agent sees
    assert session_id
