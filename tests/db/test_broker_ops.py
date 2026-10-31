"""Broker operations end to end against PostgreSQL (Task 12; brief's security
table rows 1, 2, 5 and 8; SD-007, SD-014, SD-018, SD-032; threat model T9-T17).

Real: the runs table, the audit writer and verifier, run-token resolution,
the policy, the credential validator, the transport. Mocked: Graph (respx)
and MSAL (a fake app issuing unsigned tokens). Nothing here shows real
Microsoft Graph behaviour (A-02, A-14, A-15, A-16 unverified)."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from clw.audit.events import EventType
from clw.audit.verifier import verify_chain
from clw.broker import operations, service as service_module
from clw.broker.app import create_app
from clw.broker.capability import resolve_run
from clw.broker.credentials import ValidatedToken
from clw.broker.manifest import load_manifest
from clw.broker.pagination import request_target
from clw.broker.policy import AllowlistPolicyEngine, Decision, evaluate
from clw.broker.transport import GRAPH_ORIGIN, GraphAttempt, Transport, new_graph_client
from clw.audit.writer import AuditWriter
from tests.db.broker_fixtures import (
    CATALOG, LIST, MANIFEST, PARAMS, REPO, TARGET, URL, USERS, FakeMsal, add_tenant, auth, body, kinds,
    make_service, no_sleep, page, run_records, run_row, start_run, write_key,
)

pytestmark = pytest.mark.pg

LICENCE = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
RUN_START = [EventType.RUN_REQUESTED, EventType.RUN_STARTED]
ONE_ATTEMPT = [EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_REQUEST, EventType.GRAPH_RESPONSE]


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


async def _valid(sessionmaker, tid):
    async with sessionmaker() as session:
        return await verify_chain(session, chain_id=tid)


# --------------------------------------------------------------- allowed path


async def test_approved_read_allowed_and_audited(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)

    result = await svc.handle_request(auth(token), body())

    assert (result.status_code, result.body) == (200, {"status": "ok", "data": USERS})
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert kinds(records) == RUN_START + ONE_ATTEMPT
    decision, credential, request, response = records[2:]
    assert (decision.status, decision.reason, decision.operation) == ("allowed", "allowed", LIST)
    assert (credential.status, credential.profile_id, credential.profile_version) == (
        "accepted", MANIFEST.profile.id, MANIFEST.profile.version)
    assert credential.details == {"permissions": sorted(MANIFEST.profile.expected_permissions)}
    assert (request.attempt, request.decision_seq, response.attempt) == (1, decision.seq, 1)
    assert (response.status, response.http_status, response.item_count) == ("succeeded", 200, 2)
    assert response.graph_request_id == "11111111-2222-3333-4444-555555555555"
    report = await _valid(sessionmaker, tenant[0])
    assert report.valid and report.complete, report.errors
    assert (await run_row(admin_conn, run_id))["status"] == "running"  # completion is the runner's (Task 14)


async def test_recorded_authorization_is_the_request_sent(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())

    sent = graph.calls.last.request
    decision, _, request = (await run_records(sessionmaker, tenant[0], run_id))[2:5]
    assert sent.method == "GET" and sent.url.host == "graph.microsoft.com"
    assert sent.url.raw_path.decode() == TARGET  # path and normalized query, byte for byte
    assert decision.details == {"request_target": TARGET}
    assert request.request_target == TARGET
    assert (decision.http_method, decision.path_template) == (request.http_method, request.path_template) == (
        "GET", "/users")


async def test_executed_request_is_the_object_the_policy_returned(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                  graph, monkeypatch):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    approved, executed = [], []

    def spying_evaluate(*args):
        result = evaluate(*args)
        approved.append(result[1])
        return result

    class SpyTransport(Transport):
        async def execute(self, request, token, **kwargs):
            executed.append(request)
            return await super().execute(request, token, **kwargs)

    monkeypatch.setattr(service_module, "evaluate", spying_evaluate)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer,
                       transport=SpyTransport(new_graph_client(), sleep=no_sleep))
    assert (await svc.handle_request(auth(token), body())).status_code == 200
    assert len(executed) == 1 and executed[0] is approved[0]
    assert request_target(executed[0]) == graph.calls.last.request.url.raw_path.decode()


def _announcing(target: str | None = None, method: str = "GET", attempt: int = 1):
    """A transport that announces an attempt other than the approved request."""

    class Announcing(Transport):
        async def execute(self, request, token, *, deadline, before_attempt, after_attempt):
            await before_attempt(GraphAttempt(attempt, method, target or request_target(request), None, None, 0, None))
            return await super().execute(request, token, deadline=deadline, before_attempt=before_attempt,
                                         after_attempt=after_attempt)

    return Announcing(new_graph_client(), sleep=no_sleep)


@pytest.mark.parametrize("kwargs", [
    {"target": "/v1.0/users?$select=id,signInActivity&$top=999"},
    {"target": "/v1.0/users?$select=id,signInActivity,userPrincipalName&$top=50"},
    {"target": "/v1.0/users?$select=id,signInActivity&$top=50&$expand=manager"},
    {"target": "/v1.0/users/00000000-0000-0000-0000-000000000000"},
    {"target": "/v1.0/groups?$select=id,signInActivity&$top=50"},
    {"target": "/v1.0/users?$select=id,signInActivity&$top=50$skiptoken=x"},
    {"method": "PATCH"},
    {"attempt": 2},
])
async def test_caller_cannot_replace_the_approved_request(sessionmaker, writer, admin_conn, tenant, key_path, graph,
                                                          kwargs):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, transport=_announcing(**kwargs))

    result = await svc.handle_request(auth(token), body())

    assert result.body == {"status": "failed", "reason": "request_binding_mismatch"}
    assert graph.call_count == 0
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert EventType.GRAPH_REQUEST not in kinds(records)
    assert (records[-1].event_type, records[-1].reason) == (EventType.RUN_FAILED, "request_binding_mismatch")
    assert (await _valid(sessionmaker, tenant[0])).valid


async def test_parameters_changed_after_authorization_are_not_executed(sessionmaker, writer, admin_conn, tenant,
                                                                       key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    params = {"select": ["id", "signInActivity"], "top": 50}

    def respond(request):
        params["top"] = 100  # the caller swaps its parameters (to another valid value) while the operation runs
        params["select"].append("userPrincipalName")
        return httpx.Response(429)

    graph.side_effect = respond
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    async with sessionmaker() as session:
        ctx = await resolve_run(session, token, catalog=CATALOG, now=datetime.now(timezone.utc))

    result = await svc.handle(ctx, LIST, params)

    assert result.body == {"status": "denied", "reason": "request_changed"}
    assert [c.request.url.raw_path.decode() for c in graph.calls] == [TARGET]  # the retry was never sent
    last = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (last.event_type, last.status, last.reason, last.details) == (
        EventType.OP_DECISION, "denied", "request_changed", {"for_attempt": 2})
    assert (await _valid(sessionmaker, tenant[0])).complete


@pytest.mark.parametrize("ended_by", ["broker", "halted", "runner"])
async def test_a_stale_context_records_nothing_after_the_run_stops(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                    graph, ended_by):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=httpx.Response(400))
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    async with sessionmaker() as session:
        ctx = await resolve_run(session, token, catalog=CATALOG, now=datetime.now(timezone.utc))
    if ended_by == "broker":
        assert (await svc.handle(ctx, LIST, PARAMS)).body == {"status": "failed", "reason": "bad_request"}
    elif ended_by == "halted":
        await admin_conn.execute("UPDATE runs SET status = 'halted' WHERE id = $1", uuid.UUID(run_id))
    else:
        await admin_conn.execute("UPDATE runs SET status = 'timed_out', run_token_sha256 = NULL WHERE id = $1",
                                 uuid.UUID(run_id))
    calls, before = graph.call_count, await run_records(sessionmaker, tenant[0], run_id)
    expected = "run_halted" if ended_by == "halted" else "run_not_running"

    for operation in ((LIST, PARAMS), ("users.update", {"user_id": str(uuid.uuid4())})):
        assert (await svc.handle(ctx, *operation)).body == {"status": "denied", "reason": expected}
        other_process = make_service(sessionmaker, key_path=key_path, writer=writer)
        assert (await other_process.handle(ctx, *operation)).body == {"status": "denied", "reason": expected}

    assert await run_records(sessionmaker, tenant[0], run_id) == before
    assert graph.call_count == calls
    assert (await _valid(sessionmaker, tenant[0])).valid


async def test_built_request_cannot_be_altered_in_place():
    request = operations.build_request(operations.get(LIST), PARAMS)
    with pytest.raises(AttributeError):
        request.path = "/groups"  # type: ignore[misc]
    assert type(request.query) is tuple


# ---------------------------------------------------------------- denials


@pytest.mark.parametrize("op, params, reason, method", [
    ("users.update", {"user_id": "00000000-0000-0000-0000-000000000001"}, "prohibited", "PATCH"),
    ("users.delete", {"user_id": "00000000-0000-0000-0000-000000000001"}, "prohibited", "DELETE"),
    ("users.disable", {}, "unknown_operation", None),
    (LIST, {"select": ["id"], "user_id": "../me"}, "invalid_params", "GET"),
    (LIST, {"select": ["id"], "top": 0}, "invalid_params", "GET"),
    (LIST, {"select": ["id"], "$expand": "manager"}, "invalid_params", "GET"),
])
async def test_denied_operations_are_audited_and_never_reach_graph(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                    graph, op, params, reason, method):
    run_id, token = await start_run(admin_conn, writer, tenant)
    factory = FakeMsal()
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, factory=factory)

    result = await svc.handle_request(auth(token), body(op, params))

    assert (result.status_code, result.body) == (403, {"status": "denied", "reason": reason})
    assert graph.call_count == 0 and factory.issued == []  # no token is even acquired
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert kinds(records) == RUN_START + [EventType.OP_DECISION]
    decision = records[-1]
    assert (decision.status, decision.reason, decision.operation, decision.http_method) == ("denied", reason, op, method)
    assert (await run_row(admin_conn, run_id))["status"] == "running"  # a denial does not end the run
    assert (await _valid(sessionmaker, tenant[0])).valid


async def test_readonly_task_disable_user_denied_and_audited(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    # The plan says not_in_manifest; users.update is in the manifest's prohibited
    # list, and prohibited is checked first (Task 9 acceptance, SD-003).
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    result = await svc.handle_request(auth(token), body("users.update", {"user_id": str(uuid.uuid4())}))
    assert result.body == {"status": "denied", "reason": "prohibited"}
    decision = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (decision.event_type, decision.status, decision.path_template) == (
        EventType.OP_DECISION, "denied", "/users/{user_id}")
    assert graph.call_count == 0


async def test_unlisted_operation_denied(sessionmaker, writer, admin_conn, tenant, key_path, graph, tmp_path):
    source = (REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml").read_text()
    narrowed = source.replace("  - users.delete\n", "")
    (tmp_path / "manifest.yaml").write_text(narrowed, encoding="utf-8")
    manifest = load_manifest(tmp_path / "manifest.yaml", profiles_dir=REPO / "profiles")
    run_id, token = await start_run(admin_conn, writer, tenant, manifest=manifest)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, catalog={manifest.id: manifest})
    result = await svc.handle_request(auth(token), body("users.delete", {"user_id": str(uuid.uuid4())}))
    assert result.body == {"status": "denied", "reason": "not_in_manifest"}
    assert graph.call_count == 0


async def test_unknown_operation_denied(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(
        auth(token), body("Users.List_With_Sign_In_Activity"))
    assert result.body == {"status": "denied", "reason": "unknown_operation"}
    assert graph.call_count == 0


@pytest.mark.parametrize("extra", [
    {"path": "/users/x"}, {"url": "https://graph.microsoft.com/v1.0/users"}, {"method": "DELETE"},
    {"headers": {"Authorization": "Bearer x"}}, {"tenant_id": "00000000-0000-0000-0000-000000000000"},
])
async def test_request_shaping_fields_rejected_and_audited(sessionmaker, writer, admin_conn, tenant, key_path, graph,
                                                           extra):
    run_id, token = await start_run(admin_conn, writer, tenant)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(
        auth(token), body(**extra))
    assert (result.status_code, result.body) == (403, {"status": "denied", "reason": "unknown_field"})
    decision = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (decision.event_type, decision.status, decision.reason, decision.operation) == (
        EventType.OP_DECISION, "denied", "unknown_field", LIST)
    assert graph.call_count == 0


@pytest.mark.parametrize("raw, label, reason", [
    (b"not json", "(invalid)", "invalid_request"), (b"[]", "(invalid)", "invalid_request"),
    (b'{"op": "x"}', "x", "invalid_request"), (b'{"op": 1, "params": {}}', "(invalid)", "invalid_request"),
    (b'{"op": "users.list", "params": []}', "users.list", "invalid_request"),
    (b'{"op": "x", "op": "y", "params": {}}', "(invalid)", "invalid_request"),
    (b'{"op": "x", "params": {"top": NaN}}', "(invalid)", "invalid_request"),
    (bytes([0xFF, 0xFE]), "(invalid)", "invalid_request"),
    # A well-formed body naming an operation that is not a safe label: the
    # policy denies it, and the audit records a placeholder, not the text.
    (json.dumps({"op": "a b\n", "params": {}}).encode(), "(invalid)", "unknown_operation"),
    (json.dumps({"op": "x" * 129, "params": {}}).encode(), "(invalid)", "unknown_operation"),
])
async def test_malformed_bodies_denied_and_audited(sessionmaker, writer, admin_conn, tenant, key_path, graph, raw,
                                                   label, reason):
    run_id, token = await start_run(admin_conn, writer, tenant)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), raw)
    assert result.body == {"status": "denied", "reason": reason}
    decision = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (decision.reason, decision.operation) == (reason, label)
    assert graph.call_count == 0


class RaisingEngine:
    def authorize_operation(self, manifest, op_name, params):
        raise RuntimeError("engine bug quoting " + json.dumps(params))

    def authorize_request(self, manifest, request):
        raise RuntimeError("unreachable")


async def test_policy_exception_denies(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    factory = FakeMsal()
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, engine=RaisingEngine(), factory=factory)
    result = await svc.handle_request(auth(token), body())
    assert result.body == {"status": "denied", "reason": "policy_error"}
    assert graph.call_count == 0 and factory.issued == []
    decision = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (decision.status, decision.reason, decision.details) == ("denied", "policy_error", {})


# ------------------------------------------------------- run token and tenant


async def test_run_token_after_completion_denied(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    await admin_conn.execute("UPDATE runs SET status = 'completed', run_token_sha256 = NULL, ended_at = now() "
                             "WHERE id = $1", uuid.UUID(run_id))
    before = await run_records(sessionmaker, tenant[0], run_id)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert (result.status_code, result.body) == (401, {"status": "denied", "reason": "run_token_invalid"})
    assert await run_records(sessionmaker, tenant[0], run_id) == before  # nothing after the run's end
    assert graph.call_count == 0


async def test_run_token_after_deadline_denied(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant,
                                    deadline=datetime.now(timezone.utc) - timedelta(seconds=1))
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert (result.status_code, result.body) == (403, {"status": "denied", "reason": "deadline_exceeded"})
    decision = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (decision.event_type, decision.status, decision.reason, decision.operation) == (
        EventType.OP_DECISION, "denied", "deadline_exceeded", LIST)
    assert graph.call_count == 0


@pytest.mark.parametrize("header", [
    None, "", "RunToken", "RunToken ", "Bearer {t}", "runtoken {t}", "RunToken  {t}", "RunToken {t} ",
    "RunToken {t}x", "RunToken " + "A" * 43,
])
async def test_invalid_run_tokens_refused_without_audit(sessionmaker, writer, admin_conn, tenant, key_path, graph,
                                                        header, caplog):
    run_id, token = await start_run(admin_conn, writer, tenant)
    before = await run_records(sessionmaker, tenant[0])
    value = header.format(t=token) if header else header
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(value, body())
    assert (result.status_code, result.body) == (401, {"status": "denied", "reason": "run_token_invalid"})
    assert await run_records(sessionmaker, tenant[0]) == before
    assert graph.call_count == 0
    assert "broker_run_refused reason=run_token_invalid" in caplog.text and token not in caplog.text


@pytest.mark.parametrize("status, reason", [("queued", "run_not_running"), ("halted", "run_halted")])
async def test_run_not_running_refused(sessionmaker, writer, admin_conn, tenant, key_path, graph, status, reason):
    run_id, token = await start_run(admin_conn, writer, tenant)
    if status == "queued":
        await admin_conn.execute("SET session_replication_role = replica")  # set-up only: bypass the guard
        try:
            await admin_conn.execute("UPDATE runs SET status = 'queued' WHERE id = $1", uuid.UUID(run_id))
        finally:
            await admin_conn.execute("SET session_replication_role = DEFAULT")
    else:
        await admin_conn.execute("UPDATE runs SET status = 'halted' WHERE id = $1", uuid.UUID(run_id))
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert (result.status_code, result.body) == (403, {"status": "denied", "reason": reason})
    assert graph.call_count == 0


async def test_run_token_cannot_select_tenant(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    other = await add_tenant(admin_conn)
    run_id, token = await start_run(admin_conn, writer, tenant)
    async with sessionmaker() as session:
        ctx = await resolve_run(session, token, catalog=CATALOG, now=datetime.now(timezone.utc))
    assert (ctx.tenant_id, ctx.run_id) == (tenant[0], run_id)

    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(
        auth(token), body(tenant_id=other[0]))
    assert result.body == {"status": "denied", "reason": "unknown_field"}
    assert (await run_records(sessionmaker, tenant[0], run_id))[-1].reason == "unknown_field"
    assert await run_records(sessionmaker, other[0]) == []


async def test_tenant_isolation_across_runs_execution_and_audit(sessionmaker, writer, admin_conn, key_path, graph):
    a, b = await add_tenant(admin_conn), await add_tenant(admin_conn)
    run_a, token_a = await start_run(admin_conn, writer, a)
    run_b, token_b = await start_run(admin_conn, writer, b)
    run_a2, token_a2 = await start_run(admin_conn, writer, a)
    graph.mock(return_value=page())
    factory = FakeMsal()
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, factory=factory)

    for token in (token_a, token_b, token_a, token_a2):
        assert (await svc.handle_request(auth(token), body())).status_code == 200

    # Each token acquires credentials for its own run's tenant only.
    assert {authority.rsplit("/", 1)[1] for authority in factory.authorities} == {a[0], b[0]}
    chain_a, chain_b = await run_records(sessionmaker, a[0]), await run_records(sessionmaker, b[0])
    assert {r.run_id for r in chain_a} == {run_a, run_a2} and {r.run_id for r in chain_b} == {run_b}
    assert all(r.tenant_id == a[0] for r in chain_a) and all(r.tenant_id == b[0] for r in chain_b)
    # Attempt numbers are per run, continuing across operations of the same run.
    attempts = {run: [r.attempt for r in chain_a + chain_b if r.run_id == run and r.event_type == "GRAPH_REQUEST"]
                for run in (run_a, run_b, run_a2)}
    assert attempts == {run_a: [1, 2], run_b: [1], run_a2: [1]}
    assert (await _valid(sessionmaker, a[0])).valid and (await _valid(sessionmaker, b[0])).valid


async def test_manifest_changed_fails_the_run(sessionmaker, writer, admin_conn, tenant, key_path, graph, tmp_path):
    run_id, token = await start_run(admin_conn, writer, tenant)
    source = (REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml").read_text()
    (tmp_path / "manifest.yaml").write_text(source.replace("timeout_seconds: 300", "timeout_seconds: 301"),
                                            encoding="utf-8")
    edited = load_manifest(tmp_path / "manifest.yaml", profiles_dir=REPO / "profiles")
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, catalog={edited.id: edited})

    result = await svc.handle_request(auth(token), body())

    assert result.body == {"status": "denied", "reason": "manifest_changed"}
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert [(r.event_type, r.reason) for r in records[2:]] == [
        (EventType.OP_DECISION, "manifest_changed"), (EventType.RUN_FAILED, "manifest_changed")]
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("failed", "manifest_changed", None)
    assert graph.call_count == 0
    assert (await _valid(sessionmaker, tenant[0])).valid


@pytest.mark.parametrize("catalog", [{}, {"other-task": MANIFEST}])
async def test_task_missing_from_catalog_fails_the_run(sessionmaker, writer, admin_conn, tenant, key_path, graph,
                                                       catalog):
    run_id, token = await start_run(admin_conn, writer, tenant)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer, catalog=catalog).handle_request(
        auth(token), body())
    assert result.body == {"status": "denied", "reason": "manifest_changed"}
    assert graph.call_count == 0


async def test_profile_changed_fails_the_run(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant, profile_sha256="0" * 64)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "denied", "reason": "manifest_changed"}
    assert (await run_row(admin_conn, run_id))["status"] == "failed"
    assert graph.call_count == 0


# -------------------------------------------------------------- credentials


@pytest.mark.parametrize("claims, reason", [
    ({"roles": ["AuditLog.Read.All", "User.Read.All", "User.ReadWrite.All"]}, "permissions_extra"),
    ({"roles": ["User.Read.All"]}, "permissions_missing"),
    ({"tid": "99999999-2222-4333-8444-555555555555"}, "tid_mismatch"),
    ({"appid": "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"}, "appid_mismatch"),
    ({"aud": "https://management.azure.com"}, "aud_mismatch"),
    ({"scp": "User.Read"}, "not_app_token"),
    ({"exp": 1}, "acquisition_failed"),
])
async def test_credential_rejected_fails_run(sessionmaker, writer, admin_conn, tenant, key_path, graph, claims,
                                             reason):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, factory=FakeMsal(**claims))

    result = await svc.handle_request(auth(token), body())

    assert (result.status_code, result.body) == (502, {"status": "failed", "reason": "credential_rejected"})
    assert graph.call_count == 0  # a policy allow does not make a bad token acceptable
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert [(r.event_type, r.status, r.reason) for r in records[2:]] == [
        (EventType.OP_DECISION, "allowed", "allowed"), (EventType.CREDENTIAL_REJECTED, "rejected", reason),
        (EventType.RUN_FAILED, "failed", reason)]
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("failed", reason, None)
    assert (await svc.handle_request(auth(token), body())).body["reason"] == "run_token_invalid"
    assert (await _valid(sessionmaker, tenant[0])).valid


async def test_missing_credential_configuration_fails_run(sessionmaker, writer, admin_conn, tenant, tmp_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=tmp_path / "absent.pem", writer=writer)
    result = await svc.handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "credential_rejected"}
    assert (await run_records(sessionmaker, tenant[0], run_id))[-2].reason == "acquisition_failed"
    assert graph.call_count == 0


async def test_a_token_carrying_write_roles_does_not_change_a_denial(sessionmaker, writer, admin_conn, tenant,
                                                                     key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    factory = FakeMsal(roles=["User.ReadWrite.All", "Directory.ReadWrite.All"])
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, factory=factory)
    result = await svc.handle_request(auth(token), body("users.update", {"user_id": str(uuid.uuid4())}))
    assert result.body == {"status": "denied", "reason": "prohibited"}
    assert factory.issued == [] and graph.call_count == 0


class StubProvider:
    def __init__(self, outcome):
        self.outcome, self.calls = outcome, []

    async def token_for(self, *, tenant_id, profile):
        self.calls.append(tenant_id)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


@pytest.mark.parametrize("outcome", [ValueError("caller error"), "a plain string token", None])
async def test_provider_failures_and_non_validated_tokens_are_rejected(sessionmaker, writer, admin_conn, tenant,
                                                                       key_path, graph, outcome):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    svc._credentials = StubProvider(outcome)
    result = await svc.handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "credential_rejected"}
    assert (await run_records(sessionmaker, tenant[0], run_id))[-2].reason == "acquisition_failed"
    assert graph.call_count == 0


# ----------------------------------------------------- retries and pagination


async def test_retry_is_reauthorized_and_audited_per_attempt(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [httpx.Response(429, headers={"Retry-After": "1"}), page()]
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())

    assert result.status_code == 200 and graph.call_count == 2
    records = (await run_records(sessionmaker, tenant[0], run_id))[2:]
    assert kinds(records) == [EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_REQUEST,
                              EventType.GRAPH_RESPONSE, EventType.OP_DECISION, EventType.GRAPH_REQUEST,
                              EventType.GRAPH_RESPONSE]
    d1, _, r1, s1, d2, r2, s2 = records
    assert (r1.attempt, r1.decision_seq, s1.attempt, s1.status, s1.reason, s1.http_status) == (
        1, d1.seq, 1, "failed", "http_429", 429)
    assert d2.details == {"request_target": TARGET, "for_attempt": 2}
    assert (r2.attempt, r2.decision_seq, r2.request_target, s2.attempt, s2.status) == (2, d2.seq, TARGET, 2, "succeeded")
    assert (await _valid(sessionmaker, tenant[0])).complete


async def test_each_page_has_its_own_decision_attempt_and_response(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                   graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [page([{"id": "1"}], URL + "&$skiptoken=page2"), page([{"id": "2"}], URL + "&$skiptoken=page3"),
                         page([{"id": "3"}])]
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())

    assert result.body == {"status": "ok", "data": [{"id": "1"}, {"id": "2"}, {"id": "3"}]}
    sent = [call.request.url.raw_path.decode() for call in graph.calls]
    assert sent == [TARGET, TARGET + "&$skiptoken=page2", TARGET + "&$skiptoken=page3"]
    records = await run_records(sessionmaker, tenant[0], run_id)
    requests = [r for r in records if r.event_type == EventType.GRAPH_REQUEST]
    decisions = {r.seq: r for r in records if r.event_type == EventType.OP_DECISION}
    assert [r.request_target for r in requests] == sent and [r.attempt for r in requests] == [1, 2, 3]
    assert len({r.decision_seq for r in requests}) == 3
    assert all(decisions[r.decision_seq].details["request_target"] == TARGET for r in requests)
    assert all(call.request.headers["Authorization"].startswith("Bearer ") for call in graph.calls)
    assert (await _valid(sessionmaker, tenant[0])).complete


async def test_reauthorization_denial_stops_paging(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    class SecondTimeDenies(AllowlistPolicyEngine):
        calls = 0

        def authorize_operation(self, manifest, op_name, params):
            SecondTimeDenies.calls += 1
            if SecondTimeDenies.calls > 1:
                return Decision(False, "not_in_manifest"), None
            return super().authorize_operation(manifest, op_name, params)

    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [page([{"id": "1"}], URL + "&$skiptoken=page2"), page([{"id": "2"}])]
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, engine=SecondTimeDenies())
    result = await svc.handle_request(auth(token), body())

    assert result.body == {"status": "denied", "reason": "not_in_manifest"} and "data" not in result.body
    assert graph.call_count == 1
    last = (await run_records(sessionmaker, tenant[0], run_id))[-1]
    assert (last.event_type, last.status, last.reason, last.details) == (
        EventType.OP_DECISION, "denied", "not_in_manifest", {"for_attempt": 2})
    assert (await _valid(sessionmaker, tenant[0])).complete


async def test_second_operation_continues_the_runs_attempt_numbers(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                    graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [httpx.Response(503), page(), page()]
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    assert (await svc.handle_request(auth(token), body())).status_code == 200
    assert (await svc.handle_request(auth(token), body())).status_code == 200
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert [r.attempt for r in records if r.event_type == EventType.GRAPH_REQUEST] == [1, 2, 3]
    assert [r.attempt for r in records if r.event_type == EventType.GRAPH_RESPONSE] == [1, 2, 3]
    assert (await _valid(sessionmaker, tenant[0])).complete


async def test_concurrent_operations_of_one_run_are_serialized(sessionmaker, writer, admin_conn, tenant, key_path,
                                                               graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    results = await asyncio.gather(*(svc.handle_request(auth(token), body()) for _ in range(4)))
    assert [r.status_code for r in results] == [200] * 4
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert [r.attempt for r in records if r.event_type == EventType.GRAPH_REQUEST] == [1, 2, 3, 4]
    assert (await _valid(sessionmaker, tenant[0])).complete


# ---------------------------------------------------- execution failures


async def test_non_premium_tenant_fails_run_licence_required(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=httpx.Response(403, json={"error": {"code": LICENCE, "message": "x"}},
                                           headers={"request-id": "abc-123"}))
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())

    assert (result.status_code, result.body) == (502, {"status": "failed", "reason": "licence_required"})
    assert graph.call_count == 1  # not retried
    records = (await run_records(sessionmaker, tenant[0], run_id))[-2:]
    assert (records[0].status, records[0].reason, records[0].http_status) == ("failed", "http_403", 403)
    assert (records[1].event_type, records[1].reason, records[1].details) == (
        EventType.RUN_FAILED, "licence_required",
        {"http_status": 403, "graph_error_code": LICENCE, "graph_request_id": "abc-123"})
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("failed", "licence_required", None)
    report = await _valid(sessionmaker, tenant[0])
    assert report.valid and report.complete


async def test_later_page_failure_fails_run_and_withholds_earlier_pages(sessionmaker, writer, admin_conn, tenant,
                                                                        key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [page([{"id": "SENSITIVE-PAGE-ONE"}], URL + "&$skiptoken=p2"), httpx.Response(400)]
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    result = await svc.handle_request(auth(token), body())

    assert result.body == {"status": "failed", "reason": "bad_request"}
    assert "SENSITIVE-PAGE-ONE" not in json.dumps(result.body)
    responses = [r for r in await run_records(sessionmaker, tenant[0], run_id) if r.event_type == "GRAPH_RESPONSE"]
    assert [(r.attempt, r.status, r.reason) for r in responses] == [(1, "succeeded", None), (2, "failed", "http_400")]
    assert (await run_row(admin_conn, run_id))["status"] == "failed"
    assert (await svc.handle_request(auth(token), body())).body["reason"] == "run_token_invalid"  # revoked


async def test_network_failures_record_no_response_and_fail_run(sessionmaker, writer, admin_conn, tenant, key_path,
                                                                graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = httpx.ConnectError("refused")
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "network"}
    records = await run_records(sessionmaker, tenant[0], run_id)
    responses = [r for r in records if r.event_type == EventType.GRAPH_RESPONSE]
    assert [(r.attempt, r.reason, r.http_status) for r in responses] == [(n, "no_response", None) for n in (1, 2, 3, 4)]
    assert records[-1].event_type == EventType.RUN_FAILED and records[-1].reason == "network"
    assert (await _valid(sessionmaker, tenant[0])).complete


async def test_malformed_success_response_recorded_as_unusable(sessionmaker, writer, admin_conn, tenant, key_path,
                                                               graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=httpx.Response(200, content=b'{"value": "not a list"}'))
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "invalid_response"}
    response = [r for r in await run_records(sessionmaker, tenant[0], run_id) if r.event_type == "GRAPH_RESPONSE"][0]
    assert (response.status, response.reason, response.http_status, response.details) == (
        "failed", "unusable_response", None, {"received_http_status": 200})
    assert (await _valid(sessionmaker, tenant[0])).valid


async def test_foreign_next_link_fails_run_without_following(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page(next_link="https://evil.example/v1.0/users?$skiptoken=x"))
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "invalid_next_link"} and graph.call_count == 1
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert records[-1].reason == "invalid_next_link"
    assert [r.request_target for r in records if r.event_type == "GRAPH_REQUEST"] == [TARGET]


async def test_deadline_reached_during_retries_fails_run(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant,
                                    deadline=datetime.now(timezone.utc) + timedelta(seconds=20))
    graph.mock(return_value=httpx.Response(429, headers={"Retry-After": "99999"}))
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "deadline_exceeded"} and graph.call_count == 1
    assert (await run_row(admin_conn, run_id))["outcome"] == "deadline_exceeded"


async def test_no_attempt_recorded_when_the_transport_refuses_before_sending(sessionmaker, writer, admin_conn, tenant,
                                                                             key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    svc._credentials = StubProvider(ValidatedToken(
        access_token="not a bearer-safe token", expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        permissions=frozenset()))
    result = await svc.handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "invalid_request"}
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert EventType.GRAPH_REQUEST not in kinds(records)  # no evidence of an attempt that never happened
    assert graph.call_count == 0


# ------------------------------------------------------------- evidence hygiene


async def test_audit_distinguishes_decision_attempt_response(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [httpx.Response(504), page()]
    svc = make_service(sessionmaker, key_path=key_path, writer=writer)
    await svc.handle_request(auth(token), body("users.update", {"user_id": str(uuid.uuid4())}))
    await svc.handle_request(auth(token), body())
    records = (await run_records(sessionmaker, tenant[0], run_id))[2:]
    assert kinds(records) == [
        EventType.OP_DECISION,  # the denial: nothing else
        EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_REQUEST, EventType.GRAPH_RESPONSE,
        EventType.OP_DECISION, EventType.GRAPH_REQUEST, EventType.GRAPH_RESPONSE,
    ]
    decision_fields = {"http_status", "graph_request_id", "attempt", "item_count", "duration_ms", "request_target"}
    for decision in (r for r in records if r.event_type == EventType.OP_DECISION):
        assert all(getattr(decision, f) is None for f in decision_fields)  # a decision claims no attempt
    report = await _valid(sessionmaker, tenant[0])
    assert report.valid and report.complete


async def test_audit_contains_no_tokens(sessionmaker, writer, admin_conn, tenant, key_path, graph, caplog):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.side_effect = [httpx.Response(429), page()]
    factory = FakeMsal()
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, factory=factory)
    await svc.handle_request(auth(token), body())
    await svc.handle_request(auth(token), body("users.update", {"user_id": str(uuid.uuid4())}))
    rows = await admin_conn.fetch("SELECT * FROM audit_events WHERE chain_id = $1", tenant[0])
    dump = json.dumps([dict(r) for r in rows], default=str)
    assert factory.issued and all(t not in dump for t in factory.issued)
    assert "eyJ" not in dump and "Bearer" not in dump and token not in dump
    assert token not in caplog.text and all(t not in caplog.text for t in factory.issued)
    row = await run_row(admin_conn, run_id)
    assert token not in json.dumps(dict(row), default=str)  # only its SHA-256 is stored


# ------------------------------------------------------------------ HTTP layer


@pytest.fixture
def client_for(sessionmaker, writer, key_path):
    def make(**kwargs):
        app = create_app(make_service(sessionmaker, key_path=key_path, writer=writer, **kwargs))
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://broker")

    return make


async def test_http_endpoint_allows_and_denies(sessionmaker, writer, admin_conn, tenant, key_path, graph, client_for):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page())
    async with client_for() as client:
        ok = await client.post("/v1/ops", content=body(), headers={"Authorization": auth(token)})
        denied = await client.post("/v1/ops", content=body(path="/users/x"), headers={"Authorization": auth(token)})
        anonymous = await client.post("/v1/ops", content=body())
        doubled = await client.post("/v1/ops", content=body(),
                                    headers=[("Authorization", auth(token)), ("Authorization", auth(token))])
    assert (ok.status_code, ok.json()) == (200, {"status": "ok", "data": USERS})
    assert ok.headers["cache-control"] == "no-store"
    assert (denied.status_code, denied.json()) == (403, {"status": "denied", "reason": "unknown_field"})
    assert (anonymous.status_code, anonymous.json()["reason"]) == (401, "run_token_invalid")
    assert (doubled.status_code, doubled.json()["reason"]) == (401, "run_token_invalid")
    assert graph.call_count == 1


async def test_http_oversized_body_denied_and_audited(sessionmaker, writer, admin_conn, tenant, graph, client_for):
    run_id, token = await start_run(admin_conn, writer, tenant)
    huge = json.dumps({"op": LIST, "params": {"pad": "x" * (64 * 1024)}}).encode()
    async with client_for() as client:
        response = await client.post("/v1/ops", content=huge, headers={"Authorization": auth(token)})
    assert (response.status_code, response.json()["reason"]) == (403, "invalid_request")
    assert (await run_records(sessionmaker, tenant[0], run_id))[-1].reason == "invalid_request"
    assert graph.call_count == 0


async def test_http_has_no_other_routes(client_for):
    async with client_for() as client:
        for method, path in (("GET", "/v1/ops"), ("GET", "/docs"), ("GET", "/openapi.json"), ("POST", "/v1/graph"),
                             ("POST", "/v1/ops/users")):
            assert (await client.request(method, path)).status_code in (404, 405)


# ------------------------------------------------- hook protocol and run row


class Scripted:
    """A transport that calls the hooks in a given order, then returns no data."""

    def __init__(self, steps):
        self.steps = steps

    async def execute(self, request, token, *, deadline, before_attempt, after_attempt):
        for hook, number in self.steps:
            status, items = (None, None) if hook == "before" else (200, 0)
            await (before_attempt if hook == "before" else after_attempt)(
                GraphAttempt(number, "GET", request_target(request), status, None, 1, items))
        return []


@pytest.mark.parametrize("steps", [
    [("before", 1), ("before", 2)],  # a second attempt while the first is unanswered
    [("before", 1), ("after", 2)],  # an answer for an attempt never announced
    [("before", 1), ("after", 1), ("after", 1)],  # a duplicate answer
    [("after", 1)],  # an answer with no request
    [("before", 2)],  # attempts must start at 1
])
async def test_hook_protocol_violations_fail_the_run(sessionmaker, writer, admin_conn, tenant, key_path, graph, steps):
    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, transport=Scripted(steps))
    result = await svc.handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "request_binding_mismatch"}
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert kinds(records).count(EventType.GRAPH_REQUEST) <= 1 and kinds(records).count(EventType.GRAPH_RESPONSE) <= 1
    assert records[-1].event_type == EventType.RUN_FAILED
    assert (await _valid(sessionmaker, tenant[0])).valid


async def test_a_well_behaved_scripted_transport_is_accepted(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)
    steps = [("before", 1), ("after", 1), ("before", 2), ("after", 2)]
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, transport=Scripted(steps))
    assert (await svc.handle_request(auth(token), body())).body == {"status": "ok", "data": []}
    assert (await _valid(sessionmaker, tenant[0])).complete


@pytest.mark.parametrize("row", [
    {"profile_id": "another-profile"}, {"profile_version": 2}, {"auth_mode": "delegated"},
    {"task_manifest_sha256": "f" * 64}, {"task_id": "another-task"},
])
async def test_run_row_must_match_the_catalog_manifest(sessionmaker, writer, admin_conn, tenant, key_path, graph, row):
    run_id, token = await start_run(admin_conn, writer, tenant, row=row)
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "denied", "reason": "manifest_changed"}
    assert graph.call_count == 0


async def test_run_ended_elsewhere_during_an_operation_is_not_failed_again(sessionmaker, writer, admin_conn, tenant,
                                                                           key_path, graph):
    run_id, token = await start_run(admin_conn, writer, tenant)

    async def runner_times_out(request):
        await admin_conn.execute("UPDATE runs SET status = 'timed_out', run_token_sha256 = NULL, ended_at = now() "
                                 "WHERE id = $1", uuid.UUID(run_id))
        return httpx.Response(400)

    graph.side_effect = runner_times_out
    result = await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(auth(token), body())
    assert result.body == {"status": "failed", "reason": "bad_request"}
    assert EventType.RUN_FAILED not in kinds(await run_records(sessionmaker, tenant[0], run_id))
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"]) == ("timed_out", None)


async def test_http_body_is_not_read_past_the_limit(sessionmaker, writer, admin_conn, tenant, graph, client_for):
    run_id, token = await start_run(admin_conn, writer, tenant)
    produced = []

    async def endless():
        for _ in range(10_000):
            produced.append(1)
            yield b"x" * 1024

    async with client_for() as client:
        response = await client.post("/v1/ops", content=endless(), headers={"Authorization": auth(token)})
    assert (response.status_code, response.json()["reason"]) == (403, "invalid_request")
    assert len(produced) < 200  # stopped at about 64 KiB, not 10 MiB
    assert (await run_records(sessionmaker, tenant[0], run_id))[-1].reason == "invalid_request"


async def test_http_declared_oversize_body_is_not_read(sessionmaker, writer, admin_conn, tenant, graph, client_for):
    run_id, token = await start_run(admin_conn, writer, tenant)
    produced = []

    async def small():
        produced.append(1)
        yield body()

    async with client_for() as client:
        response = await client.post("/v1/ops", content=small(),
                                     headers={"Authorization": auth(token), "Content-Length": str(10 * 1024 * 1024)})
    assert response.json()["reason"] == "invalid_request"
    assert produced == []  # refused on the declared length, before reading


async def test_attempt_numbers_ignore_other_chains_and_forged_responses(sessionmaker, writer, admin_conn, tenant,
                                                                        key_path, graph):
    """The run's attempt numbering comes from its own GRAPH_REQUEST records on
    its own tenant's chain only. Records naming the run elsewhere (another
    tenant's chain) or of another kind cannot shift it."""
    other = await add_tenant(admin_conn)
    run_id, token = await start_run(admin_conn, writer, tenant)
    await writer.append(chain_id=other[0], event={
        "tenant_id": other[0], "event_type": EventType.GRAPH_REQUEST, "status": "attempted", "run_id": run_id,
        "operation": LIST, "decision_seq": 1, "http_method": "GET", "path_template": "/users",
        "request_target": TARGET, "attempt": 7})
    await writer.append(chain_id=tenant[0], event={
        "tenant_id": tenant[0], "event_type": EventType.GRAPH_RESPONSE, "status": "failed", "reason": "forged",
        "run_id": run_id, "operation": LIST, "attempt": 9, "duration_ms": 0})
    graph.mock(return_value=page())
    assert (await make_service(sessionmaker, key_path=key_path, writer=writer).handle_request(
        auth(token), body())).status_code == 200
    requests = [r for r in await run_records(sessionmaker, tenant[0], run_id) if r.event_type == "GRAPH_REQUEST"]
    assert [r.attempt for r in requests] == [1]


async def test_lookalike_attempt_objects_are_refused(sessionmaker, writer, admin_conn, tenant, key_path, graph):
    from collections import namedtuple

    Lookalike = namedtuple("Lookalike", "attempt method request_target http_status graph_request_id duration_ms "
                                        "item_count")

    class Imitating:
        async def execute(self, request, token, *, deadline, before_attempt, after_attempt):
            await before_attempt(Lookalike(1, "GET", request_target(request), None, None, 0, None))
            return [{"id": "never-fetched"}]

    run_id, token = await start_run(admin_conn, writer, tenant)
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, transport=Imitating())
    assert (await svc.handle_request(auth(token), body())).body == {"status": "failed",
                                                                     "reason": "request_binding_mismatch"}
    assert EventType.GRAPH_REQUEST not in kinds(await run_records(sessionmaker, tenant[0], run_id))


async def test_resolve_run_refuses_a_queued_run(sessionmaker, writer, admin_conn, tenant):
    from clw.broker.capability import RunRefused

    run_id, token = await start_run(admin_conn, writer, tenant)
    await admin_conn.execute("SET session_replication_role = replica")  # set-up only: bypass the guard
    try:
        await admin_conn.execute("UPDATE runs SET status = 'queued' WHERE id = $1", uuid.UUID(run_id))
    finally:
        await admin_conn.execute("SET session_replication_role = DEFAULT")
    async with sessionmaker() as session:
        with pytest.raises(RunRefused) as info:
            await resolve_run(session, token, catalog=CATALOG, now=datetime.now(timezone.utc))
    assert (info.value.reason, info.value.run) == ("run_not_running", None)


async def test_catalog_entry_for_the_task_must_be_that_tasks_manifest(sessionmaker, writer, admin_conn, tenant,
                                                                      key_path, graph):
    # The row names task "another-task"; the catalog files the dormant manifest under that key.
    run_id, token = await start_run(admin_conn, writer, tenant, row={"task_id": "another-task"})
    svc = make_service(sessionmaker, key_path=key_path, writer=writer, catalog={"another-task": MANIFEST})
    assert (await svc.handle_request(auth(token), body())).body == {"status": "denied", "reason": "manifest_changed"}
    assert graph.call_count == 0
