"""The Graph facade inside the broker (SD-041), against real Postgres: write-ahead
audit, RR-5-bound targets, broker-held paging, Graph-shaped refusals, fail closed.

Graph is mocked with respx and credentials come from the fake MSAL app of the
broker tests; nothing reaches the network. Runs are started as for built-in
tasks; the script manifest is supplied directly (approvals arrive with M4)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from clw.audit.events import AuditUnavailable, EventType
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter
from clw.broker.facade.rules import load_script_manifest
from clw.broker.transport import GRAPH_ORIGIN
from tests.db.broker_fixtures import FakeMsal, add_tenant, kinds, make_service, run_records, run_row, start_run, write_key

pytestmark = pytest.mark.pg

MANIFEST = load_script_manifest({
    "schema_version": 1, "profile": "directory-read-auditlog-read",
    "entries": [{"id": "list-users", "method": "GET", "versions": ["beta", "v1.0"], "path": "/users",
                 "select": ["id", "displayName", "signInActivity"],
                 "filter": {"allowed": True, "properties": ["userType"]}, "top": 999, "count": True,
                 "consistency_level": True}],
})
FIRST = "/beta/users?$count=true&$select=id,displayname"
SKIP = "RFNwdAIAAQAAAB8"


def _graph_page(users, next_link=None, status=200):
    content = {"value": users} | ({"@odata.nextLink": next_link} if next_link else {})
    return httpx.Response(status, json=content, headers={"request-id": "aaaaaaaa-1111-2222-3333-444444444444"})


@pytest.fixture
async def facade(admin_conn, sessionmaker, tmp_path):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    run_id, token = await start_run(admin_conn, writer, tenant)

    async def manifests(session, row):
        return MANIFEST if str(row.id) == run_id else None

    service = make_service(sessionmaker, key_path=write_key(tmp_path), writer=writer, script_manifests=manifests)
    return service, tenant[0], run_id, token


async def call(service, token, target, *, method="GET", consistency=None, body_length=0):
    return await service.handle_facade(f"Bearer {token}", method, target,
                                       {"ConsistencyLevel": consistency} if consistency else {}, body_length)


async def _valid(sessionmaker, tid):
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=tid)
    return report.valid, report.intents_without_outcome


@respx.mock
async def test_an_allowed_request_passes_graph_through_with_write_ahead_audit(facade, sessionmaker):
    service, tid, run_id, token = facade
    route = respx.get(GRAPH_ORIGIN + FIRST).mock(return_value=_graph_page([{"id": "1"}]))
    reply = await call(service, token, "/beta/users?$select=id,%20displayName&$count=true", consistency="Eventual")
    assert reply.status_code == 200 and json.loads(reply.body) == {"value": [{"id": "1"}]}
    assert route.calls.last.request.headers["ConsistencyLevel"] == "eventual"
    records = await run_records(sessionmaker, tid, run_id)
    assert kinds(records)[2:] == ["OP_DECISION", "CREDENTIAL_ACQUIRED", "GRAPH_REQUEST", "GRAPH_RESPONSE"]
    decision, request = records[2], records[4]
    assert decision.operation == "facade.list-users" and decision.details["request_target"] == FIRST
    assert (request.request_target, request.path_template, request.decision_seq) == (FIRST, "/users", decision.seq)
    assert await _valid(sessionmaker, tid) == (True, ())


@respx.mock
async def test_paging_goes_through_broker_held_handles_bound_to_the_approval(facade, sessionmaker):
    service, tid, run_id, token = facade
    graph_next = f"{GRAPH_ORIGIN}/beta/users?$select=id,displayname&$count=true&$skiptoken={SKIP}"
    respx.get(GRAPH_ORIGIN + FIRST).mock(return_value=_graph_page([{"id": "1"}], graph_next))
    second = respx.get(GRAPH_ORIGIN + FIRST + f"&$skiptoken={SKIP}").mock(return_value=_graph_page([{"id": "2"}]))
    first_reply = await call(service, token, FIRST)
    link = json.loads(first_reply.body)["@odata.nextLink"]
    assert link.startswith(f"{GRAPH_ORIGIN}/beta/users?$skiptoken=clw_") and SKIP not in link
    reply = await call(service, token, link[len(GRAPH_ORIGIN):])
    assert json.loads(reply.body) == {"value": [{"id": "2"}]} and second.called
    records = await run_records(sessionmaker, tid, run_id)
    requests = [r for r in records if r.event_type == EventType.GRAPH_REQUEST]
    assert [r.request_target for r in requests] == [FIRST, FIRST + f"&$skiptoken={SKIP}"]
    assert len({r.decision_seq for r in requests}) == 2  # each page re-authorized
    assert await _valid(sessionmaker, tid) == (True, ())
    again = await call(service, token, link[len(GRAPH_ORIGIN):])  # a handle is single-use
    assert again.status_code == 403 and json.loads(again.body)["error"]["innerError"]["clw-reason"] == "continuation_invalid"


@pytest.mark.parametrize("method", ["PATCH", "DELETE", "POST"])
@pytest.mark.respx(assert_all_called=False)
async def test_a_write_is_refused_audited_and_never_sent(facade, sessionmaker, method, respx_mock):
    service, tid, run_id, token = facade
    graph = respx_mock.route().mock(return_value=httpx.Response(204))
    reply = await call(service, token, "/v1.0/users/00000000-0000-0000-0000-000000000001?secret=x",
                       method=method, body_length=27)
    error = json.loads(reply.body)["error"]
    assert reply.status_code == 403 and error["code"] == "Authorization_RequestDenied"
    assert error["innerError"]["clw-reason"] == "method_not_allowed" and not graph.called
    decision = (await run_records(sessionmaker, tid, run_id))[-1]
    assert (decision.event_type, decision.status, decision.reason) == ("OP_DECISION", "denied", "method_not_allowed")
    assert decision.details == {"method": method, "path": "/v1.0/users/00000000-0000-0000-0000-000000000001"}
    assert "secret" not in json.dumps(decision.details)  # the query text is never recorded


@pytest.mark.parametrize("target, reason", [
    ("/v1.0/users?$select=id,mail", "select_not_allowed"),
    ("/v1.0/groups?$select=id", "not_in_manifest"),
    ("/v1.0/$batch", "batch_not_allowed"),
    ("/beta/users?$select=id&$skiptoken=clw_forged", "continuation_tampered"),
    ("/beta/users?$skiptoken=clw_forged", "continuation_invalid"),
    ("/beta/users?$select=id&$skiptoken=RFNwdAI", "continuation_tampered"),
])
@pytest.mark.respx(assert_all_called=False)
async def test_denials_are_graph_shaped_and_nothing_is_sent(facade, target, reason, respx_mock):
    service, _, _, token = facade
    graph = respx_mock.route().mock(return_value=httpx.Response(200, json={"value": []}))
    reply = await call(service, token, target)
    assert reply.status_code == 403 and json.loads(reply.body)["error"]["innerError"]["clw-reason"] == reason
    assert not graph.called


@pytest.mark.respx(assert_all_called=False)
async def test_an_unknown_parameter_is_refused_by_name_and_its_value_never_recorded(facade, sessionmaker, respx_mock):
    service, tid, run_id, token = facade
    graph = respx_mock.route().mock(return_value=_graph_page([]))
    reply = await call(service, token, "/beta/users?$count=true&$%09op=999&$select=id,displayName&mode=SECRETVALUE")
    error = json.loads(reply.body)["error"]
    assert reply.status_code == 403 and not graph.called
    assert error["innerError"] == {"clw-reason": "unknown_query_parameter", "clw-parameter": "$\\x09op"}
    assert "$\\x09op" in error["message"]
    decision = [r for r in await run_records(sessionmaker, tid, run_id) if r.event_type == EventType.OP_DECISION][-1]
    assert (decision.status, decision.reason, decision.details["parameter"]) == (
        "denied", "unknown_query_parameter", "$\\x09op")
    assert "999" not in json.dumps(decision.details) and "SECRETVALUE" not in json.dumps(decision.details)


@respx.mock
async def test_a_graph_error_reaches_the_script_and_the_run_continues(facade, sessionmaker, admin_conn):
    service, tid, run_id, token = facade
    respx.get(GRAPH_ORIGIN + FIRST).mock(return_value=httpx.Response(
        404, json={"error": {"code": "Request_ResourceNotFound", "message": "x"}}))
    reply = await call(service, token, FIRST)
    assert reply.status_code == 404 and json.loads(reply.body)["error"]["code"] == "Request_ResourceNotFound"
    assert (await run_row(admin_conn, run_id))["status"] == "running"
    assert await _valid(sessionmaker, tid) == (True, ())


@respx.mock
async def test_a_foreign_next_link_fails_the_run(facade, admin_conn):
    service, _, run_id, token = facade
    respx.get(GRAPH_ORIGIN + FIRST).mock(return_value=_graph_page([{"id": "1"}], "https://evil.example/beta/users?$skiptoken=x"))
    reply = await call(service, token, FIRST)
    assert reply.status_code == 502 and "evil" not in reply.body.decode()
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"]) == ("failed", "invalid_next_link")


@pytest.mark.respx(assert_all_called=False)
async def test_an_over_consented_token_fails_the_run_before_any_request(admin_conn, sessionmaker, tmp_path, respx_mock):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    run_id, token = await start_run(admin_conn, writer, tenant)

    async def manifests(session, row):
        return MANIFEST

    service = make_service(sessionmaker, key_path=write_key(tmp_path), writer=writer, script_manifests=manifests,
                           factory=FakeMsal(roles=["AuditLog.Read.All", "User.Read.All", "User.ReadWrite.All"]))
    graph = respx_mock.route().mock(return_value=httpx.Response(200, json={"value": []}))
    reply = await call(service, token, FIRST)
    assert reply.status_code == 502 and not graph.called
    assert (await run_row(admin_conn, run_id))["outcome"] == "permissions_extra"


@pytest.mark.respx(assert_all_called=False)
async def test_an_audit_failure_before_sending_halts_the_run_and_sends_nothing(facade, admin_conn, respx_mock):
    service, _, run_id, token = facade
    real_append = service._writer.append

    async def failing(*, chain_id, event):
        if event["event_type"] == EventType.GRAPH_REQUEST:
            raise AuditUnavailable("down")
        return await real_append(chain_id=chain_id, event=event)

    service._writer.append = failing
    graph = respx_mock.route().mock(return_value=httpx.Response(200, json={"value": []}))
    reply = await call(service, token, FIRST)
    assert reply.status_code == 503 and not graph.called
    assert (await run_row(admin_conn, run_id))["status"] == "halted"


async def test_a_run_without_an_approved_script_manifest_is_refused(admin_conn, sessionmaker, tmp_path):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    _, token = await start_run(admin_conn, writer, tenant)

    async def none(session, row):
        return None

    service = make_service(sessionmaker, key_path=write_key(tmp_path), writer=writer, script_manifests=none)
    reply = await call(service, token, FIRST)
    assert reply.status_code == 403 and json.loads(reply.body)["error"]["innerError"]["clw-reason"] == "not_a_script_run"


@pytest.mark.parametrize("authorization", [None, "", "Bearer", "Bearer short", "RunToken " + "a" * 43, "Basic x"])
async def test_a_missing_or_malformed_capability_is_401(facade, authorization):
    service, _, _, _ = facade
    reply = await service.handle_facade(authorization, "GET", FIRST, {}, 0)
    assert reply.status_code == 401


async def test_without_a_manifest_source_the_facade_is_disabled(sessionmaker, tmp_path):
    service = make_service(sessionmaker, key_path=write_key(tmp_path))
    reply = await service.handle_facade("Bearer " + "a" * 43, "GET", FIRST, {}, 0)
    assert reply.status_code == 403 and json.loads(reply.body)["error"]["innerError"]["clw-reason"] == "facade_disabled"


@respx.mock
async def test_a_continuation_is_refused_once_the_approved_manifest_no_longer_allows_it(admin_conn, sessionmaker,
                                                                                        tmp_path):
    tenant = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    run_id, token = await start_run(admin_conn, writer, tenant)
    narrowed = load_script_manifest({**MANIFEST.document, "entries": [
        {**MANIFEST.document["entries"][0], "select": ["id"]}]})
    current = {"manifest": MANIFEST}

    async def manifests(session, row):
        return current["manifest"]

    service = make_service(sessionmaker, key_path=write_key(tmp_path), writer=writer, script_manifests=manifests)
    graph_next = f"{GRAPH_ORIGIN}/beta/users?$select=id,displayname&$count=true&$skiptoken={SKIP}"
    respx.get(GRAPH_ORIGIN + FIRST).mock(return_value=_graph_page([{"id": "1"}], graph_next))
    second = respx.get(GRAPH_ORIGIN + FIRST + f"&$skiptoken={SKIP}").mock(return_value=_graph_page([]))
    link = json.loads((await call(service, token, FIRST)).body)["@odata.nextLink"]
    current["manifest"] = narrowed  # the approval no longer allows displayName
    reply = await call(service, token, link[len(GRAPH_ORIGIN):])
    assert reply.status_code == 403 and json.loads(reply.body)["error"]["innerError"]["clw-reason"] == "select_not_allowed"
    assert not second.called


# ------------------------------------------------------------ SD-042: hashed free text

FILTERED = "/beta/users?$filter=userType%20eq%20'Member'&$select=id"


@respx.mock
async def test_filter_values_are_recorded_only_as_keyed_hashes(facade, sessionmaker, admin_conn):
    from clw.broker.facade.hashing import digest_for

    service, tid, run_id, token = facade
    sent = respx.get(GRAPH_ORIGIN + FILTERED).mock(return_value=_graph_page([{"id": "1"}]))
    reply = await call(service, token, "/beta/users?$select=id&$filter=userType%20eq%20'Member'")
    assert reply.status_code == 200 and sent.called  # Graph receives the real filter
    records = await run_records(sessionmaker, tid)
    everything = json.dumps([r.__dict__ if hasattr(r, "__dict__") else [getattr(r, f) for f in r.__dataclass_fields__]
                             for r in records], default=str)
    assert "Member" not in everything and "userType%20eq" not in everything
    digest = await digest_for(sessionmaker, tid, "$filter", "userType eq 'Member'")
    decision = [r for r in records if r.event_type == EventType.OP_DECISION][-1]
    request = [r for r in records if r.event_type == EventType.GRAPH_REQUEST][-1]
    assert decision.details["request_target"] == f"/beta/users?$filter={digest}&$select=id"
    assert request.request_target == decision.details["request_target"]
    assert await _valid(sessionmaker, tid) == (True, ())


@respx.mock
async def test_deleting_a_tenants_key_starts_a_new_one(facade, sessionmaker, admin_conn):
    service, tid, run_id, token = facade
    respx.get(GRAPH_ORIGIN + FILTERED).mock(return_value=_graph_page([]))
    await call(service, token, FILTERED)
    first_key = await admin_conn.fetchval("SELECT key_id FROM audit_value_keys WHERE tenant_id = $1", tid)
    await admin_conn.execute("DELETE FROM audit_value_keys WHERE tenant_id = $1", tid)  # the owner shreds it
    service._facade._keys.forget(tid)
    await call(service, token, FILTERED)
    second_key = await admin_conn.fetchval("SELECT key_id FROM audit_value_keys WHERE tenant_id = $1", tid)
    assert first_key and second_key and first_key != second_key


@pytest.mark.respx(assert_all_called=False)
async def test_without_a_value_key_nothing_is_sent_and_the_run_halts(facade, admin_conn, respx_mock):
    service, _, run_id, token = facade

    async def unavailable(sessionmaker, tenant_id):
        raise RuntimeError("key store down")

    service._facade._keys.get = unavailable
    graph = respx_mock.route().mock(return_value=_graph_page([]))
    reply = await call(service, token, FILTERED)
    assert reply.status_code == 503 and not graph.called
    assert (await run_row(admin_conn, run_id))["status"] == "halted"


@respx.mock
async def test_the_cli_reproduces_a_recorded_digest(facade, sessionmaker, monkeypatch, capsys):
    import asyncio

    from clw.cli import OK, main
    from clw.common import config
    from clw.db import session as db_session
    from tests.db.conftest import _sqlalchemy_url

    service, tid, _, token = facade
    respx.get(GRAPH_ORIGIN + FILTERED).mock(return_value=_graph_page([]))
    await call(service, token, FILTERED)
    recorded = [r for r in await run_records(sessionmaker, tid) if r.event_type == EventType.OP_DECISION][-1]
    url = sessionmaker.kw["bind"].url.render_as_string(hide_password=False)
    monkeypatch.setenv("DATABASE_URL", url)
    config.get_settings.cache_clear()
    db_session.get_sessionmaker.cache_clear()
    try:
        argv = ["audit-hash-value", "--chain", tid, "--option", "$filter", "--value", "userType eq 'Member'"]
        assert await asyncio.to_thread(main, argv) == OK
    finally:
        config.get_settings.cache_clear()
        db_session.get_sessionmaker.cache_clear()
    digest = json.loads(capsys.readouterr().out)["digest"]
    assert f"$filter={digest}" in recorded.details["request_target"]


@respx.mock
async def test_after_a_broker_restart_the_next_page_is_a_prompt_graph_error_not_a_hang(facade, sessionmaker,
                                                                                       tmp_path):
    import time

    service, tid, run_id, token = facade
    graph_next = f"{GRAPH_ORIGIN}/beta/users?$select=id,displayname&$count=true&$skiptoken={SKIP}"
    respx.get(GRAPH_ORIGIN + FIRST).mock(return_value=_graph_page([{"id": "1"}], graph_next))
    second = respx.get(GRAPH_ORIGIN + FIRST + f"&$skiptoken={SKIP}").mock(return_value=_graph_page([]))
    link = json.loads((await call(service, token, FIRST)).body)["@odata.nextLink"]

    restarted = make_service(sessionmaker, key_path=write_key(tmp_path), writer=service._writer,
                             script_manifests=service._facade._manifests)  # a new process: no handles
    started = time.monotonic()
    reply = await call(restarted, token, link[len(GRAPH_ORIGIN):])
    assert time.monotonic() - started < 2
    error = json.loads(reply.body)["error"]
    assert (reply.status_code, error["code"], error["innerError"]["clw-reason"]) == (
        403, "Authorization_RequestDenied", "continuation_invalid")
    assert not second.called
