"""The task SDK and the Dormant Account task against the real broker (Task 13).

The SDK's synchronous HTTP client reaches the Task 12 broker app (ASGI, in
process) through a bridge onto the test's event loop. Real: the broker's
HTTP layer, run-token resolution, policy, credential validation, transport,
the runs table and the audit chain. Mocked: Graph (respx) and MSAL (unsigned
tokens). Nothing here shows real Microsoft Graph behaviour (A-02, A-03, A-17).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from clw.audit.events import EventType
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter
from clw.broker.app import create_app
from clw.broker.transport import GRAPH_ORIGIN
from clw_task_sdk.client import USER_FIELDS, BrokerError, GraphSecurityClient, OperationDenied
from clw_task_sdk.result import RESULT_PREFIX
from tasks.dormant_account_investigation.task import investigate, main
from tests.db.broker_fixtures import add_tenant, kinds, make_service, page, run_records, run_row, start_run, write_key

pytestmark = pytest.mark.pg

BROKER = "http://broker:8080"
NOW = datetime.now(timezone.utc)
SELECT = ",".join(sorted(USER_FIELDS))
TARGET = f"/v1.0/users?$select={SELECT}"
ONE_ATTEMPT = [EventType.OP_DECISION, EventType.CREDENTIAL_ACQUIRED, EventType.GRAPH_REQUEST, EventType.GRAPH_RESPONSE]


def stamp(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def graph_user(uid, *, enabled=True, created=400, success=None):
    return {"id": uid, "userPrincipalName": f"{uid}@contoso.test", "displayName": uid, "accountEnabled": enabled,
            "createdDateTime": stamp(created),
            "signInActivity": None if success is None else {"lastSuccessfulSignInDateTime": stamp(success)}}


class LoopBridge(httpx.BaseTransport):
    """Synchronous transport that runs each request on `loop` through the ASGI app."""

    def __init__(self, app, loop: asyncio.AbstractEventLoop) -> None:
        self._asgi = httpx.ASGITransport(app=app)
        self._loop = loop

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def send() -> httpx.Response:
            forwarded = httpx.Request(request.method, request.url, headers=request.headers, content=request.read())
            response = await self._asgi.handle_async_request(forwarded)
            return httpx.Response(response.status_code, headers=response.headers, content=await response.aread())

        return asyncio.run_coroutine_threadsafe(send(), self._loop).result(timeout=60)


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


@pytest.fixture
def sdk_for(sessionmaker, writer, key_path):
    def make(token: str) -> GraphSecurityClient:
        app = create_app(make_service(sessionmaker, key_path=key_path, writer=writer))
        http = httpx.Client(transport=LoopBridge(app, asyncio.get_running_loop()), trust_env=False)
        return GraphSecurityClient(BROKER, token, http_client=http)

    return make


async def in_thread(fn, *args, **kwargs):
    return await asyncio.to_thread(fn, *args, **kwargs)


async def test_task_runs_through_the_broker_and_is_audited(sessionmaker, writer, admin_conn, tenant, graph, sdk_for):
    run_id, token = await start_run(admin_conn, writer, tenant)
    users = [graph_user("active", success=1), graph_user("dormant", success=120), graph_user("never"),
             graph_user("new", created=2), graph_user("off", enabled=False)]
    next_link = f"{GRAPH_ORIGIN}{TARGET}&$skiptoken=page2"
    graph.side_effect = [page(users[:3], next_link=next_link), page(users[3:])]

    result = await in_thread(investigate, sdk_for(token), now=NOW, inactive_days=90)

    assert result["counts"] == {"active": 1, "dormant": 1, "never_signed_in": 1, "too_new_to_judge": 1, "disabled": 1}
    assert [u["id"] for u in result["dormant"]] == ["dormant"] and [u["id"] for u in result["never_signed_in"]] == ["never"]
    # Graph saw exactly the broker-built request and its continuation.
    assert [c.request.url.raw_path.decode() for c in graph.calls] == [TARGET, TARGET + "&$skiptoken=page2"]
    assert all(c.request.method == "GET" for c in graph.calls)
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert kinds(records)[2:] == ONE_ATTEMPT + [EventType.OP_DECISION, EventType.GRAPH_REQUEST, EventType.GRAPH_RESPONSE]
    first_decision = records[2]
    assert (first_decision.status, first_decision.details["request_target"]) == ("allowed", TARGET)
    async with sessionmaker() as session:
        assert (await verify_chain(session, chain_id=tenant[0])).valid
    assert (await run_row(admin_conn, run_id))["status"] == "running"  # completing it is the runner's (Task 14)


async def test_prohibited_call_through_the_sdk_is_denied_audited_and_not_sent(
        sessionmaker, writer, admin_conn, tenant, graph, sdk_for):
    run_id, token = await start_run(admin_conn, writer, tenant)
    client = sdk_for(token)

    with pytest.raises(OperationDenied) as caught:
        await in_thread(client.call, "users.update", {"user_id": "00000000-0000-4000-8000-000000000001"})

    assert caught.value.reason == "prohibited"
    assert graph.call_count == 0
    records = await run_records(sessionmaker, tenant[0], run_id)
    assert kinds(records)[2:] == [EventType.OP_DECISION]
    assert (records[2].status, records[2].reason) == ("denied", "prohibited")
    # The run continues: the allowed read still works afterwards.
    graph.mock(return_value=page([graph_user("active", success=1)]))
    assert await in_thread(client.list_users_with_sign_in_activity) == [graph_user("active", success=1)]


async def test_invalid_token_is_denied_and_nothing_sent(admin_conn, writer, tenant, graph, sdk_for):
    await start_run(admin_conn, writer, tenant)
    with pytest.raises(OperationDenied) as caught:
        await in_thread(sdk_for("A" * 43).list_users_with_sign_in_activity)
    assert caught.value.reason == "run_token_invalid" and graph.call_count == 0


async def test_licence_failure_ends_the_task_without_a_result(
        sessionmaker, writer, admin_conn, tenant, graph, sdk_for, capsys):
    run_id, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=httpx.Response(403, json={"error": {
        "code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "message": "x"}}))

    code = await in_thread(main, [], client=sdk_for(token), now=NOW)

    assert code == 1
    captured = capsys.readouterr()
    assert RESULT_PREFIX not in captured.out and "licence_required" in captured.err
    row = await run_row(admin_conn, run_id)
    assert (row["status"], row["outcome"]) == ("failed", "licence_required")
    # The token was revoked with the run: a later call is refused.
    with pytest.raises(OperationDenied, match="run_token_invalid"):
        await in_thread(sdk_for(token).list_users_with_sign_in_activity)


async def test_task_entry_point_emits_the_result(writer, admin_conn, tenant, graph, sdk_for, capsys):
    _, token = await start_run(admin_conn, writer, tenant)
    graph.mock(return_value=page([graph_user("dormant", success=200)]))

    assert await in_thread(main, ["--inactive-days", "30"], client=sdk_for(token), now=NOW) == 0

    (line,) = capsys.readouterr().out.splitlines()
    result = json.loads(line.removeprefix(RESULT_PREFIX))
    assert result["inactive_days"] == 30 and [u["id"] for u in result["dormant"]] == ["dormant"]


async def test_broker_halt_reaches_the_task_as_an_error(sessionmaker, admin_conn, tenant, graph, key_path):
    # An audit failure on GRAPH_RESPONSE: the broker withholds the data (503) and the task gets no users.
    real = AuditWriter(sessionmaker)
    run_id, token = await start_run(admin_conn, real, tenant)

    class FailOnResponse:
        async def append(self, *, chain_id, event):
            if event["event_type"] == EventType.GRAPH_RESPONSE:
                raise RuntimeError("audit store down")
            return await real.append(chain_id=chain_id, event=event)

    graph.mock(return_value=page([graph_user("dormant", success=200)]))
    app = create_app(make_service(sessionmaker, key_path=key_path, writer=FailOnResponse()))
    client = GraphSecurityClient(BROKER, token, http_client=httpx.Client(
        transport=LoopBridge(app, asyncio.get_running_loop()), trust_env=False))

    with pytest.raises(BrokerError) as caught:
        await in_thread(client.list_users_with_sign_in_activity)

    assert (caught.value.reason, caught.value.status_code) == ("audit_unavailable", 503)
    assert not isinstance(caught.value, OperationDenied)
    assert (await run_row(admin_conn, run_id))["status"] == "halted"
