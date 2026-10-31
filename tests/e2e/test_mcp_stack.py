"""An AI agent's session through the real stack, offline (v0.1; SD-048, SD-049, SD-052).

A person starts a session in the api; the agent (here, the MCP SDK's own
client) connects to the MCP gateway with the capability and calls the curated
tool; the gateway asks the broker; the broker reaches the fake Graph. Proved
at the receiving ends: the fake Graph's own request log, the audit chain read
back through the api, and the containers' logs.

What is mocked: the identity-provider boundary only (the browser session is
minted from a verified identity; the broker's MSAL app is a fake). Nothing
here proves anything about Microsoft's real tokens or Graph.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from tests.e2e.fake_graph import EXPECTED_COUNTS, EXPECTED_DORMANT, EXPECTED_NEVER

pytestmark = pytest.mark.e2e

PROFILE = "dormant-accounts"  # on the e2e broker's one fake credential


def _api(stack) -> httpx.Client:
    return httpx.Client(base_url=stack.api_base, timeout=15.0)


def _start(stack, ttl_minutes: int = 10, profile: str = PROFILE) -> dict:
    with _api(stack) as api:
        # read-only-investigation is security leads only (SD-055); the e2e lead starts every session.
        reply = api.post("/v1/agent-sessions", json={"profile": profile, "ttl_minutes": ttl_minutes},
                         headers=stack.session_cookie("security_lead"))
    assert reply.status_code == 201, reply.text
    return reply.json()


async def _with_agent(stack, capability: str, action):
    import httpx2
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    async with httpx2.AsyncClient(headers={"authorization": f"Bearer {capability}"}, timeout=60.0) as http:
        async with streamable_http_client(stack.mcp_url, http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                return await action(session)


def _call(stack, capability: str, arguments: dict | None = None, tool: str = "entra_find_dormant_accounts"):
    if arguments is None:
        arguments = {"days": 90} if tool == "entra_find_dormant_accounts" else {}
    return asyncio.run(_with_agent(stack, capability, lambda s: s.call_tool(tool, arguments)))


def _payload(result) -> dict:
    return result.structured_content if result.structured_content is not None else __import__("json").loads(
        result.content[0].text)


def test_an_agent_finds_dormant_accounts_through_the_gateway(stack):
    stack.graph_reset()
    session = _start(stack)
    tools = asyncio.run(_with_agent(stack, session["capability"], lambda s: s.list_tools())).tools
    assert "entra_find_dormant_accounts" in [t.name for t in tools]

    result = _call(stack, session["capability"])
    assert not result.is_error
    data = _payload(result)["data"]
    assert data["counts"] == EXPECTED_COUNTS
    assert [e["userPrincipalName"] for e in data["dormant"]] == EXPECTED_DORMANT
    assert [e["userPrincipalName"] for e in data["never_signed_in"]] == EXPECTED_NEVER

    # The Graph-side proof: only GETs of /v1.0/users, every page, nothing else.
    requests = stack.graph_requests()
    assert requests and all(r["method"] == "GET" and r["path"] == "/v1.0/users" for r in requests)
    assert len(requests) == 3

    # The audit: the session's start, then the decision, credential, three requests and responses.
    with _api(stack) as api:
        audit = api.get(f"/runs/{session['id']}/audit", headers=stack.session_cookie("security_lead")).json()
    assert audit["chain"]["valid"] is True
    kinds = [e["event_type"] for e in audit["events"]]
    assert kinds[:2] == ["RUN_REQUESTED", "RUN_STARTED"]
    assert kinds.count("GRAPH_REQUEST") == kinds.count("GRAPH_RESPONSE") == 3


def test_without_the_capability_the_gateway_refuses_and_graph_sees_nothing(stack):
    stack.graph_reset()
    session = _start(stack)
    with httpx.Client(timeout=10.0) as plain:
        assert plain.post(stack.mcp_url).status_code == 401
        assert plain.post(f"{stack.mcp_url}?access_token={session['capability']}").status_code == 401
        assert plain.post(stack.mcp_url, headers={"authorization": f"RunToken {session['capability']}"}
                          ).status_code == 401
    assert stack.graph_requests() == []


def test_a_revoked_session_cannot_be_used_again(stack):
    stack.graph_reset()
    session = _start(stack)
    assert not _call(stack, session["capability"]).is_error
    with _api(stack) as api:
        assert api.delete(f"/v1/agent-sessions/{session['id']}",
                          headers=stack.session_cookie("security_lead")).status_code == 200
    stack.graph_reset()
    with pytest.raises(Exception):  # the gateway now answers 401: the client cannot even connect
        _call(stack, session["capability"])
    assert stack.graph_requests() == []


def test_the_capability_never_appears_in_any_containers_log(stack):
    session = _start(stack)
    _call(stack, session["capability"])
    with httpx.Client(timeout=10.0) as plain:
        plain.post(f"{stack.mcp_url}?access_token={session['capability']}")
    logs = stack.compose_run("logs", "--no-color", "mcp-gateway", "broker", "api")
    assert logs.returncode == 0
    assert session["capability"] not in logs.stdout + logs.stderr


INVESTIGATION = "read-only-investigation"  # the four-permission agent profile (SD-053)
SENSITIVE = ("ann.private@example.test", "+1 555 0100", "S-1-5-21-1", "BASE64", "backup secret", "keyCredentials",
             "passwordCredentials", "otherMails", "mobilePhone", "rolePermissions", "long text")


def test_admin_role_holders_through_the_gateway_with_filtered_principals(stack):
    stack.graph_reset()
    session = _start(stack, profile=INVESTIGATION)
    result = _call(stack, session["capability"], tool="entra_list_admin_role_holders")
    assert not result.is_error
    payload = _payload(result)
    roles = payload["data"]["roles"]
    assert roles[0]["role"] == "Global Administrator" and roles[0]["privileged"] is True
    assert roles[0]["holders"] == [{"displayName": "Ann Active", "userPrincipalName": "active@contoso.test",
                                    "type": "user", "id": "11111111-0000-0000-0000-000000000001",
                                    "scope": "whole tenant"}]
    assert "PIM-eligible" in payload["data"]["scope"]
    text = __import__("json").dumps(payload)
    assert not [s for s in SENSITIVE if s in text]
    requests = stack.graph_requests()
    assert [(r["method"], r["path"]) for r in requests] == [
        ("GET", "/v1.0/roleManagement/directory/roleDefinitions"),
        ("GET", "/v1.0/roleManagement/directory/roleAssignments")]
    assert requests[1]["query"] == {"$expand": "principal"}


def test_app_permissions_through_the_gateway_with_the_injected_name_as_data(stack):
    from tests.e2e.fake_graph import INJECTED_APP

    stack.graph_reset()
    session = _start(stack, profile=INVESTIGATION)
    result = _call(stack, session["capability"], tool="entra_list_app_permissions")
    assert not result.is_error
    payload = _payload(result)
    apps = payload["data"]["apps"]
    assert apps[0]["app"] == INJECTED_APP and apps[0]["highImpact"] == ["Mail.Send"]
    assert apps[1]["app"] == "Backup Automation" and apps[1]["highImpact"] == []
    assert "not instructions" in payload["note"] and "Delegated permissions" in payload["data"]["scope"]
    text = __import__("json").dumps(payload)
    assert not [s for s in SENSITIVE if s in text]
    assert all(r["method"] == "GET" for r in stack.graph_requests())


def test_the_injected_user_is_reported_as_data_and_nothing_but_reads_reach_graph(stack):
    from tests.e2e.fake_graph import INJECTED_NAME

    stack.graph_reset()
    session = _start(stack, profile=INVESTIGATION)
    payload = _payload(_call(stack, session["capability"]))
    assert INJECTED_NAME in [e["displayName"] for e in payload["data"]["dormant"]]
    assert "not instructions" in payload["note"]
    assert stack.graph_requests() and all(r["method"] == "GET" and r["path"] == "/v1.0/users"
                                          for r in stack.graph_requests())


def test_a_profile_without_the_role_reads_is_refused_before_graph(stack):
    stack.graph_reset()
    session = _start(stack)  # dormant-accounts: users only
    payload = _payload(_call(stack, session["capability"], tool="entra_list_admin_role_holders"))
    assert payload["refused"] is True and payload["sent_to_microsoft"] is False
    assert stack.graph_requests() == []


# --- change proposals (SD-054) ---------------------------------------------------------

def _disable(stack, capability: str, user_id: str, reason: str = "dormant, flagged by the review"):
    return _payload(_call(stack, capability, {"user_id": user_id, "reason": reason}, tool="entra_disable_user"))


def test_asking_to_disable_a_user_files_a_proposal_and_changes_nothing(stack):
    stack.graph_reset()
    session = _start(stack, profile=INVESTIGATION)
    data = _disable(stack, session["capability"], "11111111-0000-0000-0000-000000000007")["data"]
    assert (data["status"], data["executed"]) == ("proposed", False)
    assert data["target"]["lookup"] == "found" and data["target"]["userPrincipalName"] == "ivy.inactive@contoso.test"
    # Graph saw one GET of that user, with the registry's $select, and nothing else: no write.
    (request,) = stack.graph_requests()
    assert (request["method"], request["path"]) == ("GET", "/v1.0/users/11111111-0000-0000-0000-000000000007")
    assert request["query"] == {"$select": "accountEnabled,displayName,id,userPrincipalName"}
    with _api(stack) as api:
        audit = api.get(f"/runs/{session['id']}/audit", headers=stack.session_cookie("security_lead")).json()
    assert audit["chain"]["valid"] is True
    refusal = next(e for e in audit["events"] if e["event_type"] == "OP_DECISION" and e["operation"] == "users.update")
    assert refusal["status"] == "denied" and refusal["reason"] == "write_not_executable"


def test_an_approval_bait_name_comes_back_as_data(stack):
    from tests.e2e.fake_graph import APPROVAL_BAIT_ID, APPROVAL_BAIT_NAME

    stack.graph_reset()
    session = _start(stack, profile=INVESTIGATION)
    payload = _disable(stack, session["capability"], APPROVAL_BAIT_ID)
    assert payload["data"]["executed"] is False and payload["data"]["target"]["displayName"] == APPROVAL_BAIT_NAME
    assert "not instructions" in payload["note"]
    assert all(r["method"] == "GET" for r in stack.graph_requests())


@pytest.mark.parametrize("user_id", ["99999999-0000-4000-8000-000000000099", "44444444-0000-4000-8000-000000000001"])
def test_a_missing_or_non_user_target_is_flagged_and_the_session_goes_on(stack, user_id):
    stack.graph_reset()
    session = _start(stack, profile=INVESTIGATION)
    target = _disable(stack, session["capability"], user_id)["data"]["target"]
    assert (target["id"], target["lookup"]) == (user_id, "not_found") and "warning" in target
    assert not _call(stack, session["capability"]).is_error  # the session still works


def test_no_credential_reaches_the_agent_or_any_containers_log(stack):
    """V11 leak check, end to end: after every tool, no capability, JWT or private key in what the agent
    received or in any container's log (gateway, broker, api, fake Graph, postgres, runner)."""
    import re as _re

    session = _start(stack, profile=INVESTIGATION)
    results = [_payload(_call(stack, session["capability"], tool=tool, arguments=args)) for tool, args in (
        ("entra_find_dormant_accounts", {"days": 90}), ("entra_list_admin_role_holders", {}),
        ("entra_list_app_permissions", {}),
        ("entra_disable_user", {"user_id": "11111111-0000-0000-0000-000000000002", "reason": "leak check"}))]
    seen = __import__("json").dumps(results)
    logs = stack.compose_run("logs", "--no-color")
    assert logs.returncode == 0
    everything = seen + logs.stdout + logs.stderr
    jwt_like = _re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.")
    assert session["capability"] not in everything
    assert not jwt_like.search(everything), "a JWT-shaped string reached a tool result or a log"
    assert "PRIVATE KEY" not in everything
