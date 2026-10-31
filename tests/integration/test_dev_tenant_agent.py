"""An AI agent's session against the real dev tenant (v0.1 smoke tests; marker `tenant`; owner's yes 2026-10-31).

Real: Entra (app-only certificate credentials for both profile apps), Microsoft
Graph, token validation (the exact permission set), policy, transport,
pagination, response filtering, write-ahead audit, agent sessions (created
through the api), the MCP gateway (with its broker check on every request) and
the MCP SDK's own client. In process, not over a network: api, gateway and
broker. Reads only: no executable write exists, and both apps hold read
permissions only.

The tenant may contain real people. Nothing here prints Graph data: every
assertion is on counts, shapes or booleans.
"""

from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.api.catalog import load_agent_catalog, load_api_catalog
from clw.api.main import create_app as create_api
from clw.audit.events import EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from clw.broker.app import AGENT_PROFILES_DIR, create_app as create_broker, load_catalog
from clw.broker.credentials import MsalCertificateProvider
from clw.broker.operations import PRINCIPAL_PROPERTIES
from clw.broker.service import BrokerService
from clw.broker.transport import GRAPH_ORIGIN, Transport, new_graph_client
from clw.db import admin
from clw.mcp_gateway.app import BrokerClient, create_app as create_gateway
from tests.db.conftest import _sqlalchemy_url
from tests.integration.conftest import REPO

pytestmark = pytest.mark.tenant

GATEWAY_URL = "http://127.0.0.1:8090/mcp"
HOLDER_KEYS = {"displayName", "userPrincipalName", "type", "id", "scope"}
AGENT_PERMISSIONS = ["Application.Read.All", "AuditLog.Read.All", "RoleManagement.Read.Directory", "User.Read.All"]


def _credentials_environ(env: dict[str, str]) -> dict[str, str]:
    key = Path(env.get("CLW_PROFILE_AGENTRO_CERT_PATH") or "secrets/profiles/agent-read-only-investigation.pem")
    return {
        "CLW_PROFILE_DIRREAD_CLIENT_ID": env["CLW_PROFILE_DIRREAD_CLIENT_ID"],
        "CLW_PROFILE_DIRREAD_CERT_PATH": env["CLW_PROFILE_DIRREAD_CERT_PATH"],
        "CLW_PROFILE_DIRREAD_CERT_THUMBPRINT": env["CLW_PROFILE_DIRREAD_CERT_THUMBPRINT"],
        "CLW_PROFILE_AGENTRO_CLIENT_ID": env.get("CLW_PROFILE_AGENTRO_CLIENT_ID", ""),
        "CLW_PROFILE_AGENTRO_CERT_PATH": str(key if key.is_absolute() else (REPO / key).resolve()),
        "CLW_PROFILE_AGENTRO_CERT_THUMBPRINT": env.get("CLW_PROFILE_AGENTRO_CERT_THUMBPRINT", ""),
    }


class AgentHarness:
    def __init__(self, env: dict[str, str], app_dsn: str, owner_dsn: str) -> None:
        self.env, self.tid, self.oid = env, env["CLW_DEV_TENANT_ID"], str(uuid.uuid4())
        self._engines = [create_async_engine(_sqlalchemy_url(app_dsn)), create_async_engine(_sqlalchemy_url(owner_dsn))]
        self.app, self.owner = (async_sessionmaker(e, class_=AsyncSession, expire_on_commit=False) for e in self._engines)
        self.api = create_api(sessionmaker=self.app, writer=AuditWriter(self.app), catalog=load_api_catalog(),
                              agent_catalog=load_agent_catalog(), rate_limited=False)
        service = BrokerService(
            sessionmaker=self.app, writer=AuditWriter(self.app), transport=Transport(new_graph_client()),
            credentials=MsalCertificateProvider(resource=GRAPH_ORIGIN, environ=_credentials_environ(env)),
            catalog=load_catalog(), agent_catalog=load_catalog(AGENT_PROFILES_DIR))
        self.broker_app = create_broker(service)

    def gateway(self):
        """A fresh gateway app: the MCP SDK's session manager starts only once per app instance."""
        broker_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.broker_app), timeout=120)
        return create_gateway(broker=BrokerClient("http://broker:8080", http=broker_http), public_url=GATEWAY_URL)

    async def register(self) -> None:
        await admin.add_tenant(self.owner, tenant_id=self.tid, display_name="Dev tenant (agent smoke test)")
        await admin.add_member(self.owner, tenant_id=self.tid, oid=self.oid, role="security_lead")

    async def start(self, profile: str) -> dict:
        async with self.owner() as s:
            from sqlalchemy import text

            user_id = (await s.execute(text("SELECT id FROM workbench_users WHERE tenant_id = :t AND oid = :o"),
                                       {"t": self.tid, "o": self.oid})).scalar_one()
        cookie = issue_session(user_id=user_id, oid=self.oid, tid=self.tid, role="security_lead")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.api), base_url="http://api",
                                     cookies={SESSION_COOKIE_NAME: cookie}) as c:
            reply = await c.post("/v1/agent-sessions", json={"profile": profile, "ttl_minutes": 15})
        assert reply.status_code == 201, reply.status_code
        return reply.json()

    async def call(self, capability: str, tool: str, arguments: dict) -> dict:
        import httpx2
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        gateway = self.gateway()
        async with gateway.router.lifespan_context(gateway):
            http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=gateway),
                                      base_url="http://127.0.0.1:8090",
                                      headers={"authorization": f"Bearer {capability}"}, timeout=180)
            async with http, streamable_http_client(GATEWAY_URL, http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    result = await session.call_tool(tool, arguments)
        assert not result.is_error
        return result.structured_content if result.structured_content is not None else json.loads(result.content[0].text)

    async def records(self, run_id: str):
        async with self.owner() as s:
            return [r for r in await load_chain(s, chain_id=self.tid) if r.run_id == run_id]

    async def chain_valid(self) -> bool:
        async with self.owner() as s:
            report = await verify_chain(s, chain_id=self.tid)
        return report.valid and not report.errors

    async def close(self) -> None:
        for engine in self._engines:
            await engine.dispose()


@pytest.fixture
async def harness(dev_env, app_role_dsn, pg_dsn, monkeypatch):
    # As tests/integration/test_dev_tenant.py: the settings the api's session signing reads.
    from clw.common import config

    monkeypatch.setenv("DATABASE_URL", _sqlalchemy_url(app_role_dsn))
    monkeypatch.setenv("SESSION_JWT_SECRET", dev_env["SESSION_JWT_SECRET"])
    monkeypatch.delenv("REDIS_URL", raising=False)
    config.get_settings.cache_clear()
    h = AgentHarness(dev_env, app_role_dsn, pg_dsn)
    await h.register()
    try:
        yield h
    finally:
        await h.close()
        config.get_settings.cache_clear()


def _no_writes(records) -> bool:
    return all(r.http_method == "GET" for r in records if r.event_type == EventType.GRAPH_REQUEST)


async def test_smoke_1_dormant_accounts_on_the_original_app(harness):
    session = await harness.start("dormant-accounts")
    payload = await harness.call(session["capability"], "entra_find_dormant_accounts", {"days": 90})
    assert payload.get("refused") is not True, payload.get("reason")
    counts = payload["data"]["counts"]
    assert set(counts) == {"active", "dormant", "never_signed_in", "too_new_to_judge", "disabled"}
    assert sum(counts.values()) >= 3  # at least the three clw-test-* accounts
    assert counts["disabled"] >= 1    # clw-test-disabled
    records = await harness.records(session["id"])
    credential = next(r for r in records if r.event_type == EventType.CREDENTIAL_ACQUIRED)
    assert credential.details == {"permissions": ["AuditLog.Read.All", "User.Read.All"]}
    assert _no_writes(records) and await harness.chain_valid()


async def test_smoke_2_admin_role_holders_on_the_new_app(harness):
    session = await harness.start("read-only-investigation")
    payload = await harness.call(session["capability"], "entra_list_admin_role_holders", {})
    assert payload.get("refused") is not True, payload.get("reason")
    roles = payload["data"]["roles"]
    assert roles and any(r["role"] == "Global Administrator" and r["builtIn"] and r["privileged"] for r in roles)
    assert all(set(h) == HOLDER_KEYS for r in roles for h in r["holders"])
    assert "PIM-eligible" in payload["data"]["scope"]
    records = await harness.records(session["id"])
    credential = next(r for r in records if r.event_type == EventType.CREDENTIAL_ACQUIRED)
    assert credential.details == {"permissions": AGENT_PERMISSIONS}  # exactly the four consented (A-31)
    requests = [r.request_target for r in records if r.event_type == EventType.GRAPH_REQUEST]
    assert "/v1.0/roleManagement/directory/roleAssignments?$expand=principal" in requests
    assert _no_writes(records) and await harness.chain_valid()


async def test_smoke_2_expanded_principals_reach_the_broker_with_only_their_four_properties(harness):
    session = await harness.start("read-only-investigation")
    # Through the broker's own route, as the gateway calls it, to see the items before any tool shapes them.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=harness.broker_app), base_url="http://broker",
                                 timeout=120) as http:
        reply = await http.post("/v1/agent/ops", json={"op": "directory.list_role_assignments", "params": {}},
                                headers={"Authorization": f"Bearer {session['capability']}"})
    status, body = reply.status_code, reply.json()
    assert status == 200, body.get("reason")
    assignments = body["data"]
    assert assignments
    assert all(set(a) <= {"id", "principalId", "roleDefinitionId", "directoryScopeId", "principal"} for a in assignments)
    principals = [a["principal"] for a in assignments if isinstance(a.get("principal"), dict)]
    assert principals, "Graph returned no expanded principals"  # A-31: $expand=principal works
    assert all(set(p) <= PRINCIPAL_PROPERTIES for p in principals)


async def test_smoke_2_app_permissions_on_the_new_app(harness):
    session = await harness.start("read-only-investigation")
    payload = await harness.call(session["capability"], "entra_list_app_permissions", {})
    assert payload.get("refused") is not True, payload.get("reason")
    data = payload["data"]
    assert "detail" not in data  # Microsoft Graph's service principal was found
    assert isinstance(data["apps"], list) and "Delegated permissions" in data["scope"]
    assert all(set(a) == {"app", "id", "type", "permissions", "highImpact"} for a in data["apps"])
    records = await harness.records(session["id"])
    assert _no_writes(records) and await harness.chain_valid()


async def test_smoke_2_a_proposal_looks_up_a_test_account_and_changes_nothing(harness):
    session = await harness.start("read-only-investigation")
    target = harness.env["CLW_DEV_TEST_DISABLED_ID"].lower()
    payload = await harness.call(session["capability"], "entra_disable_user",
                                 {"user_id": target, "reason": "smoke test: lookup of a clw-test account"})
    data = payload["data"]
    assert (data["status"], data["executed"]) == ("proposed", False)
    assert data["target"]["lookup"] == "found" and data["target"]["id"] == target
    assert data["target"]["accountEnabled"] is False  # clw-test-disabled, unchanged by anything here
    assert (data["target"]["userPrincipalName"] or "").lower().startswith("clw-test")
    missing = await harness.call(session["capability"], "entra_disable_user",
                                 {"user_id": str(uuid.uuid4()), "reason": "smoke test: a missing id"})
    assert missing["data"]["target"]["lookup"] == "not_found"
    records = await harness.records(session["id"])
    lookups = [r.request_target for r in records if r.event_type == EventType.GRAPH_REQUEST]
    assert len(lookups) == 2 and all(t.endswith("?$select=accountEnabled,displayName,id,userPrincipalName")
                                     for t in lookups)
    assert _no_writes(records) and await harness.chain_valid()
