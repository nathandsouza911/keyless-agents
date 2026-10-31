"""The MCP gateway (v0.1; SD-052): what an AI agent connects to.

A streamable-HTTP MCP server that holds no credential, no database access and
no route to Graph of its own. Each tool call becomes named operations on the
broker, presented with the agent's session capability; the broker resolves
the session, applies the profile, audits and decides everything. The gateway
keeps no state between requests.

Authentication (SD-048): the server is an OAuth resource server in shape only.
It publishes Protected Resource Metadata and answers 401 with
`WWW-Authenticate: Bearer ... resource_metadata=...`, and it accepts only
`Authorization: Bearer <session capability>`, never a capability in a URL. It
runs no authorization server: a person gets the capability from the
workbench after signing in. Every request is checked again with the broker
(POST /v1/agent/session); a capability the broker refuses or cannot vouch
for is a 401, and the capability is never logged.

On compose it is on two networks only: `mcpnet` (internal, shared with the
broker) and `mcpfront`, which carries its loopback-published port and which
no other service joins.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from urllib.parse import urlsplit

import httpx
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from clw.mcp_gateway import tools

SERVER_NAME = "cloud-locksmith"
INSTRUCTIONS = (
    "Cloud Locksmith gives you access to this organization's Microsoft Entra ID (Azure AD) tenant: its users, "
    "sign-in activity and directory. Use these tools for any question about the organization's accounts or "
    "identities. When the user says 'the directory', 'our tenant', 'Azure AD', users, admins or apps, they mean "
    "this Entra directory, not files on disk: start with these tools. Every call is checked against a profile "
    "a person chose for this session, and audited. If a call is refused, tell the user why; do not try to work "
    "around it.")
SCOPE = "clw.session"
_CAPABILITY = re.compile(r"[A-Za-z0-9_-]{43}\Z")  # 256 bits, URL-safe base64 (SD-048)
_TIMEOUT = httpx.Timeout(10.0, read=120.0)


def _origin_url(url: str, name: str, *, path_allowed: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None \
            or parts.password is not None or parts.query or parts.fragment or "?" in url or "#" in url \
            or (not path_allowed and (parts.path or url.rstrip("/") != url)):
        raise RuntimeError(f"{name} must be scheme://host[:port]{'/path' if path_allowed else ''}")
    return url


def broker_url() -> str:
    """CLW_MCP_BROKER_URL as exactly scheme://host[:port]; anything else stops the gateway."""
    return _origin_url(os.environ.get("CLW_MCP_BROKER_URL", ""), "CLW_MCP_BROKER_URL", path_allowed=False)


class BrokerClient:
    """The gateway's only outbound connection: the broker's agent routes, with the capability as Bearer."""

    def __init__(self, base_url: str, *, http: httpx.AsyncClient | None = None) -> None:
        self._base = _origin_url(base_url, "the broker URL", path_allowed=False)
        self._http = http or httpx.AsyncClient(timeout=_TIMEOUT, trust_env=False, follow_redirects=False)

    async def describe(self, capability: str) -> dict | None:
        """The session the capability belongs to, or None (refused, malformed or unreachable)."""
        try:
            reply = await self._http.post(f"{self._base}/v1/agent/session",
                                          headers={"Authorization": f"Bearer {capability}"})
        except httpx.HTTPError:
            return None
        if reply.status_code != 200:
            return None
        try:
            session = reply.json()["session"]
            return session if isinstance(session, dict) else None
        except (ValueError, KeyError, TypeError):
            return None

    async def op(self, capability: str, op: str, params: dict) -> tuple[int, dict]:
        """One named operation (POST /v1/agent/ops): (HTTP status, the broker's JSON body)."""
        return await self._post(capability, "/v1/agent/ops", {"op": op, "params": params})

    async def propose(self, capability: str, user_id: str, reason: str) -> tuple[int, dict]:
        """A change proposal (POST /v1/agent/propose, SD-054): filed by the broker, never executed."""
        return await self._post(capability, "/v1/agent/propose",
                                {"action": "disable_user", "user_id": user_id, "reason": reason})

    async def _post(self, capability: str, path: str, payload: dict) -> tuple[int, dict]:
        try:
            reply = await self._http.post(f"{self._base}{path}", json=payload,
                                          headers={"Authorization": f"Bearer {capability}"})
            body = reply.json()
        except (httpx.HTTPError, ValueError):
            return 503, {"status": "error", "reason": "broker_unreachable"}
        return reply.status_code, body if isinstance(body, dict) else {"status": "error", "reason": "bad_reply"}


class SessionVerifier:
    """The MCP SDK's TokenVerifier: the broker vouches for the capability, on every request."""

    def __init__(self, broker: BrokerClient, resource: str) -> None:
        self._broker, self._resource = broker, resource

    async def verify_token(self, token: str) -> AccessToken | None:
        if not _CAPABILITY.match(token):
            return None  # not a capability at all: the broker is not asked
        session = await self._broker.describe(token)
        if session is None:
            return None
        try:
            expires = int(datetime.fromisoformat(str(session["expires_at"]).replace("Z", "+00:00")).timestamp())
            subject = str(session["id"])
        except (KeyError, ValueError):
            return None
        return AccessToken(token=token, client_id="clw-agent-session", scopes=[SCOPE], expires_at=expires,
                           resource=self._resource, subject=subject)


def create_server(*, broker: BrokerClient, public_url: str) -> MCPServer:
    """The MCP server, as a resource server for `public_url`, with the curated tools."""
    public_url = _origin_url(public_url, "CLW_MCP_PUBLIC_URL", path_allowed=True)
    parts = urlsplit(public_url)
    server = MCPServer(
        SERVER_NAME,
        instructions=INSTRUCTIONS,
        token_verifier=SessionVerifier(broker, public_url),
        # No authorization server exists (SD-048); the issuer named here is this server's own origin,
        # which serves no OAuth endpoints, so a client cannot start an OAuth flow against anyone.
        auth=AuthSettings(issuer_url=f"{parts.scheme}://{parts.netloc}", resource_server_url=public_url,
                          required_scopes=[SCOPE], validate_token_resource=True),
    )
    tools.register(server, broker)
    return server


def create_app(*, broker: BrokerClient, public_url: str):
    server = create_server(broker=broker, public_url=public_url)
    netloc = urlsplit(public_url).netloc
    security = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=[netloc],
                                         allowed_origins=[f"{urlsplit(public_url).scheme}://{netloc}"])
    return server.streamable_http_app(stateless_http=True, json_response=True, host="0.0.0.0",
                                      transport_security=security)


def create_production_app():  # pragma: no cover - wiring only
    return create_app(broker=BrokerClient(broker_url()), public_url=os.environ.get("CLW_MCP_PUBLIC_URL", ""))
