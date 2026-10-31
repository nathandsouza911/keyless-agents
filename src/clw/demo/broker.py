"""The demo broker (v0.1; SD-051): the real broker, with a fictional identity provider.

Everything is the production broker (BrokerService, policy, transport,
audit, agent sessions, proposals) except the identity-provider boundary: the
MSAL application is a fake that issues unsigned app-only tokens for the
fictional tenant, which the real token validation then checks. The profile
credentials it reads are synthetic (a key the quick start's setup generated,
fixed fake client ids), held in memory here, never in the environment.

Run: uvicorn --factory clw.demo.broker:create_demo_broker_app
Needs: DATABASE_URL, CLW_DEMO_DIR (the setup's output: certs and the key).
"""

from __future__ import annotations

import os
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt

from clw.demo import check_broker

# The fictional app registrations, one per profile (never real client ids).
DEMO_CLIENTS = {
    "directory-read-auditlog-read": ("d3e0d3e0-0000-4000-8000-0000000000c1", ["AuditLog.Read.All", "User.Read.All"]),
    "agent-read-only-investigation": ("d3e0d3e0-0000-4000-8000-0000000000c2", [
        "Application.Read.All", "AuditLog.Read.All", "RoleManagement.Read.Directory", "User.Read.All"]),
}
DEMO_THUMBPRINT = "d3e0" * 10


class DemoIdentityProvider:
    """An MSAL ConfidentialClientApplication factory for the fictional tenant: unsigned tokens."""

    def __call__(self, client_id, *, authority, client_credential):
        from clw.broker.transport import GRAPH_ORIGIN

        tenant_id = authority.rsplit("/", 1)[1]
        roles = next((r for c, r in DEMO_CLIENTS.values() if c == client_id), [])

        class App:
            def acquire_token_for_client(self, scopes):
                claims = {"aud": GRAPH_ORIGIN, "tid": tenant_id, "appid": client_id, "idtyp": "app",
                          "roles": sorted(roles),
                          "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())}
                return {"access_token": jwt.encode(claims, None, algorithm="none"), "token_type": "Bearer"}

        return App()


def demo_environ(demo_dir: Path) -> dict[str, str]:
    """Synthetic profile credentials for the provider (the same generated key for each fictional app)."""
    from clw.broker.manifest import DEFAULT_PROFILES_DIR
    from clw.broker.profiles import load_profile_by_id

    environ: dict[str, str] = {}
    for profile_id, (client_id, _) in DEMO_CLIENTS.items():
        names = load_profile_by_id(profile_id, profiles_dir=DEFAULT_PROFILES_DIR).credential
        environ |= {names.client_id_env: client_id, names.certificate_path_env: str(demo_dir / "profile_key.pem"),
                    names.thumbprint_env: DEMO_THUMBPRINT}
    return environ


def demo_graph_client(ca_file: Path) -> httpx.AsyncClient:
    """As new_graph_client, but trusting only the quick start's CA (the fake Graph's)."""
    from clw.broker.transport import DEFAULT_TIMEOUT

    context = ssl.create_default_context(cafile=str(ca_file))
    return httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=False, trust_env=False, verify=context)


def create_demo_broker_app():  # pragma: no cover - wiring only; exercised by the quick start
    check_broker(os.environ)
    from clw.audit.writer import AuditWriter
    from clw.broker.app import AGENT_PROFILES_DIR, create_app, load_catalog
    from clw.broker.credentials import MsalCertificateProvider
    from clw.broker.service import BrokerService
    from clw.broker.transport import GRAPH_ORIGIN, Transport
    from clw.db.session import get_sessionmaker

    demo_dir = Path(os.environ["CLW_DEMO_DIR"])
    sessionmaker = get_sessionmaker()
    service = BrokerService(
        sessionmaker=sessionmaker,
        writer=AuditWriter(sessionmaker),
        transport=Transport(demo_graph_client(demo_dir / "ca.pem")),
        credentials=MsalCertificateProvider(resource=GRAPH_ORIGIN, environ=demo_environ(demo_dir),
                                            app_factory=DemoIdentityProvider(), demo=True),
        catalog=load_catalog(),
        agent_catalog=load_catalog(AGENT_PROFILES_DIR),
    )
    return create_app(service)
