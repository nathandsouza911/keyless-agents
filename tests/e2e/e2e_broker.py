"""The broker, wired for the offline E2E (Task 17A).

It is the real `BrokerService` with the real policy engine, the real
`Transport` (which still sends only to the pinned `https://graph.microsoft.com`),
the real `AuditWriter`, the real manifest catalog, and the real
`MsalCertificateProvider` *with a fake MSAL application factory* in place of a
live Entra token endpoint. That factory is the identity-provider boundary —
the one external dependency the offline demo must stand in for — and
`MsalCertificateProvider.validate_token_claims` still runs for real on the
token the factory returns, so the broker's token validation is exercised, not
bypassed. Nothing about Microsoft's real tokens, licences or Graph is proven.

Run inside the broker image with this module mounted on PYTHONPATH:
    uvicorn --factory e2e_broker:create_e2e_broker_app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from clw.broker.transport import GRAPH_ORIGIN

# A fixed app registration identity for the demo (not a real client id).
FAKE_CLIENT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
FAKE_ROLES = ["AuditLog.Read.All", "User.Read.All"]  # the dormant profile's expected set
# The agent profile's app (agent-read-only-investigation, SD-053): its own client id and four permissions.
FAKE_AGENT_CLIENT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff"
FAKE_AGENT_ROLES = ["Application.Read.All", "AuditLog.Read.All", "RoleManagement.Read.Directory", "User.Read.All"]
_ROLES = {FAKE_CLIENT_ID: FAKE_ROLES, FAKE_AGENT_CLIENT_ID: FAKE_AGENT_ROLES}


class FakeMsal:
    """A ConfidentialClientApplication factory that issues an unsigned app-only
    token for the authority's tenant. The broker validates its claims for real
    and never checks the signature (A-07: the token comes from Entra over TLS)."""

    def __call__(self, client_id, *, authority, client_credential):
        tenant_id = authority.rsplit("/", 1)[1]
        roles = _ROLES.get(client_id, [])  # an unknown app gets no permissions, so the broker refuses it

        class App:
            def acquire_token_for_client(self, scopes):
                claims = {
                    "aud": GRAPH_ORIGIN, "tid": tenant_id, "appid": client_id, "idtyp": "app",
                    "roles": sorted(roles),
                    "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
                }
                return {"access_token": jwt.encode(claims, None, algorithm="none"), "token_type": "Bearer"}

        return App()


def create_e2e_broker_app():
    from clw.audit.writer import AuditWriter
    from clw.broker.app import AGENT_PROFILES_DIR, create_app, load_catalog
    from clw.broker.credentials import MsalCertificateProvider
    from clw.broker.facade.approvals import approved_manifest
    from clw.broker.service import BrokerService
    from clw.broker.transport import Transport, new_graph_client
    from clw.db.session import get_sessionmaker

    sessionmaker = get_sessionmaker()
    service = BrokerService(
        sessionmaker=sessionmaker,
        writer=AuditWriter(sessionmaker),
        transport=Transport(new_graph_client()),
        credentials=MsalCertificateProvider(resource=GRAPH_ORIGIN, app_factory=FakeMsal()),
        catalog=load_catalog(),
        script_manifests=approved_manifest,  # the facade, for approved script runs (as in production)
        agent_catalog=load_catalog(AGENT_PROFILES_DIR),  # agent sessions (SD-049), as in production
    )
    return create_app(service)
