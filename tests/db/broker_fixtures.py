"""Shared set-up for the broker tests (Task 12).

Runs are created the way Tasks 14 and 16 will create them: a `runs` row
(inserted as admin) and RUN_REQUESTED + RUN_STARTED written through the real
AuditWriter. Credentials go through the real MsalCertificateProvider and
token validator with a fake MSAL application that issues unsigned tokens
(claims only, A-07); keys are generated at runtime. Graph is mocked with
respx; nothing here reaches the network or holds a real credential.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clw.audit.events import EventType
from clw.audit.verifier import load_chain
from clw.audit.writer import AuditWriter
from clw.broker.capability import issue_run_token
from clw.broker.credentials import MsalCertificateProvider
from clw.broker.manifest import TaskManifest, load_manifest
from clw.broker.service import BrokerService
from clw.broker.transport import GRAPH_ORIGIN, Transport, new_graph_client

REPO = Path(__file__).resolve().parents[2]
MANIFEST = load_manifest(REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml")
CATALOG = {MANIFEST.id: MANIFEST}
LIST = "users.list_with_sign_in_activity"
PARAMS = {"select": ["signInActivity", "id"], "top": 50}
TARGET = "/v1.0/users?$select=id,signInActivity&$top=50"
URL = GRAPH_ORIGIN + TARGET
CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
THUMB = "0123456789abcdef0123456789abcdef01234567"
USERS = [{"id": "u-1", "signInActivity": None}, {"id": "u-2", "signInActivity": None}]
ENV_NAMES = MANIFEST.profile.credential


def new_tenant_id() -> str:
    return str(uuid.uuid4())


async def add_tenant(admin_conn) -> tuple[str, uuid.UUID, str]:
    """A registered tenant with one member: (tenant_id, user_id, oid)."""
    tid, user_id, oid = new_tenant_id(), uuid.uuid4(), str(uuid.uuid4())
    await admin_conn.execute("INSERT INTO tenants (id, display_name, status) VALUES ($1, 'Broker test', 'active')", tid)
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, 'analyst')",
                             user_id, tid, oid)
    return tid, user_id, oid


async def start_run(admin_conn, writer: AuditWriter, tenant: tuple[str, uuid.UUID, str], *,
                    manifest: TaskManifest = MANIFEST, deadline: datetime | None = None,
                    profile_sha256: str | None = None, row: dict | None = None) -> tuple[str, str]:
    """A running run: (run_id, run token). `row` overrides the run row's
    binding columns only (the audit records keep the manifest's values)."""
    tid, user_id, oid = tenant
    run_id = uuid.uuid4()
    issued = issue_run_token()
    deadline = deadline or datetime.now(timezone.utc) + timedelta(minutes=5)
    await admin_conn.execute(
        """INSERT INTO runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,
                             profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status,
                             run_token_sha256, deadline_at, started_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, 'running', $13, $14, now())""",
        run_id, tid, *({"task_id": manifest.id, "task_manifest_sha256": manifest.sha256,
                        "profile_id": manifest.profile.id, "profile_version": manifest.profile.version,
                        "profile_sha256": profile_sha256 or manifest.profile.sha256,
                        "auth_mode": manifest.mode} | (row or {})).values(), user_id, oid, tid,
        json.dumps({"inactive_days": 90}), issued.sha256, deadline,
    )
    rid = str(run_id)
    await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.RUN_REQUESTED, "status": "requested", "run_id": rid,
        "task_id": manifest.id, "task_manifest_sha256": manifest.sha256, "actor_oid": oid, "actor_tid": tid})
    await writer.append(chain_id=tid, event={
        "tenant_id": tid, "event_type": EventType.RUN_STARTED, "status": "started", "run_id": rid,
        "task_id": manifest.id, "task_manifest_sha256": manifest.sha256, "profile_id": manifest.profile.id,
        "profile_version": manifest.profile.version, "auth_mode": manifest.mode})
    return rid, issued.token


def write_key(directory: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = directory / "profile-test-key.pem"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return path


class FakeMsal:
    """An MSAL app factory issuing unsigned app-only tokens for the authority's tenant."""

    def __init__(self, **claims) -> None:
        self.claims = claims
        self.authorities: list[str] = []
        self.issued: list[str] = []

    def __call__(self, client_id, *, authority, client_credential):
        self.authorities.append(authority)
        tid = authority.rsplit("/", 1)[1]
        outer = self

        class App:
            def acquire_token_for_client(self, scopes):
                claims = {"aud": GRAPH_ORIGIN, "tid": tid, "appid": CLIENT, "idtyp": "app",
                          "roles": sorted(MANIFEST.profile.expected_permissions),
                          "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())} | outer.claims
                token = jwt.encode(claims, None, algorithm="none")
                outer.issued.append(token)
                return {"access_token": token, "token_type": "Bearer"}

        return App()


def provider(key_path: Path, factory: FakeMsal) -> MsalCertificateProvider:
    environ = {ENV_NAMES.client_id_env: CLIENT, ENV_NAMES.certificate_path_env: str(key_path),
               ENV_NAMES.thumbprint_env: THUMB}
    return MsalCertificateProvider(resource=GRAPH_ORIGIN, environ=environ, app_factory=factory)


async def no_sleep(seconds: float) -> None:
    return None


def make_service(sessionmaker, *, key_path: Path, factory: FakeMsal | None = None, writer=None,
                 transport=None, engine=None, catalog=None, script_manifests=None,
                 agent_catalog=None) -> BrokerService:
    return BrokerService(
        sessionmaker=sessionmaker,
        writer=writer or AuditWriter(sessionmaker),
        transport=transport or Transport(new_graph_client(), sleep=no_sleep),
        credentials=provider(key_path, factory or FakeMsal()),
        catalog=CATALOG if catalog is None else catalog,
        engine=engine,
        script_manifests=script_manifests,
        agent_catalog=agent_catalog,
    )


def auth(token: str) -> str:
    return f"RunToken {token}"


def body(op: str = LIST, params: dict | None = None, **extra) -> bytes:
    return json.dumps({"op": op, "params": PARAMS if params is None else params, **extra}).encode()


def page(users=USERS, next_link: str | None = None) -> httpx.Response:
    content = {"value": users} | ({"@odata.nextLink": next_link} if next_link else {})
    return httpx.Response(200, json=content, headers={"request-id": "11111111-2222-3333-4444-555555555555"})


async def run_records(sessionmaker, tid: str, run_id: str | None = None):
    async with sessionmaker() as session:
        records = await load_chain(session, chain_id=tid)
    return [r for r in records if run_id is None or r.run_id == run_id]


def kinds(records) -> list[str]:
    return [r.event_type for r in records]


async def run_row(admin_conn, run_id: str):
    return await admin_conn.fetchrow("SELECT * FROM runs WHERE id = $1", uuid.UUID(run_id))
