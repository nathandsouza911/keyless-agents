"""Dormant Account Investigation against the real dev tenant (Task 17C; marker `tenant`).

Real: Entra (app-only certificate credential), Microsoft Graph, the token
validator, policy, transport, pagination, write-ahead audit, the API route
that creates the run, the runner's start step and run lifecycle, each as its
least-privileged role. Not exercised here: the task sandbox (see the full
container stack run, docs/assumptions-to-verify.md) and the browser sign-in
(manual; docs/runbooks/dev-tenant-setup.md).

The tenant may contain real people. No test prints Graph data: values are
reduced to scalars before any assertion (pytest would otherwise show the
record), and every result a run stores is redacted at teardown (SD-037).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import httpx
import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.api.catalog import load_api_catalog
from clw.api.main import create_app
from clw.audit.chain import result_sha256
from clw.audit.events import EventType
from clw.audit.redaction import redact_result
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from clw.broker.app import load_catalog
from clw.broker.credentials import MsalCertificateProvider
from clw.broker.profiles import load_profile_by_id
from clw.broker.service import BrokerService
from clw.broker.transport import GRAPH_ORIGIN, Transport, new_graph_client
from clw.db import admin
from clw.db.models.run import Run
from clw.runner.catalog import load_task_catalog
from clw.runner.launcher import ClaimedRun, Launcher
from clw.runner.lifecycle import RunKey, RunLifecycle
from clw.runner.sandbox_spec import SandboxConfig
from clw_task_sdk.client import LIST_USERS, USER_FIELDS
from tasks.dormant_account_investigation.classify import classify
from tasks.dormant_account_investigation.task import investigate
from tests.db.conftest import RUNNER_ROLE, RUNNER_ROLE_PASSWORD, TEST_DB, _dsn_for, _sqlalchemy_url
from tests.integration.conftest import REPO

pytestmark = pytest.mark.tenant

TASK = "dormant-account-investigation"
EXPECTED_ROLES = {"AuditLog.Read.All", "User.Read.All"}


def _maker(dsn: str):
    engine = create_async_engine(_sqlalchemy_url(dsn))
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Harness:
    """One dev-tenant session: api (app role), runner (runner role), broker (app role)."""

    def __init__(self, env: dict[str, str], app_dsn: str, owner_dsn: str) -> None:
        self.env = env
        self.tid = env["CLW_DEV_TENANT_ID"]
        self.oid = str(uuid.uuid4())  # the in-process actor; browser sign-in is tested manually
        self._engines = []
        for name, dsn in (("app", app_dsn), ("runner", _dsn_for(TEST_DB, user=RUNNER_ROLE,
                                                                  password=RUNNER_ROLE_PASSWORD)),
                          ("owner", owner_dsn)):
            engine, maker = _maker(dsn)
            self._engines.append(engine)
            setattr(self, name, maker)
        self.api = create_app(sessionmaker=self.app, writer=AuditWriter(self.app), catalog=load_api_catalog(),
                              rate_limited=False)
        self.launcher = Launcher(sessionmaker=self.runner, writer=AuditWriter(self.runner), backend=object(),
                                 catalog=load_task_catalog(),
                                 config=SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080"))
        self.lifecycle = RunLifecycle(self.runner, AuditWriter(self.runner))
        self.credentials = MsalCertificateProvider(resource=GRAPH_ORIGIN, environ={
            k: env[k] for k in ("CLW_PROFILE_DIRREAD_CLIENT_ID", "CLW_PROFILE_DIRREAD_CERT_PATH",
                                "CLW_PROFILE_DIRREAD_CERT_THUMBPRINT")})
        self.broker = BrokerService(sessionmaker=self.app, writer=AuditWriter(self.app),
                                    transport=Transport(new_graph_client()), credentials=self.credentials,
                                    catalog=load_catalog())

    async def register(self) -> None:
        await admin.add_tenant(self.owner, tenant_id=self.tid, display_name="Dev tenant (integration)")
        await admin.add_member(self.owner, tenant_id=self.tid, oid=self.oid, role="analyst")

    async def user_id(self) -> uuid.UUID:
        from sqlalchemy import text

        async with self.owner() as s:
            return (await s.execute(text("SELECT id FROM workbench_users WHERE tenant_id = :t AND oid = :o"),
                                    {"t": self.tid, "o": self.oid})).scalar_one()

    async def start(self, params: dict | None = None) -> ClaimedRun:
        cookie = issue_session(user_id=await self.user_id(), oid=self.oid, tid=self.tid, role="analyst")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.api), base_url="http://api",
                                     cookies={SESSION_COOKIE_NAME: cookie}) as c:
            created = await c.post("/runs", json={"task_id": TASK, "params": params or {"inactive_days": 90}})
        assert created.status_code == 201, created.status_code
        claimed = await self.launcher._claim()  # the runner's real start step; the sandbox is not used here
        assert isinstance(claimed, ClaimedRun) and str(claimed.id) == created.json()["id"]
        return claimed

    async def users(self, claimed: ClaimedRun, **params) -> list[dict]:
        body = json.dumps({"op": LIST_USERS, "params": {"select": list(USER_FIELDS), **params}},
                          separators=(",", ":")).encode()
        reply = await self.broker.handle_request(f"RunToken {claimed.token}", body)
        status, kind = reply.status_code, reply.body.get("status")
        reason = reply.body.get("reason")
        assert (status, kind) == (200, "ok"), f"broker refused: {status} {kind} {reason}"
        return reply.body["data"]

    async def complete(self, claimed: ClaimedRun, result: dict) -> None:
        await self.lifecycle.complete(claimed.key, result, result_sha256(result))

    async def records(self, run_id: str | None = None):
        async with self.owner() as s:
            records = await load_chain(s, chain_id=self.tid)
        return [r for r in records if run_id is None or r.run_id == run_id]

    async def chain_valid(self) -> tuple[bool, tuple]:
        async with self.owner() as s:
            report = await verify_chain(s, chain_id=self.tid)
        return report.valid, report.intents_without_outcome

    async def redact_all(self) -> int:
        async with self.owner() as s:
            stored = (await s.execute(select(Run.id).where(
                Run.tenant_id == self.tid, Run.status == "completed", Run.result.is_not(None),
                Run.result_redacted_at.is_(None)))).scalars().all()
        for run_id in stored:
            await redact_result(self.owner, AuditWriter(self.owner), chain_id=self.tid, run_id=str(run_id),
                                operator="tests/integration", reason="dev-tenant test cleanup")
        return len(stored)

    async def close(self) -> None:
        for engine in self._engines:
            await engine.dispose()


@pytest.fixture
async def harness(dev_env, pg_dsn, app_role_dsn, monkeypatch):
    from clw.common import config

    monkeypatch.setenv("DATABASE_URL", _sqlalchemy_url(app_role_dsn))
    monkeypatch.setenv("SESSION_JWT_SECRET", dev_env["SESSION_JWT_SECRET"])
    monkeypatch.delenv("REDIS_URL", raising=False)
    config.get_settings.cache_clear()
    h = Harness(dev_env, app_role_dsn, pg_dsn)
    await h.register()
    try:
        yield h
    finally:
        try:
            await h.redact_all()
            async with h.owner() as s:
                left = (await s.execute(select(Run.id).where(Run.tenant_id == h.tid, Run.result.is_not(None))))
                assert left.first() is None, "a dev-tenant run result was left unredacted"
        finally:
            await h.close()
            config.get_settings.cache_clear()


def _tests_user(env: dict[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value:
        pytest.skip(f"{name} is not set (create the test account; docs/runbooks/dev-tenant-setup.md, section 5)")
    return value.lower()


# ------------------------------------------------------------------ tests


async def test_the_profile_token_has_exactly_the_expected_shape(harness):
    profile = load_profile_by_id("directory-read-auditlog-read", profiles_dir=REPO / "profiles")
    token = await harness.credentials.token_for(tenant_id=harness.tid, profile=profile)
    claims = jwt.decode(token.access_token, options={"verify_signature": False})
    roles, idtyp, aud, has_scp = sorted(token.permissions), claims.get("idtyp"), claims.get("aud"), "scp" in claims
    assert roles == sorted(EXPECTED_ROLES)
    assert (idtyp, aud, has_scp) == ("app", GRAPH_ORIGIN, False)  # A-06, A-07


async def test_a_dormant_account_run_completes_with_a_valid_chain(harness):
    claimed = await harness.start()
    users = await harness.users(claimed)
    result = investigate(type("S", (), {"list_users_with_sign_in_activity": lambda self: users})(),
                         now=datetime.now(timezone.utc), inactive_days=90)
    await harness.complete(claimed, result)
    evaluated, counted = result["users_evaluated"], sum(result["counts"].values())
    assert evaluated == len(users) and counted == evaluated
    kinds = [r.event_type for r in await harness.records(str(claimed.id))]
    assert kinds[:4] == ["RUN_REQUESTED", "RUN_STARTED", "OP_DECISION", "CREDENTIAL_ACQUIRED"]
    assert kinds[-1] == "RUN_COMPLETED" and kinds.count("GRAPH_REQUEST") == kinds.count("GRAPH_RESPONSE") >= 1
    valid, open_intents = await harness.chain_valid()
    assert valid and open_intents == ()


async def test_paging_follows_next_links_each_page_re_authorized(harness):
    claimed = await harness.start()
    users = await harness.users(claimed, top=3)  # A-14: a handful of users spans several pages
    count = len(users)
    if count <= 3:
        pytest.skip("the tenant has 3 users or fewer, so $top=3 does not page")
    await harness.complete(claimed, {"users_evaluated": count})
    records = await harness.records(str(claimed.id))
    requests = [r for r in records if r.event_type == EventType.GRAPH_REQUEST]
    decisions = {r.seq for r in records if r.event_type == EventType.OP_DECISION and r.status == "allowed"}
    first, later = requests[0].request_target, [r.request_target for r in requests[1:]]
    pages, cited = len(requests), [r.decision_seq for r in requests]
    assert pages == -(-count // 3)  # one request per page, no retries needed
    assert len(set(cited)) == pages and set(cited) <= decisions  # each page consumed its own allowed decision
    assert first.endswith("&$top=3") and all(t.startswith(first + "&$skiptoken=") for t in later)
    valid, open_intents = await harness.chain_valid()
    assert valid and open_intents == ()


async def _one_user(harness, user_id: str) -> dict | None:
    claimed = await harness.start()
    users = await harness.users(claimed)
    await harness.complete(claimed, {"users_evaluated": len(users)})
    return next((u for u in users if str(u.get("id", "")).lower() == user_id), None)


async def test_a_never_signed_in_account_has_no_sign_in_activity(harness):
    user_id = _tests_user(harness.env, "CLW_DEV_TEST_NEVER_ID")
    user = await _one_user(harness, user_id)
    assert user is not None, "the never-signed-in test account was not returned"
    activity = user.get("signInActivity")
    timestamps = [] if activity is None else [activity.get(k) for k in
                                              ("lastSignInDateTime", "lastSuccessfulSignInDateTime")]
    assert all(t is None for t in timestamps), "a never-used account carries a sign-in time"  # A-17


async def test_a_disabled_account_is_classified_disabled(harness):
    user_id = _tests_user(harness.env, "CLW_DEV_TEST_DISABLED_ID")
    user = await _one_user(harness, user_id)
    assert user is not None, "the disabled test account was not returned"
    enabled = user.get("accountEnabled")
    verdict = classify(user, now=datetime.now(timezone.utc), inactive_days=90)
    assert (enabled, verdict) == (False, "disabled")


async def test_a_recently_used_account_is_classified_active(harness):
    user_id = _tests_user(harness.env, "CLW_DEV_TEST_ACTIVE_ID")
    user = await _one_user(harness, user_id)
    assert user is not None, "the active test account was not returned"
    verdict = classify(user, now=datetime.now(timezone.utc), inactive_days=90)
    assert verdict == "active", "sign-in activity can lag up to 24 h (A-18); sign in and retry later"


# ------------------------------------------------- identity leaks (owner note on A1)


def _test_user_ids(env: dict[str, str]) -> set[str]:
    from tests.integration.conftest import TEST_USERS

    return {env[name].lower() for name in TEST_USERS if env.get(name)}


def _tracked_files() -> dict[str, str]:
    import subprocess

    names = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True).stdout.split(b"\0")
    texts = {}
    for name in filter(None, names):
        path = REPO / name.decode()
        if path.is_file():
            texts[f"tracked file {name.decode()}"] = path.read_bytes().decode("utf-8", "replace")
    return texts


async def test_no_tenant_identity_leaks(harness, caplog, capsys):
    """A real person's identity may be held only in runs.result (redacted at teardown):
    never in logs, test output, the audit chain, or any file in the repository
    (docs/spikes included)."""
    import dataclasses
    import logging

    from tests.integration.leaks import describe, find_leaks, identities

    caplog.set_level(logging.DEBUG)
    claimed = await harness.start()
    users = await harness.users(claimed)
    result = investigate(type("S", (), {"list_users_with_sign_in_activity": lambda self: users})(),
                         now=datetime.now(timezone.utc), inactive_days=90)
    await harness.complete(claimed, result)
    needles = identities(users, exclude_ids=_test_user_ids(harness.env))
    del users, result

    captured = capsys.readouterr()
    records = await harness.records()
    places = {
        "logs": "\n".join(f"{r.name} {r.getMessage()}" for r in caplog.records),
        "captured stdout": captured.out,
        "captured stderr": captured.err,
        "audit chain": "\n".join(json.dumps(dataclasses.asdict(r), default=str) for r in records),
        **_tracked_files(),
    }
    leaks = find_leaks(needles, places)
    assert not leaks, describe(leaks)


async def test_no_tenant_identity_in_compose_logs(harness):
    """After a full-stack run: the api, broker and runner container logs hold no identity.
    Opt-in (CLW_SCAN_COMPOSE_LOGS=1), since it needs the compose stack's logs."""
    import os
    import subprocess

    from tests.integration.leaks import describe, find_leaks, identities

    if os.environ.get("CLW_SCAN_COMPOSE_LOGS") != "1":
        pytest.skip("set CLW_SCAN_COMPOSE_LOGS=1 after a full-stack run to scan its container logs")
    claimed = await harness.start()
    users = await harness.users(claimed)
    await harness.complete(claimed, {"users_evaluated": len(users)})
    needles = identities(users, exclude_ids=_test_user_ids(harness.env))
    del users
    places = {}
    for service in ("api", "broker", "runner"):
        logs = subprocess.run(["docker", "compose", "--profile", "app", "logs", "--no-color", service],
                              cwd=REPO, capture_output=True, text=True, errors="replace")
        assert logs.returncode == 0, f"could not read the {service} container logs"
        places[f"{service} container logs"] = logs.stdout + logs.stderr
    leaks = find_leaks(needles, places)
    assert not leaks, describe(leaks)
