"""Bring-your-own scripts end to end against Postgres (SD-043): submission,
the runner's offline analysis, approval with real roles, the database guards,
script runs, and the broker's view of them."""

from __future__ import annotations

import json
import uuid

import asyncpg
import httpx
import pytest

from clw.api.main import create_app
from clw.audit.events import EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from clw.broker.capability import RunRefused, resolve_run
from clw.broker.facade.approvals import approved_manifest
from clw.db.models.run import Run
from clw.runner.analyser import Analyser
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.broker_fixtures import CATALOG, add_tenant, start_run

pytestmark = pytest.mark.pg

SCRIPT = ("Connect-MgGraph -Scopes 'User.Read.All'\n"
          "$u = Invoke-MgGraphRequest -Uri 'https://graph.microsoft.com/beta/users?$select=id,displayName'\n"
          "Update-MgUser -UserId $id -AccountEnabled:$false\n")
ANALYSIS = {
    "version": "1", "parse_errors": [], "commands": [{"name": "Invoke-MgGraphRequest", "line": 2}],
    "graph_calls": [
        {"source": "Invoke-MgGraphRequest", "method": "GET", "line": 2,
         "uri": "https://graph.microsoft.com/beta/users?$select=id,displayName"},
        {"source": "Update-MgUser", "method": "PATCH", "uri": "/users/{user-id}", "api_version": "v1.0", "line": 3,
         "parameters": {}}],
    "unresolved": [], "risks": [],
}


class FakeAnalyser:
    """The container backend's analyse(): canned analyser output; records what it was given."""

    def __init__(self, stdout: bytes | None = None, *, exit_code: int = 0, error: Exception | None = None):
        self.stdout = stdout if stdout is not None else b"CLW_ANALYSIS " + json.dumps(ANALYSIS).encode() + b"\n"
        self.exit_code, self.error, self.calls = exit_code, error, []

    def analyse(self, kwargs, script, timeout, max_output):
        self.calls.append((kwargs, script))
        if self.error:
            raise self.error
        return self.exit_code, self.stdout


@pytest.fixture
async def org(admin_conn, sessionmaker, runner_sessionmaker, auth_env):
    auth_env()
    # The analyser claims the oldest queued analysis of any tenant: close earlier tests' leftovers first.
    await admin_conn.execute("UPDATE script_analyses SET status = 'failed', reason = 'test_cleanup' "
                             "WHERE status = 'queued'")
    tid, analyst_id, analyst_oid = await add_tenant(admin_conn)
    lead_id, lead_oid = uuid.uuid4(), str(uuid.uuid4())
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, 'security_lead')",
                             lead_id, tid, lead_oid)
    writer = AuditWriter(sessionmaker)
    app = create_app(sessionmaker=sessionmaker, writer=writer, catalog=CATALOG, rate_limited=False)

    def headers(user_id, oid, role):
        token = issue_session(user_id=user_id, oid=oid, tid=tid, role=role)
        return {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}

    return {"tid": tid, "app": app, "writer": writer, "runner_maker": runner_sessionmaker,
            "analyst": headers(analyst_id, analyst_oid, "analyst"), "lead": headers(lead_id, lead_oid, "security_lead"),
            "analyst_id": analyst_id, "lead_id": lead_id}


def client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000")


async def submit(org, text=SCRIPT, who="analyst"):
    async with client(org["app"]) as c:
        return await c.post("/scripts", json={"text": text}, headers=org[who])


async def analyse(org, backend=None):
    backend = backend or FakeAnalyser()
    outcome = await Analyser(sessionmaker=org["runner_maker"], writer=AuditWriter(org["runner_maker"]),
                             backend=backend, image="clw-analyser:test").run_once()
    return outcome, backend


async def approve(org, sha, manifest, who="lead"):
    async with client(org["app"]) as c:
        return await c.post(f"/scripts/{sha}/approvals", json={"manifest": manifest}, headers=org[who])


async def get(org, sha, who="analyst"):
    async with client(org["app"]) as c:
        return await c.get(f"/scripts/{sha}", headers=org[who])


async def chain(sessionmaker, tid):
    async with sessionmaker() as session:
        return await load_chain(session, chain_id=tid), await verify_chain(session, chain_id=tid)


# ----------------------------------------------------------------- submission


async def test_submitting_records_the_script_and_queues_its_analysis(org, sessionmaker):
    reply = await submit(org)
    assert reply.status_code == 201 and reply.json()["created"] is True
    sha = reply.json()["sha256"]
    again = await submit(org)
    assert again.json() == {"sha256": sha, "created": False}
    view = (await get(org, sha)).json()
    assert view["text"] == SCRIPT and view["analysis"]["status"] == "queued" and view["submitted_by_you"]
    records, report = await chain(sessionmaker, org["tid"])
    assert [r.event_type for r in records] == ["SCRIPT_SUBMITTED"] and report.valid
    assert records[0].details == {"script_sha256": sha, "script_bytes": len(SCRIPT.encode())}


@pytest.mark.parametrize("body, status", [({"text": "x" * (256 * 1024 + 1)}, 413), ({"text": ""}, 422),
                                           ({"text": "x", "tenant_id": "y"}, 422)])
async def test_submission_bounds(org, body, status):
    async with client(org["app"]) as c:
        assert (await c.post("/scripts", json=body, headers=org["analyst"])).status_code == status


async def test_another_tenant_cannot_see_the_script(org, admin_conn):
    sha = (await submit(org)).json()["sha256"]
    other_tid, other_id, other_oid = await add_tenant(admin_conn)
    token = issue_session(user_id=other_id, oid=other_oid, tid=other_tid, role="analyst")
    async with client(org["app"]) as c:
        reply = await c.get(f"/scripts/{sha}", headers={"Cookie": f"{SESSION_COOKIE_NAME}={token}"})
    assert reply.status_code == 404


# ------------------------------------------------------------------- analysis


async def test_the_analysis_runs_offline_and_explains_the_script(org, sessionmaker):
    sha = (await submit(org)).json()["sha256"]
    outcome, backend = await analyse(org)
    assert outcome.status == "analyzed"
    kwargs, script = backend.calls[0]
    assert script == SCRIPT.encode()
    assert kwargs["network_mode"] == "none" and kwargs["read_only"] and kwargs["environment"] == {}
    assert kwargs["cap_drop"] == ["ALL"] and kwargs["image"] == "clw-analyser:test"
    analysis = (await get(org, sha)).json()["analysis"]
    assert analysis["status"] == "analyzed"
    assert analysis["summary"]["blocked"] == ["Tries to change data: PATCH /users/{user-id} (Update-MgUser, line 3). "
                                              "This will be blocked."]
    assert analysis["proposed_manifest"]["entries"][0]["path"] == "/users"
    records, report = await chain(sessionmaker, org["tid"])
    assert [r.event_type for r in records] == ["SCRIPT_SUBMITTED", "SCRIPT_ANALYZED"] and report.valid


@pytest.mark.parametrize("backend, reason", [
    (FakeAnalyser(exit_code=1), "analyser_error"),
    (FakeAnalyser(b"garbage\n"), "analysis_malformed"),
    (FakeAnalyser(error=TimeoutError()), "analysis_timeout"),
    (FakeAnalyser(error=RuntimeError("docker down")), "analyser_unavailable"),
])
async def test_a_failed_analysis_is_recorded_and_cannot_be_approved(org, sessionmaker, backend, reason):
    sha = (await submit(org)).json()["sha256"]
    outcome, _ = await analyse(org, backend)
    assert (outcome.status, outcome.reason) == ("failed", reason)
    records, report = await chain(sessionmaker, org["tid"])
    assert records[-1].event_type == EventType.SCRIPT_ANALYZED and records[-1].status == "failed" and report.valid
    proposed = {"schema_version": 1, "profile": "directory-read-auditlog-read",
                "entries": [{"id": "e", "method": "GET", "versions": ["beta"], "path": "/users", "select": ["id"]}]}
    assert (await approve(org, sha, proposed)).status_code == 409


# ------------------------------------------------------------------- approval


async def _analysed(org):
    sha = (await submit(org)).json()["sha256"]
    await analyse(org)
    return sha, (await get(org, sha)).json()["analysis"]["proposed_manifest"]


async def test_a_security_lead_approves_the_proposed_manifest(org, sessionmaker):
    sha, proposed = await _analysed(org)
    reply = await approve(org, sha, proposed)
    assert reply.status_code == 201
    records, report = await chain(sessionmaker, org["tid"])
    assert records[-1].event_type == EventType.MANIFEST_APPROVED and report.valid
    assert records[-1].details["approval_id"] == reply.json()["approval_id"]


async def test_an_analyst_cannot_approve(org):
    sha, proposed = await _analysed(org)
    reply = await approve(org, sha, proposed, who="analyst")
    assert (reply.status_code, reply.json()["detail"]) == (403, "role_not_allowed")


async def test_a_lead_cannot_approve_their_own_script(org):
    sha = (await submit(org, who="lead")).json()["sha256"]
    await analyse(org)
    proposed = (await get(org, sha, who="lead")).json()["analysis"]["proposed_manifest"]
    reply = await approve(org, sha, proposed)
    assert (reply.status_code, reply.json()["detail"]) == (403, "cannot_approve_own_script")


async def test_a_write_entry_can_never_be_approved(org):
    sha, proposed = await _analysed(org)
    proposed["entries"][0]["method"] = "PATCH"
    reply = await approve(org, sha, proposed)
    assert reply.status_code == 422 and "only GET" in reply.json()["detail"]


@pytest.mark.parametrize("case", ["submitter_lead", "analyst_approver", "write_entry", "wrong_digest"])
async def test_the_database_refuses_bad_approvals_whatever_the_caller(org, admin_conn, case):
    """Each case breaks exactly one rule, so each rule in the guard is what refuses it."""
    submitter = "lead" if case == "submitter_lead" else "analyst"
    sha = (await submit(org, who=submitter)).json()["sha256"]
    await analyse(org)
    proposed = (await get(org, sha, who=submitter)).json()["analysis"]["proposed_manifest"]
    script_id = await admin_conn.fetchval("SELECT id FROM scripts WHERE sha256 = $1 AND tenant_id = $2", sha, org["tid"])
    approver, digest, manifest = org["lead_id"], sha, proposed
    if case == "analyst_approver":  # an analyst who did not submit it
        approver = uuid.uuid4()
        await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, 'analyst')",
                                 approver, org["tid"], str(uuid.uuid4()))
    elif case == "write_entry":
        manifest = {**proposed, "entries": [{**proposed["entries"][0], "method": "DELETE"}]}
    elif case == "wrong_digest":
        digest = "0" * 64
    insert = ("INSERT INTO script_approvals (id, tenant_id, script_id, script_sha256, manifest, manifest_sha256, "
              "approved_by) VALUES ($1, $2, $3, $4, $5::jsonb, repeat('a', 64), $6)")
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute(insert, uuid.uuid4(), org["tid"], script_id, digest, json.dumps(manifest), approver)
    if case == "submitter_lead":  # the control: the same insert by another lead is accepted
        other = uuid.uuid4()
        await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, "
                                 "'security_lead')", other, org["tid"], str(uuid.uuid4()))
        await admin_conn.execute(insert, uuid.uuid4(), org["tid"], script_id, digest, json.dumps(manifest), other)


async def test_an_analysis_that_cannot_be_recorded_is_failed_and_not_approvable(org, admin_conn):
    from clw.audit.events import AuditUnavailable

    sha = (await submit(org)).json()["sha256"]

    class DownWriter:
        async def append(self, *, chain_id, event):
            raise AuditUnavailable("down")

    outcome = await Analyser(sessionmaker=org["runner_maker"], writer=DownWriter(), backend=FakeAnalyser(),
                             image="clw-analyser:test").run_once()
    assert (outcome.status, outcome.reason) == ("failed", "audit_unavailable")
    assert await admin_conn.fetchval("SELECT status FROM script_analyses a JOIN scripts s ON s.id = a.script_id "
                                     "WHERE s.sha256 = $1 AND s.tenant_id = $2", sha, org["tid"]) == "failed"
    proposed = {"schema_version": 1, "profile": "directory-read-auditlog-read",
                "entries": [{"id": "e", "method": "GET", "versions": ["beta"], "path": "/users", "select": ["id"]}]}
    assert (await approve(org, sha, proposed)).status_code == 409


async def test_scripts_and_approvals_never_change(org, admin_conn):
    sha, proposed = await _analysed(org)
    await approve(org, sha, proposed)
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute("UPDATE scripts SET text = 'x' WHERE sha256 = $1 AND tenant_id = $2", sha, org["tid"])
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin_conn.execute("UPDATE script_approvals SET manifest_sha256 = repeat('b', 64)")


# ----------------------------------------------------------------- script runs


async def test_a_script_run_needs_an_approval_of_exactly_that_script(org, sessionmaker):
    sha, proposed = await _analysed(org)
    async with client(org["app"]) as c:
        refused = await c.post("/runs", json={"script_sha256": sha}, headers=org["analyst"])
        assert (refused.status_code, refused.json()["detail"]) == (403, "script_not_approved")
        await approve(org, sha, proposed)
        run = await c.post("/runs", json={"script_sha256": sha}, headers=org["analyst"])
        edited = (await submit(org, SCRIPT + "# edited\n")).json()["sha256"]
        edited_run = await c.post("/runs", json={"script_sha256": edited}, headers=org["analyst"])
    assert run.status_code == 201 and run.json()["kind"] == "script" and run.json()["status"] == "queued"
    assert (edited_run.status_code, edited_run.json()["detail"]) == (403, "script_not_approved")
    records, report = await chain(sessionmaker, org["tid"])
    assert records[-2].event_type == EventType.RUN_REQUESTED and report.valid  # the edited script's submission follows


@pytest.mark.parametrize("body", [{"task_id": "dormant-account-investigation", "script_sha256": "a" * 64},
                                  {"script_sha256": "a" * 64, "params": {"inactive_days": 90}},
                                  {"task_id": "dormant-account-investigation", "approval_id": str(uuid.uuid4())}, {}])
async def test_a_run_is_exactly_one_kind(org, body):
    async with client(org["app"]) as c:
        assert (await c.post("/runs", json=body, headers=org["analyst"])).status_code == 422


async def test_a_runner_without_the_script_sandbox_leaves_script_runs_queued(org, sessionmaker, admin_conn):
    from clw.runner.catalog import load_task_catalog
    from clw.runner.launcher import Launcher
    from clw.runner.sandbox_spec import SandboxConfig

    sha, proposed = await _analysed(org)
    await approve(org, sha, proposed)
    async with client(org["app"]) as c:
        run_id = (await c.post("/runs", json={"script_sha256": sha}, headers=org["analyst"])).json()["id"]
    # The launcher claims the oldest queued task run of any tenant: close earlier tests' leftovers first.
    await admin_conn.execute("UPDATE runs SET status = 'failed', outcome = 'test_cleanup', run_token_sha256 = NULL, ended_at = now() "
                             "WHERE status = 'queued' AND id <> $1", uuid.UUID(run_id))
    launcher = Launcher(sessionmaker=org["runner_maker"], writer=AuditWriter(org["runner_maker"]), backend=object(),
                        catalog=load_task_catalog(), config=SandboxConfig(image="clw-task:phase1",
                                                                          broker_url="http://broker:8080"))
    assert await launcher._claim() is None  # not configured for script runs: it stays queued


async def test_the_broker_serves_a_script_run_only_through_its_approval(org, sessionmaker, admin_conn):
    from datetime import datetime, timedelta, timezone

    from clw.broker.capability import issue_run_token

    sha, proposed = await _analysed(org)
    await approve(org, sha, proposed)
    async with client(org["app"]) as c:
        run_id = (await c.post("/runs", json={"script_sha256": sha}, headers=org["analyst"])).json()["id"]
    issued = issue_run_token()
    await admin_conn.execute("UPDATE runs SET status = 'running', run_token_sha256 = $2, deadline_at = $3, "
                             "started_at = now() WHERE id = $1", uuid.UUID(run_id), issued.sha256,
                             datetime.now(timezone.utc) + timedelta(minutes=5))
    async with sessionmaker() as session:
        row = await session.get(Run, uuid.UUID(run_id))
        manifest = await approved_manifest(session, row)
        assert manifest is not None and manifest.entries[0].template == "/users"
        with pytest.raises(RunRefused) as refused:
            await resolve_run(session, issued.token, catalog=CATALOG, now=datetime.now(timezone.utc))
    assert refused.value.reason == "not_a_task_run"


async def test_a_task_run_has_no_script_manifest(org, sessionmaker, admin_conn):
    tenant = (org["tid"], org["analyst_id"], None)
    del tenant
    t = await add_tenant(admin_conn)
    run_id, _ = await start_run(admin_conn, AuditWriter(sessionmaker), t)
    async with sessionmaker() as session:
        assert await approved_manifest(session, await session.get(Run, uuid.UUID(run_id))) is None


async def test_a_tampered_approval_serves_nothing(org, sessionmaker, admin_conn):
    sha, proposed = await _analysed(org)
    await approve(org, sha, proposed)
    async with client(org["app"]) as c:
        run_id = (await c.post("/runs", json={"script_sha256": sha}, headers=org["analyst"])).json()["id"]
    widened = {**proposed, "entries": [{**proposed["entries"][0], "select": ["id", "displayName", "mail"]}]}
    await admin_conn.execute("SET session_replication_role = replica")  # what a DBA could do: bypass the guards
    try:
        await admin_conn.execute("UPDATE script_approvals SET manifest = $1::jsonb WHERE script_sha256 = $2 "
                                 "AND tenant_id = $3", json.dumps(widened), sha, org["tid"])
    finally:
        await admin_conn.execute("SET session_replication_role = origin")
    async with sessionmaker() as session:
        assert await approved_manifest(session, await session.get(Run, uuid.UUID(run_id))) is None
