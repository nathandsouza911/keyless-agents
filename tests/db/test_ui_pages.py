"""The demo pages against Postgres (SD-045): every action goes through the
API's own route functions, a form post needs this origin, and everything
rendered is escaped (a script's output above all)."""

from __future__ import annotations

import hashlib
import html
import json
import uuid
from urllib.parse import urlencode

import pytest

from clw.audit.writer import AuditWriter
from clw.runner.catalog import load_task_catalog
from clw.runner.launcher import Launcher
from clw.runner.sandbox_spec import SandboxConfig, ScriptSandboxConfig
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.runner_fixtures import FakeBackend, FakeProcess
from tests.db.test_scripts import FakeAnalyser, SCRIPT, analyse, client, org  # noqa: F401 (fixture)

pytestmark = pytest.mark.pg

ORIGIN = {"Origin": "http://localhost:8000", "Content-Type": "application/x-www-form-urlencoded"}
HOSTILE = "<script>alert('x')</script>"
ONE_READ = json.dumps({"schema_version": 1, "profile": "directory-read-auditlog-read", "entries": [
    {"id": "u", "method": "GET", "versions": ["v1.0"], "path": "/users", "select": ["id"]}]})


async def post(org, path, fields, who="analyst", headers=ORIGIN):
    async with client(org["app"]) as c:
        return await c.post(path, content=urlencode(fields), headers={**headers, **org[who]})


async def page(org, path, who="analyst"):
    async with client(org["app"]) as c:
        return await c.get(path, headers=org[who] if who else {})


async def submitted(org, text=SCRIPT):
    reply = await post(org, "/ui/scripts", {"text": text})
    assert reply.status_code == 303, reply.text
    return reply.headers["location"].rsplit("/", 1)[1]


async def test_without_a_session_the_pages_offer_sign_in_and_allow_no_script(org):
    reply = await page(org, "/ui", who=None)
    assert reply.status_code == 200 and "/auth/microsoft/start" in reply.text
    csp = reply.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp and "frame-ancestors 'none'" in csp
    assert reply.headers["x-content-type-options"] == "nosniff"
    # Not no-referrer: under it browsers send "Origin: null" on form posts, and every post was refused.
    assert reply.headers["referrer-policy"] == "same-origin"


async def test_submit_analyse_approve_and_run_through_the_pages(org, admin_conn):
    sha = await submitted(org, SCRIPT.replace("\n", "\r\n"))  # a browser sends CRLF
    assert sha == hashlib.sha256(SCRIPT.encode()).hexdigest()   # stored and hashed as LF text
    pending = await page(org, f"/ui/scripts/{sha}")
    assert 'http-equiv="refresh"' in pending.text and "Analysing" in pending.text
    await analyse(org)

    analysed = await page(org, f"/ui/scripts/{sha}", who="lead")
    assert "this will be blocked" in analysed.text and "Approve this manifest" in analysed.text
    manifest = analysed.text.split('<textarea name="manifest" rows="16">', 1)[1].split("</textarea>", 1)[0]
    approved = await post(org, f"/ui/scripts/{sha}/approve", {"manifest": html.unescape(manifest)}, who="lead")
    assert approved.status_code == 303
    assert "Run under the latest approval" in (await page(org, f"/ui/scripts/{sha}")).text

    run = await post(org, f"/ui/scripts/{sha}/run", {})
    assert run.status_code == 303 and run.headers["location"].startswith("/ui/runs/")
    run_page = await page(org, run.headers["location"])
    assert run_page.status_code == 200 and "queued" in run_page.text and 'http-equiv="refresh"' in run_page.text


@pytest.mark.parametrize("headers", [
    {"Content-Type": "application/x-www-form-urlencoded"},                                  # no Origin
    {"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
    {"Origin": "http://localhost:8000.evil.example", "Content-Type": "application/x-www-form-urlencoded"},
], ids=["no-origin", "other-origin", "lookalike-origin"])
async def test_a_cross_site_form_post_is_refused_and_changes_nothing(org, admin_conn, headers):
    reply = await post(org, "/ui/scripts", {"text": "Get-MgUser -Top 1\n"}, headers=headers)
    assert reply.status_code == 403 and "cross_origin_refused" in reply.text
    assert await admin_conn.fetchval("SELECT count(*) FROM scripts WHERE tenant_id = $1", org["tid"]) == 0


@pytest.mark.parametrize("content, ctype", [
    (urlencode({"text": "a", "extra": "b"}), "application/x-www-form-urlencoded"),
    (urlencode([("text", "a"), ("text", "b")]), "application/x-www-form-urlencoded"),
    ('{"text": "a"}', "application/json"),
    ("text=" + "a" * 600_000, "application/x-www-form-urlencoded"),
], ids=["extra-field", "repeated-field", "json", "too-large"])
async def test_only_a_bounded_form_with_exactly_its_fields_is_accepted(org, content, ctype):
    async with client(org["app"]) as c:
        reply = await c.post("/ui/scripts", content=content,
                             headers={"Origin": "http://localhost:8000", "Content-Type": ctype, **org["analyst"]})
    assert reply.status_code == 422 and "invalid_request" in reply.text


async def test_the_pages_keep_the_apis_approval_rules(org):
    sha = await submitted(org)
    await analyse(org)
    # An analyst cannot approve, and the approve form is not offered to one.
    assert "Approve this manifest" not in (await page(org, f"/ui/scripts/{sha}")).text
    refused = await post(org, f"/ui/scripts/{sha}/approve", {"manifest": "{}"})
    assert refused.status_code == 403 and "role_not_allowed" in refused.text
    # A lead's own script: no form, and the API's refusal if posted anyway.
    own = await post(org, "/ui/scripts", {"text": "Get-MgUser -Top 2\n"}, who="lead")
    own_sha = own.headers["location"].rsplit("/", 1)[1]
    await analyse(org)
    assert "another security lead must approve it" in (await page(org, f"/ui/scripts/{own_sha}", who="lead")).text
    refused = await post(org, f"/ui/scripts/{own_sha}/approve", {"manifest": ONE_READ}, who="lead")
    assert refused.status_code == 403 and "cannot_approve_own_script" in refused.text
    # A write is never approvable.
    write = '{"schema_version": 1, "profile": "directory-read-auditlog-read", "entries": [{"id": "w", "method": "PATCH", "versions": ["v1.0"], "path": "/users/{id}"}]}'
    refused = await post(org, f"/ui/scripts/{sha}/approve", {"manifest": write}, who="lead")
    assert refused.status_code == 422 and "manifest_refused" in refused.text
    # Not approved: it cannot run.
    refused = await post(org, f"/ui/scripts/{sha}/run", {})
    assert refused.status_code == 403 and "script_not_approved" in refused.text


async def test_another_tenants_script_is_not_found(org):
    reply = await page(org, f"/ui/scripts/{'a' * 64}")
    assert reply.status_code == 404 and "script_not_found" in reply.text
    reply = await page(org, f"/ui/runs/{uuid.uuid4()}")
    assert reply.status_code == 404 and "run_not_found" in reply.text


async def test_script_text_and_script_output_are_shown_as_text(org, admin_conn):
    sha = await submitted(org, f"'{HOSTILE}'\n")
    view = await page(org, f"/ui/scripts/{sha}")
    assert HOSTILE not in view.text and "&lt;script&gt;alert(" in view.text
    await analyse(org)
    lead_view = await page(org, f"/ui/scripts/{sha}", who="lead")
    manifest = html.unescape(lead_view.text.split('rows="16">', 1)[1].split("</textarea>", 1)[0])
    if '"entries": []' in manifest:  # nothing to read: approve one read so the run can start
        manifest = ONE_READ
    assert (await post(org, f"/ui/scripts/{sha}/approve", {"manifest": manifest}, who="lead")).status_code == 303
    run_id = (await post(org, f"/ui/scripts/{sha}/run", {})).headers["location"].rsplit("/", 1)[1]
    await admin_conn.execute("UPDATE runs SET status = 'failed', outcome = 'test_cleanup', run_token_sha256 = NULL, ended_at = now() "
                             "WHERE status = 'queued' AND id <> $1", uuid.UUID(run_id))
    maker = org["runner_maker"]
    backend = FakeBackend(FakeProcess([f"{HOSTILE}\n<b>bold</b>\n".encode(), b"CLW_SCRIPT_EXIT 0\n"]))
    launcher = Launcher(sessionmaker=maker, writer=AuditWriter(maker), backend=backend, catalog=load_task_catalog(),
                        config=SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080"),
                        script_config=ScriptSandboxConfig(image="clw-task-pwsh:test",
                                                          broker_url="https://graph.microsoft.com"),
                        bootstrap_sha256="b" * 64)
    assert (await launcher.run_once()).status == "completed"
    run_page = await page(org, f"/ui/runs/{run_id}")
    assert HOSTILE not in run_page.text and "<b>bold</b>" not in run_page.text
    assert "&lt;script&gt;alert(" in run_page.text and "&lt;b&gt;bold&lt;/b&gt;" in run_page.text
    assert "RUN_COMPLETED" in run_page.text and ">valid<" in run_page.text


async def test_sign_out_revokes_the_session_and_clears_its_cookie(org):
    assert "Sign out" in (await page(org, "/ui")).text
    out = await post(org, "/ui/signout", {})
    assert out.status_code == 303 and out.headers["location"] == "/ui"
    assert "clw_session=" in out.headers["set-cookie"] and "max-age=0" in out.headers["set-cookie"].lower()
    after = await page(org, "/ui")  # the same cookie again: revoked
    assert "/auth/microsoft/start" in after.text and "Sign out" not in after.text


async def test_a_cross_site_sign_out_is_refused_and_the_session_stays(org):
    refused = await post(org, "/ui/signout", {}, headers={"Origin": "https://evil.example",
                                                           "Content-Type": "application/x-www-form-urlencoded"})
    assert refused.status_code == 403 and "cross_origin_refused" in refused.text
    assert "Sign out" in (await page(org, "/ui")).text
