"""The bring-your-own-script demo against the real dev tenant, in process (Part B, M6; marker `tenant`).

The script is Tony Redmond's Report-LastSuccessfulSignIn.PS1 (MIT, (c) 2023
Tony Redmond; https://github.com/12Knocksinna/Office365itpros), fetched at a
pinned commit and checked against its SHA-256. It is never stored in this
repository. One disclosed correction is applied before submission: its line
11 has a typo (``$`top``, a dollar sign followed by a tab escape), which the
facade refuses as an unknown query parameter (D1); the corrected copy says
``` `$top```.

Real here: the API's intake, approval and run creation (least-privileged
roles), the offline analyser container, the runner's start step, the broker's
facade with the real profile credential, Microsoft Graph, the audit chain.
Not here: the PowerShell sandbox and the facade proxy (the full compose run).
The script's requests are made as the SDK would make them.

The tenant may contain real people: nothing from Graph is printed or kept.
Assertions use counts and property names only, and the run stores no result.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from urllib.parse import urlsplit

import httpx
import pytest

from clw.audit.events import EventType
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from clw.broker.facade.approvals import approved_manifest
from clw.broker.service import BrokerService
from clw.broker.transport import Transport, new_graph_client
from clw.db import admin
from clw.runner.analyser import Analyser
from clw.runner.backend import DockerBackend
from clw.runner.catalog import load_task_catalog
from clw.runner.launcher import ClaimedRun, Launcher
from clw.runner.sandbox_spec import SandboxConfig, ScriptSandboxConfig, bootstrap_sha256
from tests.integration.test_dev_tenant import Harness, harness  # noqa: F401 (fixture)

pytestmark = pytest.mark.tenant

SCRIPT_URL = ("https://raw.githubusercontent.com/12Knocksinna/Office365itpros/"
              "295682f806917d284d1d061bcc19f9445ee67428/Report-LastSuccessfulSignIn.PS1")
SCRIPT_SHA256 = "13bb6c3f8a33e83a1043217d4084b7f6cdcf0ef41a23d15b9243059c92e86cb5"
TYPO, FIXED = "&$`top=999", "&`$top=999"
ANALYSER_IMAGE = "clw-analyser:test"
# The script's first request as the SDK sends it (Invoke-MgGraphRequest, the
# corrected URI with System.Uri's encoding), with ConsistencyLevel: Eventual.
FIRST = ("/beta/users?$count=true&$filter=(assignedLicenses/$count%20ne%200%20and%20userType%20eq%20'Member')"
         "&$top=999&$select=id,%20displayName,%20usertype,%20signInActivity")
SELECTED = {"id", "displayName", "userType", "signInActivity"}


def demo_script() -> str:
    original = httpx.get(SCRIPT_URL, timeout=30, follow_redirects=False)
    assert original.status_code == 200
    assert hashlib.sha256(original.content).hexdigest() == SCRIPT_SHA256, "the pinned script changed"
    text = original.content.decode("utf-8")
    assert text.count(TYPO) == 1
    return text.replace(TYPO, FIXED)


@pytest.fixture
async def demo(harness):  # noqa: F811 - the dev-tenant harness, extended for scripts
    h = harness
    lead_oid = str(uuid.uuid4())
    await admin.add_member(h.owner, tenant_id=h.tid, oid=lead_oid, role="security_lead")
    h.broker = BrokerService(sessionmaker=h.app, writer=AuditWriter(h.app), transport=Transport(new_graph_client()),
                             credentials=h.credentials, catalog=h.broker._catalog, script_manifests=approved_manifest)
    h.launcher = Launcher(sessionmaker=h.runner, writer=AuditWriter(h.runner), backend=object(),
                          catalog=load_task_catalog(),
                          config=SandboxConfig(image="clw-task:phase1", broker_url="http://broker:8080"),
                          script_config=ScriptSandboxConfig(image="clw-task-pwsh:m5",
                                                            broker_url="https://graph.microsoft.com"),
                          bootstrap_sha256=bootstrap_sha256())

    async def cookie(oid, role):
        from sqlalchemy import text
        async with h.owner() as s:
            user_id = (await s.execute(text("SELECT id FROM workbench_users WHERE tenant_id = :t AND oid = :o"),
                                       {"t": h.tid, "o": oid})).scalar_one()
        return {SESSION_COOKIE_NAME: issue_session(user_id=user_id, oid=oid, tid=h.tid, role=role)}

    h.analyst_cookie = await cookie(h.oid, "analyst")
    h.lead_cookie = await cookie(lead_oid, "security_lead")
    return h


def api(h, cookies):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=h.api), base_url="http://api", cookies=cookies)


async def test_the_demo_script_reads_the_tenant_through_the_facade_under_its_approval(demo):
    h = demo
    # 1. An analyst submits the (corrected) script; the offline analyser explains it.
    async with api(h, h.analyst_cookie) as c:
        submitted = await c.post("/scripts", json={"text": demo_script()})
    assert submitted.status_code == 201, submitted.status_code
    sha = submitted.json()["sha256"]
    outcome = await Analyser(sessionmaker=h.runner, writer=AuditWriter(h.runner), backend=DockerBackend(),
                             image=ANALYSER_IMAGE).run_once()
    assert outcome is not None and outcome.status == "analyzed", outcome
    async with api(h, h.analyst_cookie) as c:
        analysis = (await c.get(f"/scripts/{sha}")).json()["analysis"]
    proposed = analysis["proposed_manifest"]
    (entry,) = proposed["entries"]
    assert (entry["path"], entry["versions"], entry["method"]) == ("/users", ["beta"], "GET")

    # 2. A security lead approves the proposed manifest as it stands; the analyst starts the run.
    async with api(h, h.lead_cookie) as c:
        assert (await c.post(f"/scripts/{sha}/approvals", json={"manifest": proposed})).status_code == 201
    async with api(h, h.analyst_cookie) as c:
        created = await c.post("/runs", json={"script_sha256": sha})
    assert created.status_code == 201 and created.json()["kind"] == "script"
    claimed = await h.launcher._claim()  # the runner's start step; the PowerShell sandbox is the compose run
    assert isinstance(claimed, ClaimedRun) and claimed.kind == "script"

    # 3. The script's requests, through the facade, to real Graph: the first page, then every next link.
    target, pages, users, keys = FIRST, 0, 0, set()
    while target is not None:
        reply = await h.broker.handle_facade(f"Bearer {claimed.token}", "GET", target,
                                             {"ConsistencyLevel": "Eventual"}, 0)
        body = json.loads(reply.body)
        reason = (body.get("error") or {}).get("innerError", {}).get("clw-reason")
        assert reply.status_code == 200, f"page {pages}: {reply.status_code} {reason}"
        pages += 1
        users += len(body["value"])
        keys |= {k for user in body["value"] for k in user}
        link = body.get("@odata.nextLink")
        target = None if link is None else urlsplit(link).path + "?" + urlsplit(link).query
    # Counts and property names only: the tenant's people never reach the test output.
    assert users >= 1 and keys - {"@odata.type"} <= SELECTED and "signInActivity" in keys, sorted(keys)

    # 4. The run ends; the chain holds the script, its analysis, its approval and every request.
    await h.lifecycle.end(claimed.key, "failed", "harness_finished")
    records = await h.records()
    kinds = [r.event_type for r in records]
    for kind in (EventType.SCRIPT_SUBMITTED, EventType.SCRIPT_ANALYZED, EventType.MANIFEST_APPROVED,
                 EventType.RUN_STARTED, EventType.GRAPH_REQUEST, EventType.GRAPH_RESPONSE):
        assert kind in kinds, kind
    assert kinds.count(EventType.GRAPH_RESPONSE) == pages
    valid, open_intents = await h.chain_valid()
    assert valid and open_intents == ()
