"""A-04 against the real dev tenant (marker `tenant`): the largest `$top` Graph
accepts for /users when `$select` includes signInActivity, on v1.0 and beta.

Through the facade, in process, as test_byos_demo does: a script approved for
one read (/users, id and signInActivity, $top up to 999, both versions), then
requests with each `$top`. Reports status codes and item counts only; nothing
from Graph is printed or kept.
"""

from __future__ import annotations

import json

import httpx
import pytest

from clw.audit.writer import AuditWriter
from clw.runner.analyser import Analyser
from clw.runner.backend import DockerBackend
from clw.runner.launcher import ClaimedRun
from tests.integration.test_byos_demo import ANALYSER_IMAGE, api, demo  # noqa: F401 (fixture)
from tests.integration.test_dev_tenant import harness  # noqa: F401 (fixture)

pytestmark = pytest.mark.tenant

SCRIPT = "Invoke-MgGraphRequest -Uri '/v1.0/users?$select=id,signInActivity&$top=500'\n"
MANIFEST = {"schema_version": 1, "profile": "directory-read-auditlog-read",
            "entries": [{"id": "users", "method": "GET", "versions": ["v1.0", "beta"], "path": "/users",
                         "select": ["id", "signInActivity"], "top": 999}]}
TARGETS = {
    "v1.0 $top=500": "/v1.0/users?$select=id,signInActivity&$top=500",
    "v1.0 $top=999": "/v1.0/users?$select=id,signInActivity&$top=999",
    "beta $top=999": "/beta/users?$select=id,signInActivity&$top=999",
}


async def test_the_largest_top_with_sign_in_activity(demo, capsys):
    h = demo
    async with api(h, h.analyst_cookie) as c:
        sha = (await c.post("/scripts", json={"text": SCRIPT})).json()["sha256"]
    assert (await Analyser(sessionmaker=h.runner, writer=AuditWriter(h.runner), backend=DockerBackend(),
                           image=ANALYSER_IMAGE).run_once()).status == "analyzed"
    async with api(h, h.lead_cookie) as c:
        assert (await c.post(f"/scripts/{sha}/approvals", json={"manifest": MANIFEST})).status_code == 201
    async with api(h, h.analyst_cookie) as c:
        assert (await c.post("/runs", json={"script_sha256": sha})).status_code == 201
    claimed = await h.launcher._claim()
    assert isinstance(claimed, ClaimedRun)

    observed = {}
    for label, target in TARGETS.items():
        reply = await h.broker.handle_facade(f"Bearer {claimed.token}", "GET", target, {}, 0)
        body = json.loads(reply.body)
        error = (body.get("error") or {}).get("code")
        observed[label] = (reply.status_code, len(body.get("value", [])) if reply.status_code == 200 else error)
    await h.lifecycle.end(claimed.key, "failed", "harness_finished")
    with capsys.disabled():
        for label, (status, detail) in observed.items():
            print(f"A-04 {label}: HTTP {status} ({'items' if status == 200 else 'error'}: {detail})")
    assert observed["v1.0 $top=500"][0] == 200
