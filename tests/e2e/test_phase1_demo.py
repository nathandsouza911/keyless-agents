"""Offline Phase 1 end-to-end demo (Task 17A).

Drives the real stack (api -> postgres -> runner -> real task sandbox ->
broker -> fake Graph) through the eight demo steps and a non-premium licence
variant, and proves at the receiving end — the fake Graph's own request log —
that only GET /v1.0/users requests reached Graph, across three pages, and that
the attempted users.update never did.

What is mocked: the identity-provider boundary only (the session is minted
directly from a verified identity, and the broker uses a fake MSAL app factory
in place of a live Entra token endpoint). Everything else runs for real. This
proves nothing about Microsoft's real tokens, licences, Graph pagination or
tenant consent (see docs/demo.md).
"""

from __future__ import annotations

import time

import httpx
import pytest

from tests.e2e.fake_graph import EXPECTED_COUNTS, EXPECTED_DORMANT, EXPECTED_NEVER

pytestmark = pytest.mark.e2e

TASK_ID = "dormant-probe-demo"
RUN_DEADLINE = 150.0


def _client(stack) -> httpx.Client:
    return httpx.Client(base_url=stack.api_base, timeout=15.0)


def _poll_until_terminal(client, headers, run_id: str) -> dict:
    deadline = time.monotonic() + RUN_DEADLINE
    last = None
    while time.monotonic() < deadline:
        last = client.get(f"/runs/{run_id}", headers=headers).json()
        if last["status"] in ("completed", "failed", "timed_out"):
            return last
        time.sleep(2.0)
    raise AssertionError(f"run {run_id} did not finish in time; last={last}")


def _upns(entries: list[dict]) -> list[str]:
    return sorted(e["userPrincipalName"] for e in entries)


def test_happy_path_demo_and_graph_side_proof(stack):
    headers = stack.session_cookie()
    stack.graph_reset()
    with _client(stack) as client:
        # 1 (session minted) + 2: the manifest view shows the allowed read and the prohibited write.
        view = client.get(f"/tasks/{TASK_ID}", headers=headers)
        assert view.status_code == 200, view.text
        view = view.json()
        assert {op["op"] for op in view["allowed"]} == {"users.list_with_sign_in_activity"}
        prohibited = {op["op"]: op["method"] for op in view["prohibited"]}
        assert prohibited.get("users.update") == "PATCH"

        # 3: start the run; tenant and actor come from the session.
        created = client.post("/runs", json={"task_id": TASK_ID, "params": {"inactive_days": 90}}, headers=headers)
        assert created.status_code == 201, created.text
        run_id = created.json()["id"]

        # 4 + 5 + 8: the runner claims and runs the task in the sandbox; the allowed op
        # succeeds across three pages; the result lists the expected dormant users.
        run = _poll_until_terminal(client, headers, run_id)
        assert run["status"] == "completed", run
        result = run["result"]
        assert result["counts"] == EXPECTED_COUNTS
        assert _upns(result["dormant"]) == EXPECTED_DORMANT
        assert _upns(result["never_signed_in"]) == EXPECTED_NEVER
        # 6: the probe's prohibited write was denied (and, below, never reached Graph).
        assert result["write_probe"]["denied"] is True
        assert result["write_probe"]["reason"] in ("prohibited", "not_in_manifest")

        # 7: the audit view shows the run's evidence and a valid chain.
        audit = client.get(f"/runs/{run_id}/audit", headers=headers).json()
    assert audit["chain"]["valid"] is True
    events = audit["events"]
    kinds = [e["event_type"] for e in events]
    assert kinds.count("GRAPH_REQUEST") == 3 and kinds.count("GRAPH_RESPONSE") == 3
    for required in ("RUN_REQUESTED", "RUN_STARTED", "CREDENTIAL_ACQUIRED", "RUN_COMPLETED"):
        assert required in kinds, kinds
    assert any(e["event_type"] == "OP_DECISION" and e["status"] == "allowed"
               and e["operation"] == "users.list_with_sign_in_activity" for e in events)
    assert any(e["event_type"] == "OP_DECISION" and e["status"] == "denied"
               and e["operation"] == "users.update" for e in events)
    # The denied write produced no Graph intent.
    assert not any(e["event_type"] == "GRAPH_REQUEST" and e["operation"] == "users.update" for e in events)

    # The Graph-side proof: assert the fake Graph's OWN request log, not the audit.
    graph = stack.graph_requests()
    assert len(graph) == 3, graph  # exactly the three pages
    assert all(r["method"] == "GET" for r in graph), graph
    assert all(r["path"] == "/v1.0/users" for r in graph), graph
    assert all(r["has_auth"] for r in graph), graph  # the broker sent a bearer token to Graph
    # No write and no non-users path ever reached Graph.
    assert not any(r["method"] != "GET" or r["path"] != "/v1.0/users" for r in graph)


def test_non_premium_tenant_fails_licence_required(stack):
    headers = stack.session_cookie()
    stack.graph_reset()
    stack.graph_set_mode("non_premium")
    try:
        with _client(stack) as client:
            created = client.post("/runs", json={"task_id": TASK_ID, "params": {"inactive_days": 90}},
                                  headers=headers)
            assert created.status_code == 201, created.text
            run = _poll_until_terminal(client, headers, created.json()["id"])
    finally:
        stack.graph_set_mode("premium")
    # The planned FAILED / licence_required mapping (Review Focus 2).
    assert run["status"] == "failed", run
    assert run["outcome"] == "licence_required", run
    # Only GET /v1.0/users reached Graph (the attempt that got the 403); no write.
    graph = stack.graph_requests()
    assert graph and all(r["method"] == "GET" and r["path"] == "/v1.0/users" for r in graph), graph
