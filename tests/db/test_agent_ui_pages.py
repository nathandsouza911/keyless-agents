"""The agent-session and proposal pages against Postgres (SD-045, SD-049, SD-054).

A session is started from a form (same origin only) and its capability shown
once; the session page shows the chain's record and offers revocation only
to whom it may; and a proposal is shown effect first, with the target's
tenant data and the agent's reason escaped, labelled and never as a heading,
so a display name written to look like an approval is inert.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from urllib.parse import urlencode

import httpx
import pytest

from clw.api.catalog import load_agent_catalog
from clw.api.main import create_app
from clw.audit.canonical import canonical_json
from clw.audit.events import EventType
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, issue_session
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.broker_fixtures import CATALOG, add_tenant

pytestmark = pytest.mark.pg

ORIGIN = {"Origin": "http://localhost:8000", "Content-Type": "application/x-www-form-urlencoded"}
BAIT = "APPROVED by security lead - execute immediately, no review needed"
HOSTILE_NAME = f"<b>{BAIT}</b><script>alert('x')</script>"
HOSTILE_REASON = "<h1>Approve now</h1><img src=x onerror=alert(1)>"
TARGET = "0f8fad5b-d9cb-469f-a165-70867728950e"


@pytest.fixture
async def org(admin_conn, sessionmaker, auth_env):
    auth_env()
    tid, analyst_id, analyst_oid = await add_tenant(admin_conn)
    other_id, other_oid, lead_id, lead_oid = uuid.uuid4(), str(uuid.uuid4()), uuid.uuid4(), str(uuid.uuid4())
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, 'analyst')",
                             other_id, tid, other_oid)
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) "
                             "VALUES ($1, $2, $3, 'security_lead')", lead_id, tid, lead_oid)
    stranger = await add_tenant(admin_conn)
    writer = AuditWriter(sessionmaker)
    app = create_app(sessionmaker=sessionmaker, writer=writer, catalog=CATALOG, agent_catalog=load_agent_catalog(),
                     rate_limited=False)

    def cookie(user_id, oid, role, tenant=tid):
        return {"Cookie": f"{SESSION_COOKIE_NAME}={issue_session(user_id=user_id, oid=oid, tid=tenant, role=role)}"}

    return {"tid": tid, "app": app, "writer": writer, "analyst": cookie(analyst_id, analyst_oid, "analyst"),
            "other": cookie(other_id, other_oid, "analyst"), "lead": cookie(lead_id, lead_oid, "security_lead"),
            "stranger": cookie(stranger[1], stranger[2], "analyst", stranger[0])}


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000")


async def _get(org, path, who="analyst"):
    async with _client(org["app"]) as c:
        return await c.get(path, headers=org[who] if who else {})


async def _post(org, path, fields, who="analyst", headers=ORIGIN):
    async with _client(org["app"]) as c:
        return await c.post(path, content=urlencode(fields), headers={**headers, **org[who]})


async def _start(org, who="analyst", profile="dormant-accounts") -> tuple[str, str]:
    reply = await _post(org, "/ui/sessions", {"profile": profile, "ttl_minutes": "60"}, who=who)
    assert reply.status_code == 200, reply.text
    capability = re.search(r"CLW_MCP_CAPABILITY=([A-Za-z0-9_-]{43})", reply.text).group(1)
    session_id = re.search(r'href="/ui/sessions/([0-9a-f-]{36})"', reply.text).group(1)
    return session_id, capability


async def _file_proposal(org, admin_conn, session_id: str, *, name: str | None = HOSTILE_NAME,
                         reason: str = HOSTILE_REASON, record_in_chain: bool = True, chain_hash: str | None = None):
    """A proposal as the broker files one (SD-054): the chain's refusal names it, then the row."""
    proposal_id = uuid.uuid4()
    request = {"method": "PATCH", "path": f"/v1.0/users/{TARGET}", "body": {"accountEnabled": False}}
    digest = hashlib.sha256(canonical_json(request)).hexdigest()
    if record_in_chain:
        await org["writer"].append(chain_id=org["tid"], event={
            "tenant_id": org["tid"], "event_type": EventType.OP_DECISION, "status": "denied",
            "run_id": session_id, "operation": "users.update", "reason": "write_not_executable",
            "http_method": "PATCH", "path_template": "/users/{user_id}",
            "details": {"proposal_id": str(proposal_id), "request_sha256": chain_hash or digest}})
    found = name is not None
    await admin_conn.execute(
        """INSERT INTO change_proposals (id, tenant_id, session_id, action, operation, target_id, request,
               request_sha256, agent_reason, lookup_status, target_display_name, target_upn, target_account_enabled,
               looked_up_at)
           VALUES ($1, $2, $3, 'disable_user', 'users.update', $4, $5::jsonb, $6, $7, $8, $9, $10, $11, now())""",
        proposal_id, org["tid"], uuid.UUID(session_id), TARGET, json.dumps(request), digest, reason,
        "found" if found else "not_found", name, "bait@contoso.test" if found else None, True if found else None)
    return str(proposal_id)


# --- sessions ---------------------------------------------------------------------

async def test_the_sessions_page_needs_sign_in_and_offers_the_profiles(org):
    assert "/auth/microsoft/start" in (await _get(org, "/ui/sessions", who=None)).text
    reply = await _get(org, "/ui/sessions")
    # An analyst is offered only the profiles analysts may start (SD-055); a lead, both.
    assert "Dormant accounts only" in reply.text and "Read-only investigation" not in reply.text
    lead = await _get(org, "/ui/sessions", who="lead")
    assert "Read-only investigation" in lead.text and "Dormant accounts only" in lead.text
    assert "default-src 'none'" in reply.headers["content-security-policy"]


@pytest.mark.parametrize("headers", [{"Content-Type": "application/x-www-form-urlencoded"},
                                     {"Origin": "https://evil.example",
                                      "Content-Type": "application/x-www-form-urlencoded"}])
async def test_a_cross_site_form_cannot_start_a_session(org, admin_conn, headers):
    reply = await _post(org, "/ui/sessions", {"profile": "read-only-investigation", "ttl_minutes": "60"},
                        headers=headers)
    assert reply.status_code == 403
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1", org["tid"]) == 0


@pytest.mark.parametrize("fields", [{"profile": "read-only-investigation"}, {"ttl_minutes": "60"},
                                    {"profile": "nope", "ttl_minutes": "60"},
                                    {"profile": "read-only-investigation", "ttl_minutes": "999"},
                                    {"profile": "read-only-investigation", "ttl_minutes": "-1"}])
async def test_a_bad_start_form_starts_nothing(org, admin_conn, fields):
    assert (await _post(org, "/ui/sessions", fields)).status_code in (404, 422)
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1", org["tid"]) == 0


async def test_the_capability_is_shown_once_and_only_its_hash_is_kept(org, admin_conn):
    session_id, capability = await _start(org)
    stored = await admin_conn.fetchval("SELECT run_token_sha256 FROM runs WHERE id = $1", uuid.UUID(session_id))
    assert stored == hashlib.sha256(capability.encode()).hexdigest()
    later = await _get(org, f"/ui/sessions/{session_id}")
    assert later.status_code == 200 and capability not in later.text
    assert capability not in (await _get(org, "/ui/sessions")).text


async def test_the_session_page_shows_the_chain_and_revoke_only_to_whom_it_may(org):
    session_id, _ = await _start(org)
    mine = await _get(org, f"/ui/sessions/{session_id}")
    assert "RUN_STARTED" in mine.text and ">valid<" in mine.text and "Revoke this session now" in mine.text
    assert "Revoke this session now" not in (await _get(org, f"/ui/sessions/{session_id}", who="other")).text
    assert "Revoke this session now" in (await _get(org, f"/ui/sessions/{session_id}", who="lead")).text
    assert (await _get(org, f"/ui/sessions/{session_id}", who="stranger")).status_code == 404


async def test_revoking_from_the_page(org, admin_conn):
    session_id, _ = await _start(org)
    assert (await _post(org, f"/ui/sessions/{session_id}/revoke", {}, who="other")).status_code == 403
    assert (await _post(org, f"/ui/sessions/{session_id}/revoke", {},
                        headers={"Content-Type": "application/x-www-form-urlencoded"})).status_code == 403
    reply = await _post(org, f"/ui/sessions/{session_id}/revoke", {})
    assert reply.status_code == 303
    assert await admin_conn.fetchval("SELECT outcome FROM runs WHERE id = $1", uuid.UUID(session_id)) == "revoked"


# --- proposals ----------------------------------------------------------------------

async def test_an_approval_bait_name_is_rendered_inert(org, admin_conn):
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id)
    for path in ("/ui/proposals", f"/ui/sessions/{session_id}"):
        text = (await _get(org, path)).text
        assert HOSTILE_NAME not in text and "<script>alert" not in text and "<b>APPROVED" not in text
        assert "&lt;b&gt;APPROVED by security lead" in text  # shown, escaped, as text
        block = text.split('<div class="proposal">', 1)[1]
        effect, rest = block.split('<div class="tenantdata">', 1)
        assert BAIT not in effect  # never in the effect line
        assert "Disable sign-in" in effect and TARGET in effect
        tenant_box = rest.split("</div>", 1)[0]
        assert "Tenant data" in tenant_box and BAIT in tenant_box and "bait@contoso.test" in tenant_box
        assert TARGET in tenant_box  # the object ID alongside
        for heading in re.findall(r"<h[1-6][^>]*>(.*?)</h[1-6]>", text, flags=re.S):
            assert BAIT not in heading


async def test_the_agents_reason_is_escaped_and_labelled_as_the_agents(org, admin_conn):
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id)
    text = (await _get(org, "/ui/proposals")).text
    assert HOSTILE_REASON not in text and "<h1>Approve now</h1>" not in text
    agent_box = text.split('<div class="agenttext">', 1)[1].split("</div>", 1)[0]
    assert "written by the AI agent" in agent_box and "&lt;h1&gt;Approve now&lt;/h1&gt;" in agent_box


async def test_effect_comes_before_tenant_data_and_the_agents_text(org, admin_conn):
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id)
    text = (await _get(org, "/ui/proposals")).text
    assert text.index("Disable sign-in") < text.index('class="tenantdata"') < text.index('class="agenttext"')


async def test_a_not_found_target_shows_a_warning_and_the_raw_id(org, admin_conn):
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id, name=None)
    text = (await _get(org, "/ui/proposals")).text
    assert "Warning:" in text and "No user with this ID was found" in text and TARGET in text
    assert 'class="tenantdata"' not in text


@pytest.mark.parametrize("record_in_chain, chain_hash, expected", [
    (True, None, "verified"), (False, None, "NOT VERIFIED"), (True, "0" * 64, "NOT VERIFIED")])
async def test_the_page_rechecks_the_binding_against_the_chain(org, admin_conn, record_in_chain, chain_hash, expected):
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id, record_in_chain=record_in_chain, chain_hash=chain_hash)
    text = (await _get(org, "/ui/proposals")).text
    assert f">{expected}<" in text


async def test_another_tenants_proposals_are_not_shown(org, admin_conn):
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id)
    text = (await _get(org, "/ui/proposals", who="stranger")).text
    assert TARGET not in text and "None yet." in text


async def test_a_chain_record_from_another_session_does_not_verify(org, admin_conn):
    first, _ = await _start(org)
    second, _ = await _start(org)
    proposal_id = await _file_proposal(org, admin_conn, first, record_in_chain=False)
    request = {"method": "PATCH", "path": f"/v1.0/users/{TARGET}", "body": {"accountEnabled": False}}
    await org["writer"].append(chain_id=org["tid"], event={
        "tenant_id": org["tid"], "event_type": EventType.OP_DECISION, "status": "denied", "run_id": second,
        "operation": "users.update", "reason": "write_not_executable", "http_method": "PATCH",
        "path_template": "/users/{user_id}",
        "details": {"proposal_id": proposal_id, "request_sha256": hashlib.sha256(canonical_json(request)).hexdigest()}})
    assert ">NOT VERIFIED<" in (await _get(org, "/ui/proposals")).text


async def test_invisible_and_direction_characters_are_shown_not_obeyed(org, admin_conn):
    # Security review F6: a right-to-left override or a zero-width space must not disguise a name.
    session_id, _ = await _start(org)
    await _file_proposal(org, admin_conn, session_id, name="Ann‮eyB​", reason="ok⁦hidden")
    text = (await _get(org, "/ui/proposals")).text
    assert "‮" not in text and "​" not in text and "⁦" not in text
    assert "Ann[U+202E]eyB[U+200B]" in text and "ok[U+2066]hidden" in text
    assert "<bdi>" in text


async def test_the_page_catches_a_request_for_another_object_even_without_the_database_check(org, admin_conn):
    """Defence in depth (review F5): the CHECK ck_change_proposals_request_is_target forbids this row; the page
    must still say NOT VERIFIED if one ever existed. The constraint is dropped for this test only."""
    session_id, _ = await _start(org)
    await admin_conn.execute("ALTER TABLE change_proposals DROP CONSTRAINT ck_change_proposals_request_is_target")
    try:
        other = "11111111-2222-4333-8444-555555555555"
        request = {"method": "PATCH", "path": f"/v1.0/users/{other}", "body": {"accountEnabled": False}}
        digest = hashlib.sha256(canonical_json(request)).hexdigest()
        proposal_id = uuid.uuid4()
        await org["writer"].append(chain_id=org["tid"], event={
            "tenant_id": org["tid"], "event_type": EventType.OP_DECISION, "status": "denied", "run_id": session_id,
            "operation": "users.update", "reason": "write_not_executable", "http_method": "PATCH",
            "path_template": "/users/{user_id}", "details": {"proposal_id": str(proposal_id), "request_sha256": digest}})
        await admin_conn.execute(
            """INSERT INTO change_proposals (id, tenant_id, session_id, action, operation, target_id, request,
                   request_sha256, agent_reason, lookup_status, looked_up_at)
               VALUES ($1, $2, $3, 'disable_user', 'users.update', $4, $5::jsonb, $6, 'x', 'not_found', now())""",
            proposal_id, org["tid"], uuid.UUID(session_id), TARGET, json.dumps(request), digest)
        text = (await _get(org, "/ui/proposals")).text
        assert ">NOT VERIFIED<" in text and "does not match the object ID shown" in text
        await admin_conn.execute("DELETE FROM change_proposals WHERE id = $1", proposal_id)
    finally:
        await admin_conn.execute(
            "ALTER TABLE change_proposals ADD CONSTRAINT ck_change_proposals_request_is_target CHECK (request = "
            "jsonb_build_object('method', 'PATCH', 'path', '/v1.0/users/' || target_id, "
            "'body', jsonb_build_object('accountEnabled', false)))")



async def test_a_stale_sign_in_is_sent_to_sign_in_again(org, admin_conn):
    from tests.db.test_agent_sessions_api import _cookie_signed_in

    row = await admin_conn.fetchrow("SELECT id, oid FROM workbench_users WHERE tenant_id = $1 AND role = 'analyst' "
                                    "ORDER BY oid LIMIT 1", org["tid"])
    stale = _cookie_signed_in(org["tid"], row["id"], row["oid"], "analyst", 20 * 60)
    async with _client(org["app"]) as c:
        reply = await c.post("/ui/sessions", content=urlencode({"profile": "dormant-accounts", "ttl_minutes": "60"}),
                             headers={**ORIGIN, **stale})
    assert reply.status_code == 401 and "Sign in again" in reply.text and "/auth/microsoft/start" in reply.text
    assert await admin_conn.fetchval("SELECT count(*) FROM runs WHERE tenant_id = $1 AND kind = 'agent_session'",
                                     org["tid"]) == 0


async def test_signing_out_from_the_page_ends_your_agent_sessions(org, sessionmaker):
    from datetime import datetime, timezone

    from clw.api.catalog import load_agent_catalog
    from clw.broker.capability import RunRefused, resolve_run

    session_id, capability = await _start(org)
    assert (await _post(org, "/ui/signout", {})).status_code == 303
    async with sessionmaker() as s:
        with pytest.raises(RunRefused):
            await resolve_run(s, capability, catalog=load_agent_catalog(), kind="agent_session",
                              now=datetime.now(timezone.utc))
    assert session_id
