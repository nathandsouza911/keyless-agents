"""The quick start's demo sign-in and banner (SD-051), against Postgres.

The route exists only in demo mode, accepts only a same-origin form, and signs
in only the fictional tenant's registered person; every page then says DEMO
MODE. Outside demo mode there is no route and no banner.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from clw.api.catalog import load_agent_catalog
from clw.api.main import create_app
from clw.audit.writer import AuditWriter
from clw.auth.session_jwt import SESSION_COOKIE_NAME, decode_session
from clw.demo import DEMO_TENANT_ID, DEMO_TENANT_NAME, DEMO_USER_OID
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.broker_fixtures import CATALOG

pytestmark = pytest.mark.pg

ORIGIN = {"Origin": "http://localhost:8000", "Content-Type": "application/x-www-form-urlencoded"}
BANNER = "DEMO MODE: a fictional tenant on fake Microsoft Graph."


@pytest.fixture
async def demo_tenant(admin_conn):
    await admin_conn.execute("INSERT INTO tenants (id, display_name, status) VALUES ($1, $2, 'active') "
                             "ON CONFLICT (id) DO NOTHING", DEMO_TENANT_ID, DEMO_TENANT_NAME)
    await admin_conn.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) "
                             "VALUES ($1, $2, $3, 'security_lead') ON CONFLICT DO NOTHING",
                             uuid.uuid4(), DEMO_TENANT_ID, DEMO_USER_OID)


def _app(sessionmaker, demo: bool):
    return create_app(sessionmaker=sessionmaker, writer=AuditWriter(sessionmaker), catalog=CATALOG,
                      agent_catalog=load_agent_catalog(), rate_limited=False, demo_mode=demo)


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000")


async def test_outside_demo_mode_there_is_no_demo_sign_in_and_no_banner(sessionmaker, auth_env, demo_tenant):
    auth_env()
    async with _client(_app(sessionmaker, demo=False)) as c:
        assert (await c.get("/ui/demo-signin")).status_code == 404
        assert (await c.post("/ui/demo-signin", headers=ORIGIN)).status_code == 404
        page = await c.get("/ui")
    assert BANNER not in page.text and "/auth/microsoft/start" in page.text


async def test_demo_sign_in_signs_in_only_the_fictional_tenants_person(sessionmaker, auth_env, demo_tenant):
    auth_env()
    async with _client(_app(sessionmaker, demo=True)) as c:
        reply = await c.post("/ui/demo-signin", headers=ORIGIN)
        assert reply.status_code == 303 and reply.headers["location"] == "/ui/sessions"
        claims = await decode_session(reply.cookies[SESSION_COOKIE_NAME])
        assert (claims.tid, claims.oid, claims.role) == (DEMO_TENANT_ID, DEMO_USER_OID, "security_lead")
        sessions = await c.get("/ui/sessions", headers={"Cookie": f"{SESSION_COOKIE_NAME}={reply.cookies[SESSION_COOKIE_NAME]}"})
    assert sessions.status_code == 200 and "Start an agent session" in sessions.text


@pytest.mark.parametrize("headers", [{"Content-Type": "application/x-www-form-urlencoded"},
                                     {"Origin": "https://evil.example",
                                      "Content-Type": "application/x-www-form-urlencoded"}])
async def test_a_cross_site_form_cannot_sign_in(sessionmaker, auth_env, demo_tenant, headers):
    auth_env()
    async with _client(_app(sessionmaker, demo=True)) as c:
        reply = await c.post("/ui/demo-signin", headers=headers)
    assert reply.status_code == 403 and SESSION_COOKIE_NAME not in reply.cookies


async def test_without_the_fictional_tenant_set_up_nobody_is_signed_in(sessionmaker, auth_env, admin_conn):
    auth_env()
    await admin_conn.execute("DELETE FROM workbench_users WHERE tenant_id = $1 AND oid = $2 "
                             "AND NOT EXISTS (SELECT 1 FROM runs WHERE actor_oid = $2)", DEMO_TENANT_ID, DEMO_USER_OID)
    if await admin_conn.fetchval("SELECT count(*) FROM workbench_users WHERE oid = $1", DEMO_USER_OID):
        pytest.skip("the demo person has runs from an earlier test in this database")
    async with _client(_app(sessionmaker, demo=True)) as c:
        reply = await c.post("/ui/demo-signin", headers=ORIGIN)
    assert reply.status_code == 503 and SESSION_COOKIE_NAME not in reply.cookies


@pytest.mark.parametrize("path", ["/ui", "/ui/demo-signin", "/ui/sessions", "/ui/proposals",
                                  "/ui/sessions/not-a-session"])
async def test_every_page_says_demo_mode(sessionmaker, auth_env, demo_tenant, path):
    auth_env()
    async with _client(_app(sessionmaker, demo=True)) as c:
        cookie = (await c.post("/ui/demo-signin", headers=ORIGIN)).cookies[SESSION_COOKIE_NAME]
        signed_in = await c.get(path, headers={"Cookie": f"{SESSION_COOKIE_NAME}={cookie}"})
        anonymous = await c.get(path)
    assert BANNER in signed_in.text and BANNER in anonymous.text
