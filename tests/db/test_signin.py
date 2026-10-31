"""Analyst sign-in end to end through the routes (Task 6, SD-029; threat-model
T5, T7). Real Postgres (admin connection: the api role's grants come with the
deployment); Microsoft's token endpoint and JWKS are mocked with respx."""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlsplit

import asyncpg
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from jwt.algorithms import RSAAlgorithm
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.api.deps import Principal, current_principal
from clw.api.middleware.rate_limit import enforce_rate_limit
from clw.api.routes.auth import router as auth_router
from clw.auth.session_jwt import SESSION_COOKIE_NAME, SessionInvalid, decode_session
from clw.auth.signin import LOGIN_COOKIE_NAME, TOKEN_URL
from clw.db.session import get_session
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)
from tests.db.conftest import _sqlalchemy_url

pytestmark = pytest.mark.pg

CLIENT_ID = str(uuid.uuid4())
REDIRECT = "http://localhost:8000/auth/microsoft/callback"
KID = "signin-test-kid"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
async def db(pg_dsn):
    engine = create_async_engine(_sqlalchemy_url(pg_dsn))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
def env(auth_env, monkeypatch):
    def configure(environment: str = "test"):
        auth_env(environment=environment)
        monkeypatch.setenv("MICROSOFT_CLIENT_ID", CLIENT_ID)
        monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "test-client-secret-" + uuid.uuid4().hex)
        monkeypatch.setenv("OIDC_REDIRECT_URI", REDIRECT)
        monkeypatch.setenv("POST_LOGIN_PATH", "/app")
        from clw.common import config

        config.get_settings.cache_clear()

    configure()
    return configure


@pytest.fixture
async def admin(pg_dsn):
    conn = await asyncpg.connect(pg_dsn)
    yield conn
    await conn.close()


async def _tenant(admin, status: str = "active") -> str:
    tid = str(uuid.uuid4())
    await admin.execute("INSERT INTO tenants (id, display_name, status) VALUES ($1, 'Test tenant', $2)", tid, status)
    return tid


async def _member(admin, tid: str, role: str = "analyst") -> tuple[uuid.UUID, str]:
    user_id, oid = uuid.uuid4(), str(uuid.uuid4())
    await admin.execute("INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES ($1, $2, $3, $4)",
                        user_id, tid, oid, role)
    return user_id, oid


def _app(db, *, rate_limited: bool = True) -> FastAPI:
    app = FastAPI(dependencies=[Depends(enforce_rate_limit)] if rate_limited else [])
    app.include_router(auth_router)
    # Sign-out also ends the person's agent sessions (SD-055), through the app's database and audit writer.
    from clw.audit.writer import AuditWriter

    app.state.sessionmaker, app.state.writer = db, AuditWriter(db)

    @app.get("/whoami", name="whoami")
    async def whoami(principal: Principal = Depends(current_principal)):
        return {"tid": principal.tid, "oid": principal.oid, "role": principal.role, "user_id": str(principal.user_id)}

    async def session_override():
        async with db() as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    return app


def _client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000")


def _set_cookies(response: httpx.Response) -> dict[str, SimpleCookie]:
    cookies = {}
    for header in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        for name in parsed:
            cookies[name] = parsed[name]
    return cookies


class Flow:
    def __init__(self, response: httpx.Response):
        assert response.status_code == 302, response.text
        location = urlsplit(response.headers["location"])
        self.params = {k: v[0] for k, v in parse_qs(location.query).items()}
        self.location = location
        self.state = self.params["state"]
        self.nonce = self.params["nonce"]
        self.login_cookie = _set_cookies(response)[LOGIN_COOKIE_NAME].value
        self.start_response = response


async def _start(client) -> Flow:
    return Flow(await client.get("/auth/microsoft/start"))


def _id_token(key, *, tid, oid, nonce, iss_tid=None, **extra) -> str:
    now = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{iss_tid or tid}/v2.0", "aud": CLIENT_ID,
              "exp": now + 600, "iat": now, "nbf": now, "sub": "s-" + uuid.uuid4().hex, "oid": oid, "tid": tid,
              "nonce": nonce, "preferred_username": "analyst@example.test", **extra}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


def _jwks(key) -> dict:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": KID, "use": "sig"})
    return {"keys": [jwk]}


async def _callback(client, flow: Flow, *, mock, id_token=None, token_status=200, cookie="flow", extra=""):
    token_route = mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(token_status, json={"id_token": id_token, "token_type": "Bearer"}))
    client.cookies.clear()  # only the explicit Cookie header below reaches the callback
    headers = {}
    value = flow.login_cookie if cookie == "flow" else cookie
    if value is not None:
        headers["Cookie"] = f"{LOGIN_COOKIE_NAME}={value}"
    response = await client.get(f"/auth/microsoft/callback?state={flow.state}&code=auth-code-1{extra}", headers=headers)
    return response, token_route


def _jwks_route(mock, tid, key):
    return mock.get(f"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys").mock(
        return_value=httpx.Response(200, json=_jwks(key)))


# ---------------------------------------------------------------- the successful path


async def test_member_gets_a_session_with_tid_and_oid_from_the_verified_token(env, db, admin, rsa_key):
    tid = await _tenant(admin)
    user_id, oid = await _member(admin, tid, role="security_lead")
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    assert response.status_code == 303 and response.headers["location"] == "/app"
    cookies = _set_cookies(response)
    session = await decode_session(cookies[SESSION_COOKIE_NAME].value)
    assert (session.tid, session.oid, session.user_id, session.role) == (tid, oid, user_id, "security_lead")
    assert cookies[LOGIN_COOKIE_NAME]["max-age"] == "0"  # login cookie cleared


async def test_whoami_principal_comes_from_the_session_only(env, db, admin, rsa_key):
    tid, other_tid = await _tenant(admin), await _tenant(admin)
    _, oid = await _member(admin, tid)
    app = _app(db)
    async with _client(app) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    token = _set_cookies(response)[SESSION_COOKIE_NAME].value
    async with _client(app) as client:
        me = await client.get(f"/whoami?tid={other_tid}", headers={
            "Cookie": f"{SESSION_COOKIE_NAME}={token}", "X-Tenant-Id": other_tid, "Authorization": "Bearer junk"})
        anonymous = await client.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["tid"] == tid
    assert anonymous.status_code == 401  # sessions are read from the cookie only


async def test_callback_tid_query_parameter_is_ignored(env, db, admin, rsa_key):
    tid, other_tid = await _tenant(admin), await _tenant(admin)
    _, oid = await _member(admin, tid)
    await _member(admin, other_tid)
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock, extra=f"&tid={other_tid}&tenant={other_tid}",
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    assert response.status_code == 303
    assert (await decode_session(_set_cookies(response)[SESSION_COOKIE_NAME].value)).tid == tid


async def test_token_request_uses_pkce_secret_and_registered_redirect(env, db, admin, rsa_key):
    tid = await _tenant(admin)
    _, oid = await _member(admin, tid)
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        _, token_route = await _callback(client, flow, mock=mock,
                                         id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    sent = {k: v[0] for k, v in parse_qs(token_route.calls.last.request.content.decode()).items()}
    assert sent["grant_type"] == "authorization_code" and sent["code"] == "auth-code-1"
    assert sent["client_id"] == CLIENT_ID and sent["client_secret"].startswith("test-client-secret-")
    assert sent["redirect_uri"] == REDIRECT
    challenge = base64.urlsafe_b64encode(hashlib.sha256(sent["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert challenge == flow.params["code_challenge"] and flow.params["code_challenge_method"] == "S256"


# ---------------------------------------------------------------- state: unknown, reused, expired, unbound


async def test_unknown_state_rejected(env, db, admin):
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        flow.state = "never-issued-" + uuid.uuid4().hex
        response, token_route = await _callback(client, flow, mock=mock, id_token="x")
    assert response.status_code == 400 and response.json() == {"detail": "sign_in_failed"}
    assert not token_route.called and SESSION_COOKIE_NAME not in _set_cookies(response)


async def test_reused_state_rejected(env, db, admin, rsa_key):
    tid = await _tenant(admin)
    _, oid = await _member(admin, tid)
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        token = _id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce)
        first, token_route = await _callback(client, flow, mock=mock, id_token=token)
        redeemed = token_route.call_count
        second, _ = await _callback(client, flow, mock=mock, id_token=token)
    assert first.status_code == 303 and redeemed == 1
    assert second.status_code == 400 and token_route.call_count == 1  # never redeemed again
    assert SESSION_COOKIE_NAME not in _set_cookies(second)


async def test_expired_login_rejected(env, db, admin):
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        state_hash = hashlib.sha256(flow.state.encode()).hexdigest()
        await admin.execute("UPDATE oidc_logins SET created_at = now() - interval '601 seconds' WHERE state_hash = $1",
                            state_hash)
        response, token_route = await _callback(client, flow, mock=mock, id_token="x")
    assert response.status_code == 400 and not token_route.called


@pytest.mark.parametrize("cookie", [None, "", "someone-elses-login-cookie"])
async def test_login_bound_to_the_starting_browser(env, db, admin, cookie):
    # Login CSRF: a victim following an attacker's callback link has no (or a different) login cookie.
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        response, token_route = await _callback(client, flow, mock=mock, id_token="x", cookie=cookie)
        assert response.status_code == 400 and not token_route.called
        if cookie:  # the state was claimed and burned: the right cookie no longer helps
            retry, _ = await _callback(client, flow, mock=mock, id_token="x")
            assert retry.status_code == 400


async def test_cookie_from_another_sign_in_does_not_fit(env, db, admin):
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        attacker, victim = await _start(client), await _start(client)
        response, token_route = await _callback(client, victim, mock=mock, id_token="x", cookie=attacker.login_cookie)
    assert response.status_code == 400 and not token_route.called


# ---------------------------------------------------------------- the ID token (T5) and the tenant


async def test_nonce_mismatch_rejected(env, db, admin, rsa_key):
    tid = await _tenant(admin)
    _, oid = await _member(admin, tid)
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        other = await _start(client)  # a real nonce, but from another sign-in
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=other.nonce))
    assert response.status_code == 401 and SESSION_COOKIE_NAME not in _set_cookies(response)


async def test_id_token_for_another_tenant_issuer_rejected(env, db, admin, rsa_key):
    tid, other_tid = await _tenant(admin), await _tenant(admin)
    _, oid = await _member(admin, tid)
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock, id_token=_id_token(
            rsa_key, tid=tid, oid=oid, nonce=flow.nonce, iss_tid=other_tid))
    assert response.status_code == 401


@pytest.mark.parametrize("status", ["unregistered", "disabled"])
async def test_unregistered_or_disabled_tenant_denied_before_verification(env, db, admin, rsa_key, status):
    tid = str(uuid.uuid4()) if status == "unregistered" else await _tenant(admin, status="disabled")
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        jwks = _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=str(uuid.uuid4()), nonce=flow.nonce))
    assert response.status_code == 403 and response.json() == {"detail": "access_denied"}
    assert not jwks.called and SESSION_COOKIE_NAME not in _set_cookies(response)


async def test_signin_unknown_membership_denied(env, db, admin, rsa_key):
    # T7: a valid token for a registered tenant, but (tid, oid) is not a workbench user.
    tid = await _tenant(admin)
    await _member(admin, tid)  # someone else
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=str(uuid.uuid4()), nonce=flow.nonce))
    assert response.status_code == 403 and response.json() == {"detail": "access_denied"}
    assert SESSION_COOKIE_NAME not in _set_cookies(response)


async def test_member_of_another_tenant_denied(env, db, admin, rsa_key):
    tid, other_tid = await _tenant(admin), await _tenant(admin)
    _, oid = await _member(admin, other_tid)  # same oid string, but registered under another tenant
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    assert response.status_code == 403


@pytest.mark.parametrize("status", [400, 500])
async def test_failed_code_redemption_fails_closed(env, db, admin, status):
    async with _client(_app(db)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        response, _ = await _callback(client, flow, mock=mock, id_token="x", token_status=status)
    assert response.status_code == 401 and SESSION_COOKIE_NAME not in _set_cookies(response)


async def test_token_endpoint_redirect_is_not_followed(env, db, admin, rsa_key):
    tid = await _tenant(admin)
    _, oid = await _member(admin, tid)
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        mock.post(TOKEN_URL).mock(return_value=httpx.Response(307, headers={"location": "https://evil.example/token"}))
        evil = mock.post("https://evil.example/token").mock(return_value=httpx.Response(200, json={
            "id_token": _id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce)}))
        _jwks_route(mock, tid, rsa_key)
        client.cookies.clear()
        response = await client.get(f"/auth/microsoft/callback?state={flow.state}&code=c",
                                    headers={"Cookie": f"{LOGIN_COOKIE_NAME}={flow.login_cookie}"})
    assert response.status_code == 401 and not evil.called
    assert SESSION_COOKIE_NAME not in _set_cookies(response)


async def test_missing_code_burns_the_state(env, db, admin):
    async with _client(_app(db)) as client, respx.mock(assert_all_called=False) as mock:
        flow = await _start(client)
        response = await client.get(f"/auth/microsoft/callback?state={flow.state}&error=access_denied",
                                    headers={"Cookie": f"{LOGIN_COOKIE_NAME}={flow.login_cookie}"})
        retry, token_route = await _callback(client, flow, mock=mock, id_token="x")
    assert response.status_code == 400 and retry.status_code == 400 and not token_route.called


# ---------------------------------------------------------------- what is stored, cookies, logout


async def test_only_hashes_are_stored(env, db, admin):
    async with _client(_app(db)) as client:
        flow = await _start(client)
    row = await admin.fetchrow("SELECT * FROM oidc_logins WHERE state_hash = $1",
                               hashlib.sha256(flow.state.encode()).hexdigest())
    stored = " ".join(str(v) for v in row.values())
    for secret in (flow.state, flow.nonce, flow.login_cookie, flow.params["code_challenge"]):
        assert secret not in stored
    assert row["nonce_hash"] == hashlib.sha256(flow.nonce.encode()).hexdigest()
    assert row["used_at"] is None


@pytest.mark.parametrize("environment", ["test", "production"])
async def test_cookie_flags(env, db, admin, rsa_key, environment, monkeypatch):
    env(environment)
    tid = await _tenant(admin)
    _, oid = await _member(admin, tid)
    if environment == "production":
        # Production refuses a non-https redirect URI (config_invalid).
        from clw.common import config

        monkeypatch.setenv("OIDC_REDIRECT_URI", "https://workbench.example/auth/microsoft/callback")
        config.get_settings.cache_clear()
    # Production rate limiting needs Redis; this test is about cookies only.
    async with _client(_app(db, rate_limited=False)) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    login = _set_cookies(flow.start_response)[LOGIN_COOKIE_NAME]
    session = _set_cookies(response)[SESSION_COOKIE_NAME]
    secure = environment == "production"
    assert login["httponly"] and login["samesite"] == "lax" and login["path"] == "/auth/microsoft/callback"
    assert login["max-age"] == "600" and bool(login["secure"]) is secure
    assert session["httponly"] and session["samesite"] == "lax" and session["path"] == "/"
    assert session["max-age"] == str(8 * 3600) and bool(session["secure"]) is secure


async def test_logout_revokes_the_session(env, db, admin, rsa_key):
    tid = await _tenant(admin)
    _, oid = await _member(admin, tid)
    app = _app(db)
    async with _client(app) as client, respx.mock(assert_all_called=True) as mock:
        flow = await _start(client)
        _jwks_route(mock, tid, rsa_key)
        response, _ = await _callback(client, flow, mock=mock,
                                      id_token=_id_token(rsa_key, tid=tid, oid=oid, nonce=flow.nonce))
    token = _set_cookies(response)[SESSION_COOKIE_NAME].value
    cookie = {"Cookie": f"{SESSION_COOKIE_NAME}={token}"}
    async with _client(app) as client:
        assert (await client.get("/whoami", headers=cookie)).status_code == 200
        out = await client.post("/auth/logout", headers=cookie)
        assert out.status_code == 204 and _set_cookies(out)[SESSION_COOKIE_NAME]["max-age"] == "0"
        assert (await client.get("/whoami", headers=cookie)).status_code == 401
        assert (await client.post("/auth/logout", headers=cookie)).status_code == 401
        assert (await client.post("/auth/logout")).status_code == 401
    with pytest.raises(SessionInvalid):
        await decode_session(token)
