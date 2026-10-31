"""Sign-in pieces that need no database (Task 6, SD-029). The end-to-end flow
against Postgres is tests/db/test_signin.py."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest

from clw.api.middleware.rate_limit import RATE_LIMITS
from clw.api.routes import auth as auth_routes
from clw.auth import signin
from clw.auth.signin import SignInError, start_sign_in
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)

CLIENT_ID = str(uuid.uuid4())


class FakeDb:
    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        pass


@pytest.fixture
def env(auth_env, monkeypatch):
    def configure(environment="test", client_id=CLIENT_ID, secret="s3cret-value", redirect="http://localhost:8000/cb"):
        auth_env(environment=environment)
        for name, value in (("MICROSOFT_CLIENT_ID", client_id), ("MICROSOFT_CLIENT_SECRET", secret),
                            ("OIDC_REDIRECT_URI", redirect)):
            if value is None:
                monkeypatch.delenv(name, raising=False)
            else:
                monkeypatch.setenv(name, value)
        from clw.common import config

        config.get_settings.cache_clear()

    configure()
    return configure


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


async def test_authorize_request(env):
    db = FakeDb()
    started = await start_sign_in(db)
    url = urlsplit(started.authorize_url)
    params = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert (url.scheme, url.netloc, url.path) == ("https", "login.microsoftonline.com", "/organizations/oauth2/v2.0/authorize")
    assert params["prompt"] == "login"  # SD-055: always interactive
    assert set(params) == {"prompt", "client_id", "response_type", "redirect_uri", "response_mode", "scope", "state",
                           "nonce",
                           "code_challenge", "code_challenge_method"}
    assert (params["client_id"], params["response_type"], params["scope"]) == (CLIENT_ID, "code", "openid profile")
    assert params["code_challenge_method"] == "S256"
    # nonce and PKCE verifier are bound to the login cookie; the row holds hashes only.
    cookie = started.login_cookie
    assert params["nonce"] == signin._derive("nonce", cookie)
    assert params["code_challenge"] == _b64(hashlib.sha256(signin._derive("pkce", cookie).encode()).digest())
    (row,) = db.added
    assert row.state_hash == hashlib.sha256(params["state"].encode()).hexdigest()
    assert row.binding_hash == hashlib.sha256(cookie.encode()).hexdigest()
    assert row.nonce_hash == hashlib.sha256(params["nonce"].encode()).hexdigest()
    assert cookie not in started.authorize_url
    assert "secret" not in started.authorize_url


async def test_each_sign_in_is_fresh(env):
    a, b = await start_sign_in(FakeDb()), await start_sign_in(FakeDb())
    assert a.login_cookie != b.login_cookie and a.authorize_url != b.authorize_url


@pytest.mark.parametrize(
    "kw",
    [
        {"client_id": None}, {"client_id": "not-a-guid"}, {"client_id": CLIENT_ID.upper()},
        {"secret": None}, {"secret": ""},
        {"redirect": None}, {"redirect": "ftp://x/cb"}, {"redirect": "http://evil.example/cb"},
        {"environment": "production"},  # http://localhost is development-only
    ],
)
async def test_incomplete_configuration_refuses_sign_in(env, kw):
    env(**kw)
    with pytest.raises(SignInError) as info:
        await start_sign_in(FakeDb())
    assert info.value.reason == "config_invalid" and info.value.status_code == 500


async def test_production_accepts_https_redirect(env):
    env(environment="production", redirect="https://workbench.example/auth/microsoft/callback")
    assert (await start_sign_in(FakeDb())).authorize_url


def _token(payload) -> str:
    return f"{_b64(b'{}')}.{_b64(json.dumps(payload).encode()) if not isinstance(payload, bytes) else _b64(payload)}.sig"


@pytest.mark.parametrize(
    "token,expected",
    [
        (_token({"tid": "0b9c7e64-1a2b-4c3d-8e9f-001122334455"}), "0b9c7e64-1a2b-4c3d-8e9f-001122334455"),
        (_token({"tid": "0B9C7E64-1A2B-4C3D-8E9F-001122334455"}), None),
        (_token({"tid": "common"}), None),
        (_token({"tid": 7}), None),
        (_token({}), None),
        (_token(["tid"]), None),
        (_token(b"not json"), None),
        ("no-dots", None),
        ("a.!!!.c", None),
    ],
)
def test_unverified_tid_only_accepts_a_guid(token, expected):
    assert signin._unverified_tid(token) == expected


def test_sign_in_errors_carry_no_identifiers():
    exc = SignInError("id_token_invalid", detail="tid_mismatch")
    assert str(exc) == "sign-in refused: id_token_invalid (tid_mismatch)" and exc.status_code == 401
    with pytest.raises(ValueError):
        SignInError("made_up")
    statuses = {r: SignInError(r).status_code for r in signin._STATUS}
    assert statuses["state_invalid"] == 400 and statuses["not_a_member"] == 403
    assert statuses["tenant_not_registered"] == 403  # same status and body as not_a_member: no tenant oracle


@pytest.mark.parametrize("path", ["//evil.example/", "https://evil.example/", "/\\evil.example", "app", ""])
def test_post_login_path_must_be_local(env, monkeypatch, caplog, path):
    from fastapi import HTTPException

    from clw.common import config

    monkeypatch.setenv("POST_LOGIN_PATH", path)
    config.get_settings.cache_clear()
    with caplog.at_level("WARNING"), pytest.raises(HTTPException):
        auth_routes._post_login_path()
    # The operator learns why sign-in is unavailable; the value itself isn't logged.
    assert "sign_in_refused reason=post_login_path_invalid" in caplog.text
    assert not path or path not in caplog.text


def test_rate_limit_rules_name_registered_routes():
    # SD-027 limit: a rule naming a missing route limits nothing. runs_create
    # belongs to the runs routes (Task 16).
    from clw.api.routes.runs import router as runs_router
    from clw.api.routes.scripts import router as scripts_router
    from clw.api.ui.pages import router as ui_router

    # FastAPI 0.143 no longer flattens included routers into app.routes, so
    # names come from the routers the app includes.
    names = {getattr(route, "name", None)
             for router in (auth_routes.router, runs_router, scripts_router, ui_router) for route in router.routes}
    for name in RATE_LIMITS:
        assert name in names, name  # a rule naming no route would limit nothing
