"""Analyst sign-in with Entra ID: authorization code + PKCE, single-use state
and nonce, workbench membership (Task 6, SD-029).

start_sign_in: a random `state` (sent to Microsoft) and a random browser
binding value (kept only in an HttpOnly login cookie). The OIDC `nonce` and
the PKCE verifier are derived from the binding value, so the ID token can
only be redeemed by the browser that started the sign-in. The database row
holds SHA-256 hashes of the state, nonce and binding value.

complete_sign_in, in order: claim the row by state, once, within 10 minutes
(unknown, reused or expired all fail the same way); the login cookie must
match the row; redeem the code (client secret + PKCE); select the tenant
by the token's tid, which must be a registered, active tenant (the one
unverified read, used only to pick the row; SD-029); verify the ID token
against that tenant (signature, issuer, audience, tid, nonce: SD-009);
require (tid, oid) in workbench_users; issue a session with tid and oid from
the verified token and the role from the membership row.

Errors carry a fixed reason for server-side logs; clients get only the
status. Nothing from the request selects a tenant.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from clw.auth.oidc import OIDCVerificationError, fetch_microsoft_jwks, verify_id_token
from clw.auth.session_jwt import issue_session
from clw.common.config import get_settings
from clw.db.models.oidc_login import OidcLogin
from clw.db.models.tenant import Tenant
from clw.db.models.workbench_user import WorkbenchUser

logger = logging.getLogger(__name__)

AUTHORIZE_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
SCOPE = "openid profile"
LOGIN_COOKIE_NAME = "clw_login"
LOGIN_TTL_SECONDS = 600
_TOKEN_TIMEOUT_SECONDS = 10
_MAX_PARAM_CHARS = 4096
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# reason -> HTTP status. Clients see the status only.
_STATUS = {
    "config_invalid": 500,
    "state_invalid": 400,
    "login_cookie_missing": 400,
    "binding_mismatch": 400,
    "code_missing": 400,
    "token_exchange_failed": 401,
    "id_token_missing": 401,
    "id_token_invalid": 401,
    "tenant_not_registered": 403,
    "not_a_member": 403,
}


class SignInError(Exception):
    """Sign-in refused. `reason` is a key of _STATUS; no token or identifier is carried."""

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        if reason not in _STATUS:
            raise ValueError("unknown sign-in failure reason")
        super().__init__(f"sign-in refused: {reason}" + (f" ({detail})" if detail else ""))
        self.reason = reason
        self.detail = detail  # e.g. the OIDCVerificationError reason code
        self.status_code = _STATUS[reason]


@dataclass(frozen=True, slots=True)
class SignInStart:
    authorize_url: str
    login_cookie: str


@dataclass(frozen=True, slots=True)
class SignInResult:
    session_token: str
    user_id: str
    tid: str
    oid: str
    role: str


@dataclass(frozen=True, slots=True)
class _Config:
    client_id: str
    client_secret: str
    redirect_uri: str


def _config() -> _Config:
    s = get_settings()
    client_id = s.MICROSOFT_CLIENT_ID
    secret = s.MICROSOFT_CLIENT_SECRET.get_secret_value() if s.MICROSOFT_CLIENT_SECRET else ""
    redirect = s.OIDC_REDIRECT_URI or ""
    local_http = not s.is_production and redirect.startswith(("http://localhost:", "http://127.0.0.1:"))
    if not (isinstance(client_id, str) and _GUID.fullmatch(client_id) and secret
            and (redirect.startswith("https://") or local_http)):
        raise SignInError("config_invalid")
    return _Config(client_id, secret, redirect)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _derive(label: str, binding: str) -> str:
    """43 URL-safe characters: a valid PKCE verifier and nonce."""
    return _b64url(hashlib.sha256(f"clw-{label}:{binding}".encode("ascii")).digest())


def _short_ascii(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_PARAM_CHARS and value.isascii()


async def start_sign_in(db: AsyncSession) -> SignInStart:
    cfg = _config()
    state = secrets.token_urlsafe(32)
    binding = secrets.token_urlsafe(32)
    nonce = _derive("nonce", binding)
    verifier = _derive("pkce", binding)
    db.add(OidcLogin(state_hash=_sha256_hex(state), nonce_hash=_sha256_hex(nonce), binding_hash=_sha256_hex(binding)))
    await db.commit()
    params = {
        "client_id": cfg.client_id,
        "response_type": "code",
        "redirect_uri": cfg.redirect_uri,
        "response_mode": "query",
        "scope": SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
        "code_challenge_method": "S256",
        # Always an interactive sign-in, never a silent single sign-on: starting an agent session needs a
        # recent one (SD-055, review F1), and a workbench sign-in is rare enough to ask for it every time.
        "prompt": "login",
    }
    return SignInStart(authorize_url=f"{AUTHORIZE_URL}?{urlencode(params)}", login_cookie=binding)


async def _claim(db: AsyncSession, state: str) -> tuple[str, str] | None:
    """Mark the login used, at most once and only while fresh. Committed at once."""
    row = (await db.execute(
        text(
            "UPDATE oidc_logins SET used_at = now() "
            "WHERE state_hash = :h AND used_at IS NULL "
            "AND created_at > now() - make_interval(secs => :ttl) "
            "RETURNING nonce_hash, binding_hash"
        ),
        {"h": _sha256_hex(state), "ttl": LOGIN_TTL_SECONDS},
    )).first()
    await db.commit()
    return None if row is None else (row[0], row[1])


async def _redeem_code(cfg: _Config, code: str, verifier: str) -> str:
    data = {
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": verifier,
        "scope": SCOPE,
    }
    try:
        async with httpx.AsyncClient(timeout=_TOKEN_TIMEOUT_SECONDS, follow_redirects=False) as http:
            response = await http.post(TOKEN_URL, data=data)
        body = response.json() if response.status_code == 200 else None
    except Exception:
        body = None
    if not isinstance(body, dict):
        raise SignInError("token_exchange_failed")
    id_token = body.get("id_token")
    if not _short_ascii(id_token):
        raise SignInError("id_token_missing")
    return id_token


def _unverified_tid(id_token: str) -> str | None:
    """The payload's tid, read WITHOUT verification, only to choose a tenant row."""
    try:
        payload = id_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None
    tid = claims.get("tid") if isinstance(claims, dict) else None
    return tid if isinstance(tid, str) and _GUID.fullmatch(tid) else None


async def complete_sign_in(db: AsyncSession, *, state: object, code: object, login_cookie: object) -> SignInResult:
    cfg = _config()
    if not _short_ascii(state):
        raise SignInError("state_invalid")
    if not _short_ascii(login_cookie):
        raise SignInError("login_cookie_missing")
    claimed = await _claim(db, state)
    if claimed is None:
        raise SignInError("state_invalid")  # unknown, reused or expired
    nonce_hash, binding_hash = claimed
    if not hmac.compare_digest(_sha256_hex(login_cookie), binding_hash):
        raise SignInError("binding_mismatch")
    nonce = _derive("nonce", login_cookie)
    if not hmac.compare_digest(_sha256_hex(nonce), nonce_hash):
        raise SignInError("state_invalid")
    if not _short_ascii(code):
        raise SignInError("code_missing")

    id_token = await _redeem_code(cfg, code, _derive("pkce", login_cookie))

    tid = _unverified_tid(id_token)
    tenant = await db.get(Tenant, tid) if tid else None
    if tenant is None or tenant.status != "active":
        raise SignInError("tenant_not_registered")

    try:
        claims = await verify_id_token(
            id_token,
            expected_tid=tenant.id,  # from the tenant registry, not from the token
            expected_nonce=nonce,  # derived from this browser's login cookie
            client_id=cfg.client_id,
            jwks_fetcher=fetch_microsoft_jwks,
        )
    except OIDCVerificationError as exc:
        raise SignInError("id_token_invalid", detail=exc.reason) from None

    user = (await db.execute(
        select(WorkbenchUser).where(WorkbenchUser.tenant_id == claims.tid, WorkbenchUser.oid == claims.oid)
    )).scalar_one_or_none()
    if user is None:
        raise SignInError("not_a_member")

    token = issue_session(user_id=user.id, oid=claims.oid, tid=claims.tid, role=user.role)
    return SignInResult(session_token=token, user_id=str(user.id), tid=claims.tid, oid=claims.oid, role=user.role)
