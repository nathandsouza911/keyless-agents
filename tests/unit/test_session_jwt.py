"""Session tokens (F-3, SD-011)."""

from __future__ import annotations

import ast
import time
import uuid
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from clw.auth import denylist, session_jwt
from clw.auth.session_jwt import SessionConfigError, SessionInvalid, decode_session, issue_session
from clw.common.config import Settings
from tests.auth_fixtures import PG, auth_env, closed_port_url  # noqa: F401 (fixture)

SRC = Path(__file__).resolve().parents[2] / "src" / "clw" / "auth" / "session_jwt.py"
TID = str(uuid.uuid4())
OID = str(uuid.uuid4())


def _issue(**kw) -> str:
    args = {"user_id": uuid.uuid4(), "oid": OID, "tid": TID, "role": "analyst"}
    args.update(kw)
    return issue_session(**args)


def _secret() -> str:
    from clw.common.config import get_settings

    return get_settings().SESSION_JWT_SECRET.get_secret_value()


def _payload(**overrides) -> dict:
    now = int(time.time())
    payload = {
        "sub": str(uuid.uuid4()), "oid": OID, "tid": TID, "role": "analyst",
        "jti": str(uuid.uuid4()), "iat": now, "exp": now + 3600,
    }
    for key, value in overrides.items():
        if value is _DROP:
            payload.pop(key)
        elif value is _FLOAT_EXP:  # computed now, not at collection: a stale value would read as expired
            payload[key] = float(now + 60)
        elif value is _OVERLONG_EXP:  # likewise: computed at collection, it shrinks below the TTL
            payload[key] = now + 8 * 3600 + 60
        else:
            payload[key] = value
    return payload


_DROP = object()
_FLOAT_EXP = object()  # a float exp, a valid time otherwise
_OVERLONG_EXP = object()  # an exp more than the session TTL after iat


def _sign(payload: dict, *, alg: str = "HS256", key=None, headers=None) -> str:
    return jwt.encode(payload, key if key is not None else _secret(), algorithm=alg, headers=headers)


async def _reason(token) -> str:
    with pytest.raises(SessionInvalid) as info:
        await decode_session(token)
    return info.value.reason


# ---------------------------------------------------------------- round trip


async def test_issue_and_decode_round_trip(auth_env):
    user_id = uuid.uuid4()
    token = _issue(user_id=user_id, role="security_lead")
    claims = await decode_session(token)
    assert (claims.user_id, claims.oid, claims.tid, claims.role) == (user_id, OID, TID, "security_lead")
    assert claims.expires_at - claims.issued_at == session_jwt.SESSION_TTL_SECONDS == 8 * 3600
    assert uuid.UUID(claims.jti)


async def test_issued_token_has_exactly_the_session_claims(auth_env):
    token = _issue()
    assert jwt.get_unverified_header(token) == {"alg": "HS256", "typ": "JWT"}
    payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    assert set(payload) == {"sub", "oid", "tid", "role", "jti", "exp", "iat"}


async def test_every_session_gets_a_fresh_jti(auth_env):
    a, b = (await decode_session(_issue())), (await decode_session(_issue()))
    assert a.jti != b.jti


# ---------------------------------------------------------------- jti and revocation (SD-011)


async def test_token_without_jti_rejected(auth_env):
    assert await _reason(_sign(_payload(jti=_DROP))) == "claim_missing"


@pytest.mark.parametrize("jti", [None, "", "not-a-uuid", 42, str(uuid.uuid4()).upper()])
async def test_token_with_bad_jti_rejected(auth_env, jti):
    assert await _reason(_sign(_payload(jti=jti))) in {"claim_missing", "claim_invalid"}


async def test_revoked_jti_rejected(auth_env):
    token = _issue()
    claims = await decode_session(token)
    await denylist.revoke(claims.jti, claims.expires_at)
    assert await _reason(token) == "revoked"
    assert (await decode_session(_issue())).jti != claims.jti  # others unaffected


async def test_production_with_redis_down_rejects_every_session(auth_env):
    auth_env(environment="development")
    token = _issue()
    assert await decode_session(token)
    auth_env(environment="production", redis_url=closed_port_url(), secret=_secret())
    assert await _reason(token) == "revoked"


async def test_production_without_redis_configured_rejects_every_session(auth_env):
    auth_env(environment="production")
    assert await _reason(_issue()) == "revoked"


# ---------------------------------------------------------------- claims


@pytest.mark.parametrize("claim", ["sub", "oid", "tid", "role", "exp", "iat"])
async def test_every_claim_required(auth_env, claim):
    assert await _reason(_sign(_payload(**{claim: _DROP}))) == "claim_missing"


@pytest.mark.parametrize(
    "extra",
    [{"organization_id": "x"}, {"tenant_ids": [TID]}, {"email": "a@b"}, {"token_source": "cloud_locksmith_app"},
     {"nbf": 0}, {"aud": "clw"}],
)
async def test_unexpected_claims_rejected(auth_env, extra):
    assert await _reason(_sign({**_payload(), **extra})) == "claim_unexpected"


@pytest.mark.parametrize(
    "overrides",
    [
        {"role": "ADMIN"}, {"role": "Analyst"}, {"role": None},
        {"tid": TID.upper()}, {"tid": "common"}, {"tid": [TID]},
        {"oid": OID.upper()}, {"oid": 1},
        {"sub": "user-1"}, {"sub": str(uuid.uuid4()).upper()}, {"sub": 7},
        {"iat": True}, {"exp": _FLOAT_EXP},
        {"exp": _OVERLONG_EXP},  # longer than the session TTL
    ],
)
async def test_invalid_claim_values_rejected(auth_env, overrides):
    assert await _reason(_sign(_payload(**overrides))) in {"claim_invalid", "claim_missing"}


async def test_string_iat_rejected(auth_env):
    # PyJWT itself accepts int("123"); the session check does not.
    assert await _reason(_sign(_payload(iat=str(int(time.time()))))) == "claim_invalid"


async def test_expired_session_rejected(auth_env):
    now = int(time.time())
    assert await _reason(_sign(_payload(iat=now - 3600, exp=now - 1))) == "expired"


async def test_future_iat_rejected(auth_env):
    now = int(time.time())
    assert await _reason(_sign(_payload(iat=now + 120, exp=now + 3600))) == "not_yet_valid"


# ---------------------------------------------------------------- algorithm and signature


@pytest.mark.parametrize("alg", ["HS384", "HS512"])
async def test_other_hmac_algorithms_rejected(auth_env, alg):
    assert await _reason(_sign(_payload(), alg=alg)) == "unsupported_alg"


async def test_rs256_token_rejected(auth_env):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await _reason(_sign(_payload(), alg="RS256", key=key)) == "unsupported_alg"


async def test_alg_none_rejected(auth_env):
    token = jwt.encode(_payload(), None, algorithm="none")
    assert await _reason(token) == "unsupported_alg"


async def test_wrong_secret_rejected(auth_env):
    assert await _reason(_sign(_payload(), key="x" * 48)) == "signature_invalid"


async def test_tampered_payload_rejected(auth_env):
    header, _, sig = _issue(role="analyst").split(".")
    forged = jwt.encode(_payload(role="security_lead"), "irrelevant-key-" * 4, algorithm="HS256").split(".")[1]
    assert await _reason(f"{header}.{forged}.{sig}") == "signature_invalid"


@pytest.mark.parametrize("headers", [{"kid": "k1"}, {"jku": "https://evil.example"}, {"crit": ["exp"]}])
async def test_unexpected_header_rejected(auth_env, headers):
    assert await _reason(_sign(_payload(), headers=headers)) == "malformed"


@pytest.mark.parametrize("token", [None, 42, b"x", "", "not-a-jwt", "a.b.c", "é.é.é", "x" * 5000])
async def test_malformed_tokens_rejected(auth_env, token):
    assert await _reason(token) == "malformed"


async def test_oversized_signed_token_rejected_before_claim_checks(auth_env):
    token = _sign({**_payload(), "pad": "a" * 5000})
    assert await _reason(token) == "malformed"


# ---------------------------------------------------------------- issue_session input


@pytest.mark.parametrize(
    "kw",
    [{"role": "ADMIN"}, {"role": "admin"}, {"tid": "common"}, {"tid": TID.upper()}, {"oid": ""},
     {"user_id": "not-a-uuid"}, {"user_id": str(uuid.uuid4())}],
)
def test_issue_session_rejects_bad_input(auth_env, kw):
    with pytest.raises(ValueError):
        _issue(**kw)


# ---------------------------------------------------------------- configuration


@pytest.mark.parametrize("secret", [None, "short", "x" * 31])
async def test_missing_or_short_secret_fails_closed(auth_env, secret):
    token = _issue()
    auth_env(secret=secret)
    with pytest.raises(SessionConfigError):
        _issue()
    with pytest.raises(SessionConfigError):
        await decode_session(token)


def test_secret_not_in_settings_repr():
    settings = Settings(_env_file=None, DATABASE_URL=PG, SESSION_JWT_SECRET="s" * 40, REDIS_URL="redis://:pw-xyz@h:1/0")
    assert "s" * 40 not in repr(settings) and "pw-xyz" not in repr(settings)
    assert Settings(_env_file=None, DATABASE_URL=PG).SESSION_JWT_SECRET is None


# ---------------------------------------------------------------- hygiene


async def test_errors_carry_no_token_material(auth_env):
    token = _sign(_payload(role="ADMIN"))
    with pytest.raises(SessionInvalid) as info:
        await decode_session(token)
    text = f"{info.value!s} {info.value!r}"
    assert token not in text and _secret() not in text and "ADMIN" not in text
    with pytest.raises(ValueError):
        SessionInvalid("made_up")


def test_legacy_helpers_removed():
    defined = {n.name for n in ast.walk(ast.parse(SRC.read_text(encoding="utf-8"))) if isinstance(n, ast.FunctionDef)}
    assert "issue_session" in defined
    for name in ("create_token", "create_access_token", "decode_access_token", "decode_token"):
        assert name not in defined, name
        assert not hasattr(session_jwt, name), name


def test_no_unverified_decode_or_web_framework():
    source = SRC.read_text(encoding="utf-8")
    assert "verify_signature" not in source
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert not roots & {"fastapi", "starlette"}
