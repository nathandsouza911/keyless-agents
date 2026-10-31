"""Workbench session tokens (F-3, SD-011).

HS256 only, with a dedicated SESSION_JWT_SECRET. A session carries exactly
sub (internal user ID), oid, tid, role, jti, exp and iat; every claim is
required, strictly typed and nothing else is accepted. Every decode checks
the revocation list by jti, which fails closed in production.

The tenant in a session comes from a verified ID token at sign-in (Task 6);
nothing here accepts a tenant from request input.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from typing import Literal

import jwt
from jwt import exceptions as jwt_errors

from clw.auth.denylist import is_revoked
from clw.common.config import get_settings

ALGORITHM = "HS256"
SESSION_TTL_SECONDS = 8 * 3600
SESSION_COOKIE_NAME = "clw_session"
ROLES = frozenset({"analyst", "security_lead"})
Role = Literal["analyst", "security_lead"]

_CLAIMS = frozenset({"sub", "oid", "tid", "role", "jti", "exp", "iat"})
_HEADER_KEYS = frozenset({"alg", "typ"})
_MIN_SECRET_BYTES = 32
_MAX_TOKEN_CHARS = 4096
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

REASONS = frozenset({
    "malformed", "unsupported_alg", "signature_invalid", "expired", "not_yet_valid",
    "claim_missing", "claim_unexpected", "claim_invalid", "revoked",
})


class SessionInvalid(Exception):
    """The session token was rejected. `reason` is one of REASONS."""

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:
            raise ValueError("unknown session rejection reason")
        super().__init__(f"session rejected: {reason}")
        self.reason = reason


class SessionConfigError(Exception):
    """SESSION_JWT_SECRET is missing or too short."""


@dataclass(frozen=True, slots=True)
class SessionClaims:
    user_id: uuid.UUID
    oid: str
    tid: str
    role: Role
    jti: str
    issued_at: int
    expires_at: int


def _secret() -> bytes:
    value = get_settings().SESSION_JWT_SECRET
    if value is None:
        raise SessionConfigError("SESSION_JWT_SECRET is not set")
    raw = value.get_secret_value().encode("utf-8")
    if len(raw) < _MIN_SECRET_BYTES:
        raise SessionConfigError(f"SESSION_JWT_SECRET must be at least {_MIN_SECRET_BYTES} bytes")
    return raw


def _is_guid(value: object) -> bool:
    return isinstance(value, str) and _GUID.fullmatch(value) is not None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def issue_session(*, user_id: uuid.UUID, oid: str, tid: str, role: Role) -> str:
    if not isinstance(user_id, uuid.UUID):
        raise ValueError("user_id must be a UUID")
    if not _is_guid(oid) or not _is_guid(tid):
        raise ValueError("oid and tid must be lowercase GUIDs")
    if role not in ROLES:
        raise ValueError("unknown role")
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "oid": oid,
        "tid": tid,
        "role": role,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def _check_signature_and_lifetime(token: str, secret: bytes) -> dict:
    try:
        return jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require": sorted(_CLAIMS)})
    except jwt_errors.ExpiredSignatureError:
        reason = "expired"
    except jwt_errors.ImmatureSignatureError:
        reason = "not_yet_valid"
    except jwt_errors.MissingRequiredClaimError:
        reason = "claim_missing"
    except jwt_errors.InvalidSignatureError:
        reason = "signature_invalid"
    except jwt_errors.InvalidAudienceError:  # an aud claim; sessions carry none
        reason = "claim_unexpected"
    except (jwt_errors.InvalidIssuedAtError, jwt_errors.InvalidSubjectError, jwt_errors.InvalidJTIError):
        reason = "claim_invalid"
    except Exception:  # DecodeError and anything unexpected
        reason = "malformed"
    raise SessionInvalid(reason)


def _claims_valid(p: dict) -> bool:
    try:
        sub_ok = isinstance(p["sub"], str) and str(uuid.UUID(p["sub"])) == p["sub"]
        jti_ok = isinstance(p["jti"], str) and str(uuid.UUID(p["jti"])) == p["jti"]
    except ValueError:
        return False
    return (
        sub_ok
        and jti_ok
        and _is_guid(p["oid"])
        and _is_guid(p["tid"])
        and p["role"] in ROLES
        and _is_int(p["iat"])
        and _is_int(p["exp"])
        # Caps lifetime at the current TTL, including for tokens issued before a cut.
        and 0 < p["exp"] - p["iat"] <= SESSION_TTL_SECONDS
    )


async def decode_session(token: str) -> SessionClaims:
    """Verify a session token and check revocation. Raises SessionInvalid."""
    secret = _secret()  # a missing secret is a configuration error, not a bad token
    if not isinstance(token, str) or not token.isascii() or not 0 < len(token) <= _MAX_TOKEN_CHARS:
        raise SessionInvalid("malformed")
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise SessionInvalid("malformed") from None
    if header.get("alg") != ALGORITHM:
        raise SessionInvalid("unsupported_alg")
    if not set(header) <= _HEADER_KEYS:
        raise SessionInvalid("malformed")

    payload = _check_signature_and_lifetime(token, secret)
    if set(payload) != _CLAIMS:
        raise SessionInvalid("claim_unexpected")
    if not _claims_valid(payload):
        raise SessionInvalid("claim_invalid")
    if await is_revoked(payload["jti"]):
        raise SessionInvalid("revoked")
    return SessionClaims(
        user_id=uuid.UUID(payload["sub"]),
        oid=payload["oid"],
        tid=payload["tid"],
        role=payload["role"],
        jti=payload["jti"],
        issued_at=payload["iat"],
        expires_at=payload["exp"],
    )
