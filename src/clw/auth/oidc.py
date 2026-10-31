"""Entra ID (v2.0) ID token verification (SD-009).

Verifies, in order: token shape; header alg == RS256 and a kid; the key with
exactly that kid in the expected tenant's JWKS; RS256 signature; exp, nbf
and iat; iss == https://login.microsoftonline.com/{expected_tid}/v2.0;
aud == client_id (a single string); tid present and == expected_tid; nonce
present and == expected_nonce (constant time); oid and sub present.

Every failure raises OIDCVerificationError with a fixed reason code and no
token material. Unverified claims are never returned. The caller supplies
expected_tid from server-side state (never from this token) and owns
single-use nonce storage and replay protection (Task 6).

Microsoft behaviour relied on here is unverified until recorded in
docs/assumptions-to-verify.md (A-11, A-12, A-21, A-22).
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt import exceptions as jwt_errors
from jwt.algorithms import RSAAlgorithm

_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ALGORITHM = "RS256"
_MIN_RSA_BITS = 2048
_MAX_TOKEN_CHARS = 16_384
_JWKS_TIMEOUT_SECONDS = 10

REASONS = frozenset({
    "malformed", "unsupported_alg", "kid_missing", "kid_unknown",
    "jwks_unavailable", "jwks_invalid", "signature_invalid",
    "expired", "not_yet_valid", "issuer_mismatch", "audience_mismatch",
    "claim_missing", "claim_invalid", "tid_missing", "tid_mismatch",
    "nonce_missing", "nonce_mismatch",
})


class OIDCVerificationError(Exception):
    """The ID token was rejected. `reason` is one of REASONS."""

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:
            raise ValueError("unknown OIDC verification reason")
        super().__init__(f"ID token rejected: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class IdTokenClaims:
    oid: str
    tid: str
    sub: str
    preferred_username: str | None
    nonce: str


class JwksFetcher(Protocol):
    def __call__(self, tid: str) -> Awaitable[Mapping[str, Any]]: ...


def _require_guid(tid: object) -> str:
    if not isinstance(tid, str) or not _GUID.fullmatch(tid):
        raise ValueError("tenant ID must be a lowercase GUID")
    return tid


async def fetch_microsoft_jwks(tid: str) -> Mapping[str, Any]:
    """The tenant's v2.0 signing keys (A-12). No redirects; any non-200 is an error."""
    url = f"https://login.microsoftonline.com/{_require_guid(tid)}/discovery/v2.0/keys"
    async with httpx.AsyncClient(timeout=_JWKS_TIMEOUT_SECONDS, follow_redirects=False) as http:
        response = await http.get(url)
    if response.status_code != 200:
        raise RuntimeError("JWKS fetch failed")
    return response.json()


def _select_key(document: object, kid: str) -> RSAPublicKey:
    keys = document.get("keys") if isinstance(document, Mapping) else None
    if not isinstance(keys, list) or not keys or not all(isinstance(k, Mapping) for k in keys):
        raise OIDCVerificationError("jwks_invalid")
    matches = [k for k in keys if k.get("kid") == kid]
    if not matches:
        raise OIDCVerificationError("kid_unknown")
    if len(matches) > 1:
        raise OIDCVerificationError("jwks_invalid")
    jwk = matches[0]
    if (
        jwk.get("kty") != "RSA"
        or jwk.get("use", "sig") != "sig"
        or jwk.get("alg", _ALGORITHM) != _ALGORITHM
        or "d" in jwk
    ):
        raise OIDCVerificationError("jwks_invalid")
    try:
        key = RSAAlgorithm.from_jwk(dict(jwk))
    except Exception:
        raise OIDCVerificationError("jwks_invalid") from None
    if not isinstance(key, RSAPublicKey) or key.key_size < _MIN_RSA_BITS:
        raise OIDCVerificationError("jwks_invalid")
    return key


def _decode(id_token: str, key: RSAPublicKey, *, issuer: str, client_id: str) -> dict:
    try:
        return jwt.decode(
            id_token,
            key,
            algorithms=[_ALGORITHM],
            audience=client_id,
            issuer=issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "oid"], "strict_aud": True},
        )
    except jwt_errors.ExpiredSignatureError:
        reason = "expired"
    except jwt_errors.ImmatureSignatureError:
        reason = "not_yet_valid"
    except jwt_errors.MissingRequiredClaimError:
        reason = "claim_missing"
    except jwt_errors.InvalidIssuerError:
        reason = "issuer_mismatch"
    except jwt_errors.InvalidAudienceError:
        reason = "audience_mismatch"
    except jwt_errors.InvalidSignatureError:
        reason = "signature_invalid"
    except (jwt_errors.InvalidSubjectError, jwt_errors.InvalidIssuedAtError):
        reason = "claim_invalid"
    except Exception:  # DecodeError and anything unexpected
        reason = "malformed"
    raise OIDCVerificationError(reason)


def _non_empty_str(value: object) -> bool:
    return isinstance(value, str) and value != ""


def _utf8(text: str) -> bytes:
    # surrogatepass: JSON may carry lone surrogates; they must compare, not crash.
    return text.encode("utf-8", "surrogatepass")


async def verify_id_token(
    id_token: str,
    *,
    expected_tid: str,
    expected_nonce: str,
    client_id: str,
    jwks_fetcher: JwksFetcher,
) -> IdTokenClaims:
    _require_guid(expected_tid)
    if not _non_empty_str(expected_nonce) or not _non_empty_str(client_id):
        raise ValueError("expected_nonce and client_id are required")

    if not isinstance(id_token, str) or not id_token.isascii() or not 0 < len(id_token) <= _MAX_TOKEN_CHARS:
        raise OIDCVerificationError("malformed")
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception:
        raise OIDCVerificationError("malformed") from None
    if not isinstance(header, dict) or "crit" in header:
        raise OIDCVerificationError("malformed")
    if header.get("alg") != _ALGORITHM:
        raise OIDCVerificationError("unsupported_alg")
    kid = header.get("kid")
    if not _non_empty_str(kid):
        raise OIDCVerificationError("kid_missing")

    try:
        document = await jwks_fetcher(expected_tid)
    except Exception:
        raise OIDCVerificationError("jwks_unavailable") from None
    key = _select_key(document, kid)

    claims = _decode(
        id_token, key, issuer=f"https://login.microsoftonline.com/{expected_tid}/v2.0", client_id=client_id
    )

    # Signature, lifetime, issuer and audience hold from here on.
    if not isinstance(claims.get("aud"), str):
        raise OIDCVerificationError("audience_mismatch")
    tid = claims.get("tid")
    if tid is None or tid == "":
        raise OIDCVerificationError("tid_missing")
    if not isinstance(tid, str) or tid != expected_tid:
        raise OIDCVerificationError("tid_mismatch")
    nonce = claims.get("nonce")
    if nonce is None or nonce == "":
        raise OIDCVerificationError("nonce_missing")
    if not isinstance(nonce, str) or not hmac.compare_digest(_utf8(nonce), _utf8(expected_nonce)):
        raise OIDCVerificationError("nonce_mismatch")
    oid, sub, username = claims.get("oid"), claims.get("sub"), claims.get("preferred_username")
    if not _non_empty_str(oid) or not _non_empty_str(sub) or not (username is None or isinstance(username, str)):
        raise OIDCVerificationError("claim_invalid")
    return IdTokenClaims(oid=oid, tid=tid, sub=sub, preferred_username=username, nonce=nonce)
