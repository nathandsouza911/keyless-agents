"""ID token verification at the tenant boundary (SD-009; threat-model T3-T6).

A locally generated RSA key and a fake JWKS fetcher; no network. Nonce
replay (single-use storage) is Task 6 (`tests/security/test_signin.py`).
"""

from __future__ import annotations

import ast
import base64
import json
import time
import uuid
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from clw.auth import oidc
from clw.auth.oidc import IdTokenClaims, OIDCVerificationError, verify_id_token

OIDC_SRC = Path(__file__).resolve().parents[2] / "src" / "clw" / "auth" / "oidc.py"
TID = str(uuid.uuid4())
OTHER_TID = str(uuid.uuid4())
CLIENT_ID = str(uuid.uuid4())
NONCE = "n-" + uuid.uuid4().hex
KID = "test-kid-1"


def _issuer(tid: str) -> str:
    return f"https://login.microsoftonline.com/{tid}/v2.0"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def other_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(private_key, kid: str = KID, **extra) -> dict:
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256", **extra})
    return jwk


class FakeJwks:
    def __init__(self, document=None, error: Exception | None = None):
        self.document = document
        self.error = error
        self.calls: list[str] = []

    async def __call__(self, tid: str):
        self.calls.append(tid)
        if self.error is not None:
            raise self.error
        return self.document


@pytest.fixture
def jwks(rsa_key):
    return FakeJwks({"keys": [_jwk(rsa_key)]})


def _claims(**overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": _issuer(TID),
        "aud": CLIENT_ID,
        "exp": now + 600,
        "iat": now,
        "nbf": now,
        "sub": "pairwise-sub-" + uuid.uuid4().hex,
        "oid": str(uuid.uuid4()),
        "tid": TID,
        "nonce": NONCE,
        "preferred_username": "analyst@example.test",
    }
    for key, value in overrides.items():
        if value is _DROP:
            claims.pop(key, None)
        else:
            claims[key] = value
    return claims


_DROP = object()


def _token(private_key, claims=None, *, alg="RS256", headers=None) -> str:
    hdrs = {"kid": KID}
    hdrs.update(headers or {})
    return jwt.encode(claims if claims is not None else _claims(), private_key, algorithm=alg, headers=hdrs)


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _unsigned(header: dict, claims: dict) -> str:
    return f"{_b64(header)}.{_b64(claims)}."


async def _verify(token, fetcher, **kw):
    args = {"expected_tid": TID, "expected_nonce": NONCE, "client_id": CLIENT_ID, "jwks_fetcher": fetcher}
    args.update(kw)
    return await verify_id_token(token, **args)


async def _reason(token, fetcher, **kw) -> str:
    with pytest.raises(OIDCVerificationError) as info:
        await _verify(token, fetcher, **kw)
    return info.value.reason


# ---------------------------------------------------------------- valid token


async def test_valid_id_token_returns_claims(rsa_key, jwks):
    claims = _claims()
    result = await _verify(_token(rsa_key, claims), jwks)
    assert result == IdTokenClaims(
        oid=claims["oid"], tid=TID, sub=claims["sub"],
        preferred_username="analyst@example.test", nonce=NONCE,
    )
    assert jwks.calls == [TID]


async def test_preferred_username_is_optional(rsa_key, jwks):
    result = await _verify(_token(rsa_key, _claims(preferred_username=_DROP)), jwks)
    assert result.preferred_username is None


async def test_jwks_is_fetched_for_the_expected_tenant_not_the_token_tenant(rsa_key, jwks):
    token = _token(rsa_key, _claims(tid=OTHER_TID, iss=_issuer(OTHER_TID)))
    assert await _reason(token, jwks) == "issuer_mismatch"
    assert jwks.calls == [TID]


# ---------------------------------------------------------------- T3 / T4: tid


async def test_id_token_missing_tid_rejected(rsa_key, jwks):
    assert await _reason(_token(rsa_key, _claims(tid=_DROP)), jwks) == "tid_missing"


@pytest.mark.parametrize("value", [None, ""])
async def test_id_token_null_or_empty_tid_rejected(rsa_key, jwks, value):
    assert await _reason(_token(rsa_key, _claims(tid=value)), jwks) == "tid_missing"


async def test_id_token_tid_mismatch_rejected(rsa_key, jwks):
    # Issuer still names the expected tenant: only the tid check can catch this.
    assert await _reason(_token(rsa_key, _claims(tid=OTHER_TID)), jwks) == "tid_mismatch"


@pytest.mark.parametrize("value", [TID.upper(), f" {TID}", 42, [TID], {"tid": TID}])
async def test_id_token_tid_must_match_exactly(rsa_key, jwks, value):
    assert await _reason(_token(rsa_key, _claims(tid=value)), jwks) == "tid_mismatch"


async def test_token_from_another_tenant_rejected(rsa_key, jwks):
    token = _token(rsa_key, _claims(tid=OTHER_TID, iss=_issuer(OTHER_TID)))
    assert await _reason(token, jwks) == "issuer_mismatch"


# ---------------------------------------------------------------- T5: nonce


async def test_id_token_nonce_missing_rejected(rsa_key, jwks):
    assert await _reason(_token(rsa_key, _claims(nonce=_DROP)), jwks) == "nonce_missing"


@pytest.mark.parametrize("value", [None, ""])
async def test_id_token_null_or_empty_nonce_rejected(rsa_key, jwks, value):
    assert await _reason(_token(rsa_key, _claims(nonce=value)), jwks) == "nonce_missing"


@pytest.mark.parametrize("value", ["other-nonce", NONCE[:-1], NONCE + "x", NONCE.upper(), 42, [NONCE]])
async def test_id_token_nonce_mismatch_rejected(rsa_key, jwks, value):
    assert await _reason(_token(rsa_key, _claims(nonce=value)), jwks) == "nonce_mismatch"


async def test_non_ascii_nonce_compared_safely(rsa_key, jwks):
    token = _token(rsa_key, _claims(nonce="é" * 8))
    assert await _reason(token, jwks, expected_nonce="e" * 8) == "nonce_mismatch"
    assert (await _verify(token, jwks, expected_nonce="é" * 8)).nonce == "é" * 8


# ---------------------------------------------------------------- T6: issuer / audience


@pytest.mark.parametrize(
    "iss",
    [
        f"https://sts.windows.net/{TID}/",
        "https://login.microsoftonline.com/common/v2.0",
        "https://login.microsoftonline.com/organizations/v2.0",
        _issuer(TID) + "/",
        _issuer(TID).replace("https://", "http://"),
        _issuer(TID.upper()),
        _issuer(OTHER_TID),
    ],
)
async def test_id_token_wrong_issuer_rejected(rsa_key, jwks, iss):
    assert await _reason(_token(rsa_key, _claims(iss=iss)), jwks) == "issuer_mismatch"


@pytest.mark.parametrize("aud", [str(uuid.uuid4()), CLIENT_ID.upper(), [CLIENT_ID, str(uuid.uuid4())], [CLIENT_ID]])
async def test_id_token_wrong_audience_rejected(rsa_key, jwks, aud):
    assert await _reason(_token(rsa_key, _claims(aud=aud)), jwks) == "audience_mismatch"


@pytest.mark.parametrize("claim", ["iss", "aud"])
async def test_id_token_missing_issuer_or_audience_rejected(rsa_key, jwks, claim):
    assert await _reason(_token(rsa_key, _claims(**{claim: _DROP})), jwks) == "claim_missing"


# ---------------------------------------------------------------- lifetime


async def test_expired_id_token_rejected(rsa_key, jwks):
    now = int(time.time())
    token = _token(rsa_key, _claims(exp=now - 1, iat=now - 600, nbf=now - 600))
    assert await _reason(token, jwks) == "expired"


async def test_not_yet_valid_id_token_rejected(rsa_key, jwks):
    now = int(time.time())
    assert await _reason(_token(rsa_key, _claims(nbf=now + 300)), jwks) == "not_yet_valid"


@pytest.mark.parametrize("claim", ["exp", "iat"])
async def test_lifetime_claims_required(rsa_key, jwks, claim):
    assert await _reason(_token(rsa_key, _claims(**{claim: _DROP})), jwks) == "claim_missing"


# ---------------------------------------------------------------- algorithm and key selection


async def test_alg_none_rejected(jwks):
    token = _unsigned({"alg": "none", "kid": KID, "typ": "JWT"}, _claims())
    assert await _reason(token, jwks) == "unsupported_alg"


async def test_hs256_signed_with_public_key_rejected(rsa_key, jwks):
    # Classic key confusion: the public key PEM used as an HMAC secret.
    pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = {"alg": "HS256", "kid": KID, "typ": "JWT"}
    signing_input = f"{_b64(header)}.{_b64(_claims())}".encode()
    import hashlib
    import hmac

    sig = base64.urlsafe_b64encode(hmac.new(pem, signing_input, hashlib.sha256).digest()).rstrip(b"=")
    token = signing_input.decode() + "." + sig.decode()
    assert await _reason(token, jwks) == "unsupported_alg"


@pytest.mark.parametrize("alg", ["RS512", "PS256"])
async def test_other_rsa_algorithms_rejected(rsa_key, jwks, alg):
    assert await _reason(_token(rsa_key, alg=alg), jwks) == "unsupported_alg"


@pytest.mark.parametrize("alg", ["rs256", "", None, 256])
async def test_alg_must_be_exactly_rs256(jwks, alg):
    header = {"kid": KID, "typ": "JWT"}
    if alg is not None:
        header["alg"] = alg
    assert await _reason(_unsigned(header, _claims()) + "sig", jwks) == "unsupported_alg"


async def test_kid_unknown_rejected(rsa_key, jwks):
    token = _token(rsa_key, headers={"kid": "rotated-away"})
    assert await _reason(token, jwks) == "kid_unknown"


@pytest.mark.parametrize("kid", [None, ""])
async def test_kid_missing_rejected(rsa_key, jwks, kid):
    header = {"alg": "RS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    assert await _reason(_unsigned(header, _claims()) + "sig", jwks) == "kid_missing"


async def test_non_string_kid_rejected(jwks):
    header = {"alg": "RS256", "typ": "JWT", "kid": 7}
    assert await _reason(_unsigned(header, _claims()) + "sig", jwks) == "malformed"
    assert jwks.calls == []


async def test_no_fallback_to_another_key(rsa_key, other_rsa_key):
    # Legacy once fell back to keys[0]; the only key here has another kid.
    fetcher = FakeJwks({"keys": [_jwk(rsa_key, kid="different")]})
    assert await _reason(_token(rsa_key), fetcher) == "kid_unknown"


async def test_signature_by_another_key_rejected(other_rsa_key, jwks):
    assert await _reason(_token(other_rsa_key), jwks) == "signature_invalid"


async def test_tampered_payload_rejected(rsa_key, jwks):
    header, _, sig = _token(rsa_key).split(".")
    forged = f"{header}.{_b64(_claims(tid=OTHER_TID))}.{sig}"
    assert await _reason(forged, jwks) == "signature_invalid"


async def test_crit_header_rejected(rsa_key, jwks):
    assert await _reason(_token(rsa_key, headers={"crit": ["exp"]}), jwks) == "malformed"
    assert jwks.calls == []  # refused before any JWKS fetch


async def test_unencoded_payload_extension_rejected_before_fetch(jwks):
    # RFC 7797 b64=false is the one crit value PyJWT accepts; we use no JWS extensions.
    header = {"alg": "RS256", "kid": KID, "typ": "JWT", "crit": ["b64"], "b64": False}
    detached = f"{_b64(header)}..sig"  # PyJWT's header parser accepts this shape
    assert await _reason(detached, jwks) == "malformed"
    assert jwks.calls == []


async def test_oversized_valid_token_rejected_before_fetch(rsa_key, jwks):
    token = _token(rsa_key, _claims(pad="a" * 20000))
    assert await _reason(token, jwks) == "malformed"
    assert jwks.calls == []


# ---------------------------------------------------------------- claims


@pytest.mark.parametrize("claim", ["oid", "sub"])
async def test_id_token_missing_oid_or_sub_rejected(rsa_key, jwks, claim):
    assert await _reason(_token(rsa_key, _claims(**{claim: _DROP})), jwks) == "claim_missing"


@pytest.mark.parametrize(
    "overrides",
    [{"oid": ""}, {"oid": 42}, {"oid": [str(uuid.uuid4())]}, {"sub": ""}, {"sub": 42}, {"preferred_username": 42}],
)
async def test_id_token_claims_of_wrong_type_rejected(rsa_key, jwks, overrides):
    assert await _reason(_token(rsa_key, _claims(**overrides)), jwks) == "claim_invalid"


# ---------------------------------------------------------------- malformed input


@pytest.mark.parametrize(
    "token",
    [None, 42, b"bytes", "", "   ", "not-a-jwt", "a.b", "a.b.c", "é.é.é", "x" * 20000],
)
async def test_malformed_tokens_rejected(jwks, token):
    assert await _reason(token, jwks) == "malformed"
    assert jwks.calls == []  # nothing fetched for garbage


# ---------------------------------------------------------------- JWKS failures (fail closed)


async def test_jwks_fetch_failure_fails_closed(rsa_key):
    fetcher = FakeJwks(error=RuntimeError("network down"))
    assert await _reason(_token(rsa_key), fetcher) == "jwks_unavailable"


@pytest.mark.parametrize(
    "document",
    [None, [], "keys", {}, {"keys": []}, {"keys": "x"}, {"keys": [None]}, {"keys": [{"kid": KID}]}],
)
async def test_unusable_jwks_document_fails_closed(rsa_key, document):
    assert await _reason(_token(rsa_key), FakeJwks(document)) == "jwks_invalid"


async def test_jwks_with_duplicate_kid_rejected(rsa_key, other_rsa_key):
    fetcher = FakeJwks({"keys": [_jwk(rsa_key), _jwk(other_rsa_key)]})
    assert await _reason(_token(rsa_key), fetcher) == "jwks_invalid"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda j: j.update(kty="EC"), id="not-rsa"),
        pytest.param(lambda j: j.update(use="enc"), id="use-enc"),
        pytest.param(lambda j: j.update(alg="RS512"), id="jwk-alg-mismatch"),
        pytest.param(lambda j: j.update(n="AQAB"), id="tiny-modulus"),
        pytest.param(lambda j: j.pop("n"), id="no-modulus"),
    ],
)
async def test_unacceptable_jwk_rejected(rsa_key, mutate):
    jwk = _jwk(rsa_key)
    mutate(jwk)
    assert await _reason(_token(rsa_key), FakeJwks({"keys": [jwk]})) == "jwks_invalid"


async def test_jwk_carrying_private_key_rejected(rsa_key):
    jwk = RSAAlgorithm.to_jwk(rsa_key, as_dict=True)  # includes "d"
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    assert await _reason(_token(rsa_key), FakeJwks({"keys": [jwk]})) == "jwks_invalid"


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")  # signing the probe
async def test_small_rsa_key_rejected():
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    assert await _reason(_token(small), FakeJwks({"keys": [_jwk(small)]})) == "jwks_invalid"


# ---------------------------------------------------------------- caller input


@pytest.mark.parametrize(
    "kw",
    [
        {"expected_tid": ""},
        {"expected_tid": TID.upper()},
        {"expected_tid": "common"},
        {"expected_tid": f"{TID}/../evil"},
        {"expected_tid": None},
        {"expected_nonce": ""},
        {"expected_nonce": None},
        {"client_id": ""},
        {"client_id": None},
    ],
)
async def test_invalid_caller_arguments_rejected_before_any_fetch(rsa_key, jwks, kw):
    with pytest.raises(ValueError):
        await _verify(_token(rsa_key), jwks, **kw)
    assert jwks.calls == []


# ---------------------------------------------------------------- error hygiene


async def test_errors_carry_a_reason_code_and_no_token_material(rsa_key, jwks):
    claims = _claims(tid=OTHER_TID)
    token = _token(rsa_key, claims)
    with pytest.raises(OIDCVerificationError) as info:
        await _verify(token, jwks)
    exc = info.value
    assert exc.reason == "tid_mismatch" and exc.reason in oidc.REASONS
    text = f"{exc!s} {exc!r} {exc.args!r}"
    for secret in (token, OTHER_TID, NONCE, claims["oid"], claims["sub"]):
        assert secret not in text
    assert exc.__cause__ is None


def test_reason_codes_cover_the_plan():
    assert {
        "tid_missing", "tid_mismatch", "nonce_missing", "nonce_mismatch", "issuer_mismatch",
        "audience_mismatch", "expired", "unsupported_alg", "kid_unknown", "claim_missing",
    } <= oidc.REASONS
    with pytest.raises(ValueError):
        OIDCVerificationError("made_up_reason")


def test_oidc_module_has_no_web_framework_or_unverified_decode():
    tree = ast.parse(OIDC_SRC.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert not roots & {"fastapi", "starlette"}
    source = OIDC_SRC.read_text(encoding="utf-8")
    assert "verify_signature" not in source
    assert "get_unverified_claims" not in source
