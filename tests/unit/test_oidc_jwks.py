"""The default Microsoft JWKS fetcher (SD-009, A-12). respx only; no network."""

from __future__ import annotations

import time
import uuid

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from clw.auth.oidc import OIDCVerificationError, fetch_microsoft_jwks, verify_id_token

TID = str(uuid.uuid4())
CLIENT_ID = str(uuid.uuid4())
NONCE = "n-" + uuid.uuid4().hex
JWKS_URL = f"https://login.microsoftonline.com/{TID}/discovery/v2.0/keys"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks(key) -> dict:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": "k1", "use": "sig"})
    return {"keys": [jwk]}


def _token(key) -> str:
    now = int(time.time())
    claims = {
        "iss": f"https://login.microsoftonline.com/{TID}/v2.0", "aud": CLIENT_ID,
        "exp": now + 600, "iat": now, "sub": "s", "oid": str(uuid.uuid4()), "tid": TID, "nonce": NONCE,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


async def _verify(token):
    return await verify_id_token(
        token, expected_tid=TID, expected_nonce=NONCE, client_id=CLIENT_ID, jwks_fetcher=fetch_microsoft_jwks
    )


async def test_fetches_the_tenant_jwks_url(rsa_key):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(rsa_key)))
        claims = await _verify(_token(rsa_key))
    assert claims.tid == TID
    assert route.call_count == 1
    assert route.calls.last.request.url == httpx.URL(JWKS_URL)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500),
        httpx.Response(404),
        httpx.Response(302, headers={"location": "https://evil.example/keys"}),
        httpx.Response(200, text="not json"),
        httpx.Response(200, json=["keys"]),
    ],
)
async def test_bad_jwks_responses_fail_closed(rsa_key, response):
    with respx.mock(assert_all_called=True) as mock:
        mock.get(JWKS_URL).mock(return_value=response)
        with pytest.raises(OIDCVerificationError) as info:
            await _verify(_token(rsa_key))
    assert info.value.reason in {"jwks_unavailable", "jwks_invalid"}


async def test_redirect_is_not_followed(rsa_key):
    with respx.mock(assert_all_called=False) as mock:
        mock.get(JWKS_URL).mock(return_value=httpx.Response(302, headers={"location": "https://evil.example/keys"}))
        evil = mock.get("https://evil.example/keys").mock(return_value=httpx.Response(200, json=_jwks(rsa_key)))
        with pytest.raises(OIDCVerificationError) as info:
            await _verify(_token(rsa_key))
    assert info.value.reason == "jwks_unavailable"
    assert not evil.called


@pytest.mark.parametrize("error", [httpx.ConnectError("down"), httpx.ReadTimeout("slow")])
async def test_network_errors_fail_closed(rsa_key, error):
    with respx.mock(assert_all_called=True) as mock:
        mock.get(JWKS_URL).mock(side_effect=error)
        with pytest.raises(OIDCVerificationError) as info:
            await _verify(_token(rsa_key))
    assert info.value.reason == "jwks_unavailable"


@pytest.mark.parametrize("tid", ["common", TID.upper(), f"{TID}/../x", "", None])
async def test_fetcher_rejects_non_guid_tenant_without_a_request(tid):
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route().mock(return_value=httpx.Response(200, json={"keys": []}))
        with pytest.raises(ValueError):
            await fetch_microsoft_jwks(tid)
    assert not route.called
