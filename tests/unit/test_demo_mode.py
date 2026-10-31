"""Demo mode's refusals (SD-051): never in production, never beside real settings, fictional tenant only."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from clw.broker.credentials import CredentialRejected, MsalCertificateProvider
from clw.broker.manifest import DEFAULT_PROFILES_DIR
from clw.broker.profiles import load_profile_by_id as _load
from clw.broker.transport import GRAPH_ORIGIN, Transport
from clw.demo import DEMO_TENANT_ID, DemoModeRefused, check_api, check_broker
from clw.demo.broker import DEMO_CLIENTS, DemoIdentityProvider, demo_environ, demo_graph_client
from clw.demo.setup import write_certs

def load_profile_by_id(profile_id):
    return _load(profile_id, profiles_dir=DEFAULT_PROFILES_DIR)


REAL_TENANT = "72f988bf-0000-4000-8000-000000000001"


def _settings(**changes):
    values = {"CLW_DEMO_MODE": True, "ENVIRONMENT": "development", "MICROSOFT_CLIENT_ID": None,
              "MICROSOFT_CLIENT_SECRET": None, "OIDC_REDIRECT_URI": None} | changes
    return SimpleNamespace(**values, is_production=values["ENVIRONMENT"] == "production")


def test_the_api_starts_in_demo_mode_only_in_development_or_test_with_nothing_real():
    check_api(_settings())
    check_api(_settings(ENVIRONMENT="test"))


def test_the_api_refuses_demo_mode_in_production():
    with pytest.raises(DemoModeRefused):
        check_api(_settings(ENVIRONMENT="production"))


@pytest.mark.parametrize("name, value", [("MICROSOFT_CLIENT_ID", "aaaaaaaa-1111-4222-8333-444444444444"),
                                         ("MICROSOFT_CLIENT_SECRET", "x"),
                                         ("OIDC_REDIRECT_URI", "https://x.example/auth/microsoft/callback")])
def test_the_api_refuses_demo_mode_beside_real_sign_in_settings(name, value):
    with pytest.raises(DemoModeRefused):
        check_api(_settings(**{name: value}))


def test_without_demo_mode_nothing_is_checked():
    check_api(_settings(CLW_DEMO_MODE=False, ENVIRONMENT="production", MICROSOFT_CLIENT_ID="x"))


@pytest.mark.parametrize("environ", [{"ENVIRONMENT": "production"},
                                     {"CLW_PROFILE_DIRREAD_CLIENT_ID": "aaaaaaaa-1111-4222-8333-444444444444"},
                                     {"CLW_PROFILE_AGENTRO_CERT_PATH": "/run/secrets/key.pem"}])
def test_the_demo_broker_refuses_production_and_real_profile_credentials(environ):
    with pytest.raises(DemoModeRefused):
        check_broker(environ)


def test_the_demo_broker_starts_with_nothing_real():
    check_broker({"ENVIRONMENT": "development", "CLW_DEMO_DIR": "/demo", "CLW_PROFILE_UNSET": ""})


# --- the tenant guard, both ways -----------------------------------------------------------

@pytest.fixture
def demo_dir(tmp_path):
    write_certs(tmp_path)
    from clw.demo.setup import _key, _pem_key

    (tmp_path / "profile_key.pem").write_bytes(_pem_key(_key()))
    return tmp_path


def _provider(demo_dir, *, demo: bool) -> MsalCertificateProvider:
    return MsalCertificateProvider(resource=GRAPH_ORIGIN, environ=demo_environ(demo_dir),
                                   app_factory=DemoIdentityProvider(), demo=demo)


async def test_every_normal_broker_refuses_the_demo_tenant(demo_dir):
    with pytest.raises(CredentialRejected) as refused:
        await _provider(demo_dir, demo=False).token_for(
            tenant_id=DEMO_TENANT_ID, profile=load_profile_by_id("directory-read-auditlog-read"))
    assert refused.value.reason == "tenant_not_allowed"


async def test_the_demo_broker_refuses_every_real_tenant(demo_dir):
    with pytest.raises(CredentialRejected) as refused:
        await _provider(demo_dir, demo=True).token_for(
            tenant_id=REAL_TENANT, profile=load_profile_by_id("directory-read-auditlog-read"))
    assert refused.value.reason == "tenant_not_allowed"


@pytest.mark.parametrize("profile_id", sorted(DEMO_CLIENTS))
async def test_the_demo_broker_issues_each_profile_exactly_its_permissions(demo_dir, profile_id):
    profile = load_profile_by_id(profile_id)
    token = await _provider(demo_dir, demo=True).token_for(tenant_id=DEMO_TENANT_ID, profile=profile)
    assert token.permissions == frozenset(profile.expected_permissions)


def test_the_demo_graph_client_is_one_the_transport_accepts_and_trusts_only_the_demo_ca(demo_dir):
    client = demo_graph_client(demo_dir / "ca.pem")
    Transport(client)  # no redirects, no environment, no auth or hooks
    assert isinstance(client, httpx.AsyncClient) and client.follow_redirects is False and client.trust_env is False
