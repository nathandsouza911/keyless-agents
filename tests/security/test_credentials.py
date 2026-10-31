"""Profile credential provider and token validation (Task 10, SD-004;
threat model T8, T16).

# A-06/A-08: claim names are unverified. Until they are, the validator
# takes `appid` or `azp` for the app id, and an app-only token is one with
# idtyp == "app", or roles present and no idtyp; `scp` always refuses. Revise
# this file when A-06 and A-08 are verified.

Tokens here are forged unsigned JWTs (alg "none"): only claims are tested,
and the client never verifies signatures (A-07). Keys are generated at
runtime; nothing here is a real credential."""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import inspect
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clw.broker import credentials, policy
from clw.broker.credentials import (
    CredentialRejected,
    MsalCertificateProvider,
    ValidatedToken,
    validate_token_claims,
)
from clw.broker.manifest import load_manifest
from clw.broker.policy import AllowlistPolicyEngine, Decision, evaluate
from clw.broker.profiles import load_profile

REPO = Path(__file__).resolve().parents[2]
PROFILE = load_profile(REPO / "profiles" / "directory-read-auditlog-read.yaml")
MANIFEST = load_manifest(REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml")
GRAPH = "https://graph.microsoft.com"  # in production, supplied by clw.broker.transport (Task 11)
TENANT = "1111aaaa-2222-4333-8444-555555555555"
OTHER_TENANT = "99999999-2222-4333-8444-555555555555"
CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
THUMB = "0123456789abcdef0123456789abcdef01234567"
EXPECTED = sorted(PROFILE.expected_permissions)
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def _claims(**changes):
    claims = {
        "aud": GRAPH, "tid": TENANT, "appid": CLIENT, "idtyp": "app", "roles": list(EXPECTED),
        "exp": int((NOW + timedelta(hours=1)).timestamp()),
    }
    for key, value in changes.items():
        if value is _DROP:
            claims.pop(key, None)
        else:
            claims[key] = value
    return claims


_DROP = object()


def _validate(claims, **kwargs):
    args = {"tenant_id": TENANT, "profile": PROFILE, "client_id": CLIENT, "audience": GRAPH} | kwargs
    return validate_token_claims(claims, **args)


def _reason(claims, **kwargs):
    with pytest.raises(CredentialRejected) as info:
        _validate(claims, **kwargs)
    return info.value.reason


def _token(claims) -> str:
    return jwt.encode(claims, None, algorithm="none")


# --- validate_token_claims: the plan's cases ------------------------------------


def test_valid_claims_return_the_permission_set():
    assert _validate(_claims()) == frozenset(EXPECTED)


def test_missing_tid():
    assert _reason(_claims(tid=_DROP)) == "tid_missing"


def test_wrong_tid():
    assert _reason(_claims(tid=OTHER_TENANT)) == "tid_mismatch"


def test_missing_appid_and_azp():
    assert _reason(_claims(appid=_DROP)) == "appid_missing"


def test_wrong_appid():
    assert _reason(_claims(appid="bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee")) == "appid_mismatch"


@pytest.mark.parametrize("aud", [
    "https://management.azure.com", "https://graph.microsoft.com/", "https://GRAPH.microsoft.com",
    "00000003-0000-0000-c000-000000000000", "", [GRAPH], None,
])
def test_audience_not_graph(aud):
    assert _reason(_claims(aud=aud)) == "aud_mismatch"


def test_missing_audience():
    assert _reason(_claims(aud=_DROP)) == "aud_mismatch"


def test_scp_present_is_not_an_app_token():
    assert _reason(_claims(scp="User.Read")) == "not_app_token"


def test_extra_role_is_permissions_extra():
    assert _reason(_claims(roles=[*EXPECTED, "User.ReadWrite.All"])) == "permissions_extra"


def test_missing_role_is_permissions_missing():
    roles = [r for r in EXPECTED if r != "AuditLog.Read.All"]
    assert _reason(_claims(roles=roles)) == "permissions_missing"


async def test_msal_error_dict_is_acquisition_failed(provider_env):
    provider, apps = provider_env({"error": "invalid_client", "error_description": "AADSTS7000215 secret-ish detail"})
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "acquisition_failed"
    assert "AADSTS" not in str(info.value) and info.value.__context__ is None


def test_validated_token_repr_has_no_token():
    token = _token(_claims())
    vt = ValidatedToken(access_token=token, expires_at=NOW, permissions=frozenset(EXPECTED))
    for rendering in (repr(vt), str(vt), f"{vt}", repr([vt])):
        assert token not in rendering and "eyJ" not in rendering


# --- validate_token_claims: further cases ------------------------------------------


@pytest.mark.parametrize("tid", [TENANT.upper(), f" {TENANT}", f"{TENANT}\n", 1, None, ""])
def test_tid_must_match_exactly(tid):
    assert _reason(_claims(tid=tid)) in {"tid_mismatch", "tid_missing"}


def test_azp_is_accepted_when_appid_is_absent():
    assert _validate(_claims(appid=_DROP, azp=CLIENT)) == frozenset(EXPECTED)


def test_appid_and_azp_must_agree():
    assert _reason(_claims(azp="bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee")) == "appid_mismatch"
    assert _validate(_claims(azp=CLIENT)) == frozenset(EXPECTED)


@pytest.mark.parametrize("appid", [CLIENT.upper(), 1, None, ""])
def test_appid_must_be_the_exact_string(appid):
    assert _reason(_claims(appid=appid)) in {"appid_mismatch", "appid_missing"}


@pytest.mark.parametrize("changes", [
    {"idtyp": "user"},
    {"idtyp": "app", "scp": ""},
    {"idtyp": _DROP, "scp": "User.Read.All"},
    {"idtyp": _DROP, "roles": _DROP},
    {"idtyp": "App"},
    {"idtyp": None},
])
def test_not_app_token(changes):
    assert _reason(_claims(**changes)) == "not_app_token"


def test_roles_without_idtyp_is_an_app_token():
    assert _validate(_claims(idtyp=_DROP)) == frozenset(EXPECTED)


def test_app_token_without_roles_is_permissions_missing():
    assert _reason(_claims(roles=_DROP)) == "permissions_missing"
    assert _reason(_claims(roles=[])) == "permissions_missing"


@pytest.mark.parametrize("roles", [
    [*EXPECTED, "Directory.Read.All"],
    [*EXPECTED, "user.read.all"],
    [*EXPECTED, ""],
    [*EXPECTED, 1],
    [*EXPECTED, None],
    [*EXPECTED, ["User.Read.All"]],
])
def test_unexpected_roles_are_permissions_extra(roles):
    assert _reason(_claims(roles=roles)) == "permissions_extra"


def test_extra_is_reported_before_missing():
    assert _reason(_claims(roles=["User.Read.All", "User.ReadWrite.All"])) == "permissions_extra"


@pytest.mark.parametrize("roles", ["User.Read.All AuditLog.Read.All", {"User.Read.All": 1}, 1, None])
def test_roles_must_be_a_list(roles):
    assert _reason(_claims(roles=roles)) in {"permissions_missing", "permissions_extra"}


def test_duplicate_roles_are_the_same_set():
    assert _validate(_claims(roles=[*EXPECTED, *EXPECTED])) == frozenset(EXPECTED)


@pytest.mark.parametrize("claims", [None, [], "claims", 1])
def test_non_mapping_claims_are_refused(claims):
    with pytest.raises(CredentialRejected):
        _validate(claims)


def test_delegated_profile_is_refused():
    delegated = dataclasses.replace(PROFILE, mode="delegated")
    with pytest.raises(ValueError):
        _validate(_claims(), profile=delegated)


@pytest.mark.parametrize("arg,claim", [("tenant_id", "tid"), ("client_id", "appid"), ("audience", "aud")])
@pytest.mark.parametrize("value", ["", None])
def test_empty_expected_values_never_match(arg, claim, value):
    # An empty or missing expected value is a caller bug, refused even when
    # the token carries the same empty value.
    with pytest.raises(ValueError):
        _validate(_claims(**{claim: value}), **{arg: value})


def test_rejection_message_holds_only_the_reason():
    err = CredentialRejected("permissions_extra")
    assert str(err) == "permissions_extra" and err.reason == "permissions_extra"
    with pytest.raises(ValueError):
        CredentialRejected("something_else")


def test_validated_token_is_frozen():
    vt = ValidatedToken(access_token="x", expires_at=NOW, permissions=frozenset())
    with pytest.raises(dataclasses.FrozenInstanceError):
        vt.permissions = frozenset({"User.ReadWrite.All"})  # type: ignore[misc]


# --- MsalCertificateProvider -------------------------------------------------------------


class FakeApp:
    def __init__(self, client_id, *, authority, client_credential, **kwargs):
        self.client_id, self.authority, self.client_credential, self.kwargs = client_id, authority, client_credential, kwargs
        self.result: object = None
        self.scopes: list = []

    def acquire_token_for_client(self, scopes):
        self.scopes.append(list(scopes))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def key_pem(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = tmp_path / "dirread.pem"
    path.write_bytes(pem)
    return path, pem


@pytest.fixture
def environ(key_pem):
    path, _ = key_pem
    return {
        PROFILE.credential.client_id_env: CLIENT,
        PROFILE.credential.certificate_path_env: str(path),
        PROFILE.credential.thumbprint_env: THUMB,
    }


@pytest.fixture
def provider_env(environ):
    def make(result, *, env=None, clock=lambda: NOW):
        apps: list[FakeApp] = []

        def factory(*args, **kwargs):
            app = FakeApp(*args, **kwargs)
            app.result = result
            apps.append(app)
            return app

        provider = MsalCertificateProvider(resource=GRAPH, environ=environ if env is None else env,
                                           app_factory=factory, clock=clock)
        return provider, apps
    return make


def _msal_ok(claims=None):
    return {"access_token": _token(_claims() if claims is None else claims), "token_type": "Bearer", "expires_in": 3599}


async def test_provider_returns_a_validated_token(provider_env, key_pem):
    result = _msal_ok()
    provider, apps = provider_env(result)
    vt = await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert vt.access_token == result["access_token"]
    assert vt.permissions == frozenset(EXPECTED)
    assert vt.expires_at == NOW + timedelta(hours=1)
    (app,) = apps
    assert app.client_id == CLIENT
    assert app.authority == f"https://login.microsoftonline.com/{TENANT}"
    assert app.client_credential == {"private_key": key_pem[1].decode(), "thumbprint": THUMB}
    assert app.scopes == [[f"{GRAPH}/.default"]]


async def test_provider_never_passes_a_persistent_cache(provider_env):
    provider, apps = provider_env(_msal_ok())
    await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert "token_cache" not in apps[0].kwargs  # MSAL's default cache is in memory


async def test_one_app_per_tenant_and_profile(provider_env):
    provider, apps = provider_env(_msal_ok())
    await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert len(apps) == 1 and len(apps[0].scopes) == 2   # every token is validated again
    await provider.token_for(tenant_id=TENANT, profile=dataclasses.replace(PROFILE, sha256="0" * 64))
    assert len(apps) == 2   # a changed profile gets its own app
    await provider.token_for(tenant_id=TENANT, profile=dataclasses.replace(PROFILE, version=2))
    assert len(apps) == 3
    apps[0].result = _msal_ok(_claims(tid=OTHER_TENANT))
    with pytest.raises(CredentialRejected):
        await provider.token_for(tenant_id=OTHER_TENANT, profile=PROFILE)   # another tenant, another app
    assert len(apps) == 4 and apps[3].authority.endswith(OTHER_TENANT)


async def test_token_for_another_tenant_is_rejected(provider_env):
    provider, apps = provider_env(_msal_ok(_claims(tid=OTHER_TENANT)))
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "tid_mismatch"


async def test_over_consented_token_is_rejected(provider_env):
    provider, _ = provider_env(_msal_ok(_claims(roles=[*EXPECTED, "User.ReadWrite.All"])))
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "permissions_extra"


@pytest.mark.parametrize("result", [
    None, {}, {"access_token": ""}, {"access_token": None}, {"access_token": "not-a-jwt"}, "eyJ", [],
    {"access_token": "a.b.c"}, RuntimeError("network down"),
    {"access_token": _token(_claims()).encode()},          # PyJWT would decode bytes
])
async def test_bad_msal_results_are_acquisition_failed(provider_env, result):
    provider, _ = provider_env(result)
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "acquisition_failed" and info.value.__context__ is None


@pytest.mark.parametrize("exp", [_DROP, None, "9999999999", True, 1.5e9, float(int((NOW + timedelta(hours=1)).timestamp())),
                                 int(NOW.timestamp()), int((NOW + timedelta(seconds=30)).timestamp())])
async def test_expired_or_unusable_exp_is_acquisition_failed(provider_env, exp):
    provider, _ = provider_env(_msal_ok(_claims(exp=exp)))
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "acquisition_failed"


@pytest.mark.parametrize("missing", ["client_id_env", "certificate_path_env", "thumbprint_env"])
async def test_missing_environment_is_acquisition_failed(provider_env, environ, missing):
    env = dict(environ)
    del env[getattr(PROFILE.credential, missing)]
    provider, apps = provider_env(_msal_ok(), env=env)
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "acquisition_failed" and apps == []


@pytest.mark.parametrize("key,value", [
    ("client_id_env", "not-a-guid"), ("client_id_env", ""), ("thumbprint_env", "xyz"),
    ("thumbprint_env", THUMB + "00"), ("certificate_path_env", "/nonexistent/key.pem"), ("certificate_path_env", ""),
])
async def test_malformed_environment_is_acquisition_failed(provider_env, environ, key, value):
    env = dict(environ) | {getattr(PROFILE.credential, key): value}
    provider, apps = provider_env(_msal_ok(), env=env)
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert info.value.reason == "acquisition_failed" and apps == []


async def test_certificate_file_without_a_private_key_is_refused(provider_env, environ, tmp_path):
    path = tmp_path / "public.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    provider, apps = provider_env(_msal_ok(), env=environ | {PROFILE.credential.certificate_path_env: str(path)})
    with pytest.raises(CredentialRejected):
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert apps == []


async def test_uppercase_client_id_is_normalized(provider_env, environ):
    provider, apps = provider_env(_msal_ok(), env=environ | {PROFILE.credential.client_id_env: CLIENT.upper()})
    await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert apps[0].client_id == CLIENT


@pytest.mark.parametrize("tenant", [
    TENANT.upper(), "common", "organizations", f"{TENANT}/../evil", "evil.example", "", None, 1,
])
async def test_tenant_must_be_a_lowercase_guid(provider_env, tenant):
    provider, apps = provider_env(_msal_ok())
    with pytest.raises(ValueError):
        await provider.token_for(tenant_id=tenant, profile=PROFILE)
    assert apps == []


async def test_delegated_profile_is_refused_before_acquisition(provider_env):
    provider, apps = provider_env(_msal_ok())
    with pytest.raises(ValueError):
        await provider.token_for(tenant_id=TENANT, profile=dataclasses.replace(PROFILE, mode="delegated"))
    assert apps == []


@pytest.mark.parametrize("resource", [
    "", "http://graph.microsoft.com", "https://graph.microsoft.com/", "https://graph.microsoft.com/v1.0",
    "https://graph.microsoft.com/.default", None,
])
def test_resource_must_be_an_https_origin(resource, environ):
    with pytest.raises(ValueError):
        MsalCertificateProvider(resource=resource, environ=environ)


async def test_no_secret_in_reprs_or_errors(provider_env, key_pem):
    _, pem = key_pem
    key_text = pem.decode().splitlines()[1]
    result = _msal_ok(_claims(roles=[*EXPECTED, "User.ReadWrite.All"]))
    provider, _ = provider_env(result)
    with pytest.raises(CredentialRejected) as info:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    rendered = "".join(traceback.format_exception(info.value)) + repr(provider)
    for secret in (result["access_token"], key_text, THUMB):
        assert secret not in rendered


async def test_provider_reads_only_the_profile_environment(provider_env, environ):
    reads = []

    class Recording(dict):
        def get(self, key, default=None):
            reads.append(key)
            return super().get(key, default)

        def __getitem__(self, key):
            reads.append(key)
            return super().__getitem__(key)

    provider, _ = provider_env(_msal_ok(), env=Recording(environ | {"AZURE_CLIENT_SECRET": "x"}))
    await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    assert set(reads) == set(environ)


async def test_token_for_runs_msal_off_the_event_loop(provider_env):
    # MSAL is synchronous network I/O; it must not block the broker's loop.
    seen = []
    provider, apps = provider_env(_msal_ok())
    orig = FakeApp.acquire_token_for_client

    def record(self, scopes):
        try:
            asyncio.get_running_loop()
            seen.append("loop")
        except RuntimeError:
            seen.append("thread")
        return orig(self, scopes)

    FakeApp.acquire_token_for_client = record
    try:
        await provider.token_for(tenant_id=TENANT, profile=PROFILE)
    finally:
        FakeApp.acquire_token_for_client = orig
    assert seen == ["thread"]


# --- Separation from task authorization (SD-004) -------------------------------------------


def _module_imports(module) -> set[str]:
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{a.name}" for a in node.names)
    return names


def test_credentials_know_nothing_about_tasks_or_operations():
    imports = _module_imports(credentials)
    for forbidden in ("clw.broker.policy", "clw.broker.manifest", "clw.broker.operations"):
        assert not any(n == forbidden or n.startswith(forbidden + ".") for n in imports), forbidden
    for name in ("validate_token_claims",):
        params = set(inspect.signature(getattr(credentials, name)).parameters)
        assert params == {"claims", "tenant_id", "profile", "client_id", "audience"}
    assert set(inspect.signature(MsalCertificateProvider.token_for).parameters) == {"self", "tenant_id", "profile"}


def test_policy_never_consults_credentials():
    imports = _module_imports(policy)
    assert not any("credentials" in n or n.split(".")[0] in {"msal", "jwt"} for n in imports)
    assert set(inspect.signature(evaluate).parameters) == {"engine", "manifest", "op_name", "params"}


GUID = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"


@pytest.mark.parametrize("op,params,reason", [
    ("users.update", {"user_id": GUID}, "prohibited"),
    ("users.delete", {"user_id": GUID}, "prohibited"),
    ("directory_roles.add_member", {"role_id": GUID}, "prohibited"),
    ("graph.raw", {}, "unknown_operation"),
    ("users.list_with_sign_in_activity", {"select": ["id"], "path": "/users"}, "invalid_params"),
])
def test_a_valid_token_does_not_make_the_policy_allow(op, params, reason):
    # The profile's token is accepted (even one carrying write roles, had the
    # profile expected them), and the policy still denies: it has no token
    # input, and the decision is the same whichever token exists.
    write_profile = dataclasses.replace(PROFILE, expected_permissions=frozenset({*EXPECTED, "User.ReadWrite.All"}))
    assert _validate(_claims(roles=[*EXPECTED, "User.ReadWrite.All"]), profile=write_profile)
    assert _validate(_claims()) == PROFILE.expected_permissions
    assert evaluate(AllowlistPolicyEngine(), MANIFEST, op, params) == (Decision(False, reason), None)


def test_a_policy_allow_does_not_make_a_token_valid():
    # The policy allows the list op; the credential check still refuses a bad token.
    decision, _ = evaluate(AllowlistPolicyEngine(), MANIFEST, "users.list_with_sign_in_activity", {"select": ["id"]})
    assert decision.allowed
    assert _reason(_claims(roles=[*EXPECTED, "User.ReadWrite.All"])) == "permissions_extra"
    assert _reason(_claims(tid=OTHER_TENANT)) == "tid_mismatch"
