"""Profile credential provider and token validation (Task 10, SD-004).

The provider gets an app-only Graph token for one (tenant, permission
profile) and checks it is the right token. It knows nothing about tasks or
operations: whether an operation may run is the policy's decision
(clw.broker.policy), made separately and never from token claims.

`validate_token_claims` refuses, in this order:
  tid_missing / tid_mismatch      `tid` absent, or not exactly the run's tenant
  appid_missing / appid_mismatch  neither `appid` nor `azp`, or any present
                                  one not exactly the profile's client id
  aud_mismatch                    `aud` not exactly the Graph resource
  not_app_token                   `scp` present, `idtyp` present and not
                                  "app", or neither `idtyp` nor `roles`
  permissions_extra               any role outside the profile's expected
                                  set (or not a string)
  permissions_missing             any expected role absent
Claim names follow A-06 and A-08, both unverified: `appid` or `azp` is
accepted, and an app-only token is idtyp == "app", or roles without idtyp.
Signatures are not checked (A-07): the token comes straight from the
Entra token endpoint over TLS.

The Graph resource is a required argument, not a constant here: only
clw.broker.transport names the Graph host (Task 0 boundary), and the
broker passes transport's origin (Task 12), so the audience a token is
checked against is the origin requests are sent to.

Credentials come from the environment variables the profile names, read
only when an app is first built for a (tenant, profile). The private key
and token never appear in a repr, an exception message or its context.
"""

from __future__ import annotations

import asyncio
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol, get_args

import jwt
import msal

from clw.broker.profiles import PermissionProfile
from clw.common.timeutil import utc_now
from clw.demo import DEMO_TENANT_ID

Reason = Literal[
    "tid_missing", "tid_mismatch", "appid_missing", "appid_mismatch", "aud_mismatch",
    "not_app_token", "permissions_missing", "permissions_extra", "acquisition_failed",
    "tenant_not_allowed",  # SD-051: the demo tenant on a real broker, or a real tenant on the demo broker
]
_REASONS = frozenset(get_args(Reason))

AUTHORITY_HOST = "https://login.microsoftonline.com"
MIN_LIFETIME = timedelta(seconds=60)
MAX_KEY_FILE_BYTES = 64 * 1024

_TENANT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_CLIENT_ID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_THUMBPRINT = re.compile(r"[0-9a-fA-F]{40}\Z")
_ORIGIN = re.compile(r"https://[a-z0-9]+(?:[.-][a-z0-9]+)*\Z")
_EMPTY = (None, "")


class CredentialRejected(Exception):
    """The token is not the profile's token, or none could be obtained. The
    message is the reason code only."""

    def __init__(self, reason: Reason) -> None:
        if reason not in _REASONS:
            raise ValueError("unknown credential rejection reason")
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ValidatedToken:
    access_token: str = field(repr=False)  # never logged, never returned to tasks, never audited
    expires_at: datetime
    permissions: frozenset[str]


class CredentialProvider(Protocol):
    async def token_for(self, *, tenant_id: str, profile: PermissionProfile) -> ValidatedToken: ...


def validate_token_claims(
    claims: Mapping[str, object], *, tenant_id: str, profile: PermissionProfile, client_id: str, audience: str
) -> frozenset[str]:
    """The token's permission set, if it equals the profile's expected set."""
    if not all(isinstance(v, str) and v for v in (tenant_id, client_id, audience)):
        raise ValueError("tenant_id, client_id and audience are required")
    if profile.mode != "app_only":
        raise ValueError("only app-only profiles are supported in Phase 1 (SD-010)")
    if not isinstance(claims, Mapping):
        raise CredentialRejected("acquisition_failed")

    if claims.get("tid") in _EMPTY:
        raise CredentialRejected("tid_missing")
    if claims["tid"] != tenant_id:
        raise CredentialRejected("tid_mismatch")

    app_ids = [claims[k] for k in ("appid", "azp") if claims.get(k) not in _EMPTY]
    if not app_ids:
        raise CredentialRejected("appid_missing")
    if any(app_id != client_id for app_id in app_ids):
        raise CredentialRejected("appid_mismatch")

    if claims.get("aud") != audience:
        raise CredentialRejected("aud_mismatch")

    if "scp" in claims or ("idtyp" in claims and claims["idtyp"] != "app") or (
        "idtyp" not in claims and "roles" not in claims
    ):
        raise CredentialRejected("not_app_token")

    roles = claims.get("roles", [])
    if type(roles) is not list:
        raise CredentialRejected("permissions_missing")
    if not all(type(role) is str for role in roles):
        raise CredentialRejected("permissions_extra")
    granted = frozenset(roles)
    if granted - profile.expected_permissions:
        raise CredentialRejected("permissions_extra")
    if profile.expected_permissions - granted:
        raise CredentialRejected("permissions_missing")
    return granted


class _Unavailable(Exception):
    pass


class MsalCertificateProvider:
    """One ConfidentialClientApplication per (tenant, profile), with MSAL's
    default in-memory token cache only. Every token, cached or not, is
    validated again before it is returned."""

    def __init__(
        self,
        *,
        resource: str,
        environ: Mapping[str, str] | None = None,
        app_factory: Callable[..., object] | None = None,
        clock: Callable[[], datetime] = utc_now,
        demo: bool = False,
    ) -> None:
        if not (isinstance(resource, str) and _ORIGIN.match(resource)):
            raise ValueError("resource must be an https origin with no path")
        self._resource = resource
        self._environ = os.environ if environ is None else environ
        self._factory = msal.ConfidentialClientApplication if app_factory is None else app_factory
        self._clock = clock
        # SD-051: a demo provider serves only the fictional tenant, and every other provider refuses it.
        self._demo = demo
        self._apps: dict[tuple[str, str, int, str], tuple[object, str]] = {}
        self._lock = threading.Lock()

    async def token_for(self, *, tenant_id: str, profile: PermissionProfile) -> ValidatedToken:
        # The tenant comes from the run record; it is also the authority path.
        if not (type(tenant_id) is str and _TENANT.match(tenant_id)):
            raise ValueError("tenant_id must be a lowercase GUID")
        if not isinstance(profile, PermissionProfile) or profile.mode != "app_only":
            raise ValueError("only app-only profiles are supported in Phase 1 (SD-010)")
        if (tenant_id == DEMO_TENANT_ID) is not self._demo:
            raise CredentialRejected("tenant_not_allowed")
        result, client_id = await asyncio.to_thread(self._acquire, tenant_id, profile)
        return self._validated(result, tenant_id, profile, client_id)

    def _read_credential(self, profile: PermissionProfile) -> tuple[str, str, str]:
        names = profile.credential
        client_id = self._environ.get(names.client_id_env)
        key_path = self._environ.get(names.certificate_path_env)
        thumbprint = self._environ.get(names.thumbprint_env)
        if not (isinstance(client_id, str) and _CLIENT_ID.match(client_id)):
            raise _Unavailable
        if not (isinstance(thumbprint, str) and _THUMBPRINT.match(thumbprint)):
            raise _Unavailable
        with open(key_path, "rb") as fh:  # a missing or empty path fails here
            pem = fh.read(MAX_KEY_FILE_BYTES + 1)
        if len(pem) > MAX_KEY_FILE_BYTES or b"PRIVATE KEY-----" not in pem:
            raise _Unavailable
        return client_id.lower(), pem.decode("ascii"), thumbprint

    def _app_for(self, tenant_id: str, profile: PermissionProfile) -> tuple[object, str]:
        key = (tenant_id, profile.id, profile.version, profile.sha256)
        with self._lock:
            entry = self._apps.get(key)
            if entry is None:
                client_id, private_key, thumbprint = self._read_credential(profile)
                app = self._factory(
                    client_id,
                    authority=f"{AUTHORITY_HOST}/{tenant_id}",
                    client_credential={"private_key": private_key, "thumbprint": thumbprint},
                )
                entry = self._apps[key] = (app, client_id)
            return entry

    def _acquire(self, tenant_id: str, profile: PermissionProfile) -> tuple[object, str]:
        outcome = None
        try:
            app, client_id = self._app_for(tenant_id, profile)
            outcome = (app.acquire_token_for_client(scopes=[f"{self._resource}/.default"]), client_id)
        except Exception:  # noqa: BLE001 - configuration, file and MSAL errors all mean no token
            pass
        if outcome is None:
            # Raised outside the except block: the original (which may quote
            # MSAL's response or a file) is not attached as context.
            raise CredentialRejected("acquisition_failed")
        return outcome

    def _validated(
        self, result: object, tenant_id: str, profile: PermissionProfile, client_id: str
    ) -> ValidatedToken:
        token = result.get("access_token") if isinstance(result, dict) else None
        claims = None
        if type(token) is str and token:
            try:
                claims = jwt.decode(token, options={"verify_signature": False})
            except jwt.PyJWTError:
                pass
        if not isinstance(claims, dict):
            raise CredentialRejected("acquisition_failed")
        permissions = validate_token_claims(
            claims, tenant_id=tenant_id, profile=profile, client_id=client_id, audience=self._resource
        )
        exp = claims.get("exp")
        expires_at = datetime.fromtimestamp(exp, timezone.utc) if type(exp) is int and 0 < exp < 2**33 else None
        if expires_at is None or expires_at - self._clock() < MIN_LIFETIME:
            raise CredentialRejected("acquisition_failed")
        return ValidatedToken(access_token=token, expires_at=expires_at, permissions=permissions)
