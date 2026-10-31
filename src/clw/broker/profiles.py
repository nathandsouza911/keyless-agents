"""Permission profile loader (Task 8; SD-004, SD-010).

A profile names one app registration's expected permission set and the
environment variables the broker reads its credential from (Task 10). It
holds no secret, and this loader never reads the environment: a profile
file that looks like it carries a secret (a PEM header anywhere, or 30+
base64 characters in a credential entry) is refused. Phase 1 is read-only,
so a profile that expects any write permission is refused too.

Profiles are found by id in a fixed directory: the id is a slug, the file
is `<id>.yaml`, it must resolve inside that directory, and its `id` must
equal its file name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from clw.broker._loading import ManifestError, read_yaml, validate

SLUG_PATTERN = r"^[a-z0-9]+(-[a-z0-9]+)*$"
_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_SLUG_MAX = 64
_PEM = "-----BEGIN"
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{30,}")

Slug = Annotated[str, StringConstraints(pattern=SLUG_PATTERN, max_length=_SLUG_MAX)]
EnvName = Annotated[str, StringConstraints(pattern=r"^CLW_PROFILE_[A-Z0-9_]+$", max_length=64)]
Permission = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Za-z]*(\.[A-Z][A-Za-z]*)+$", max_length=128)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class _CredentialDoc(_Strict):
    client_id_env: EnvName
    certificate_path_env: EnvName
    thumbprint_env: EnvName


class _ProfileDoc(_Strict):
    id: Slug
    version: int = Field(ge=1)
    mode: Literal["app_only", "delegated"]
    expected_permissions: list[Permission] = Field(min_length=1, max_length=32)
    credential: _CredentialDoc

    @field_validator("expected_permissions")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate permissions")
        return value


@dataclass(frozen=True, slots=True)
class ProfileCredential:
    """Environment variable NAMES; the values are read by the broker only."""

    client_id_env: str
    certificate_path_env: str
    thumbprint_env: str


@dataclass(frozen=True, slots=True)
class PermissionProfile:
    id: str
    version: int
    mode: str
    expected_permissions: frozenset[str]
    credential: ProfileCredential
    sha256: str


def _looks_secret(data: dict) -> bool:
    credential = data.get("credential")
    if not isinstance(credential, dict):
        return False
    return any(isinstance(v, str) and (_BASE64_RUN.search(v) or _PEM in v) for v in credential.values())


def load_profile(path: Path) -> PermissionProfile:
    path = Path(path)
    name = path.name
    # The PEM check reads the raw text, so a key pasted into a comment is caught too.
    try:
        pem = _PEM.encode() in path.read_bytes()[: 1 << 20]
    except OSError:
        pem = False  # read_yaml reports the unreadable file
    if pem:
        raise ManifestError(f"{name}: contains what looks like a secret (PEM header)")
    loaded = read_yaml(path)
    if _looks_secret(loaded.data):
        raise ManifestError(f"{name}: a credential entry looks like a secret value, not an environment variable name")
    doc = validate(_ProfileDoc, loaded.data, name)
    if path.stem != doc.id or path.suffix != ".yaml":
        raise ManifestError(f"{name}: file name must be <id>.yaml")
    writes = [p for p in doc.expected_permissions if "write" in p.lower()]
    if writes:
        raise ManifestError(f"{name}: Phase 1 profiles are read-only; a write permission is expected")
    return PermissionProfile(
        id=doc.id,
        version=doc.version,
        mode=doc.mode,
        expected_permissions=frozenset(doc.expected_permissions),
        credential=ProfileCredential(**doc.credential.model_dump()),
        sha256=loaded.sha256,
    )


def load_profile_by_id(profile_id: str, *, profiles_dir: Path) -> PermissionProfile:
    if not (isinstance(profile_id, str) and len(profile_id) <= _SLUG_MAX and _SLUG.match(profile_id)):
        raise ManifestError("permission profile id is not a valid slug")
    base = Path(profiles_dir).resolve()
    try:
        resolved = (base / f"{profile_id}.yaml").resolve(strict=True)
    except OSError:
        resolved = None
    if resolved is None or resolved.parent != base or not resolved.is_file():
        raise ManifestError(f"permission profile {profile_id} not found")
    return load_profile(resolved)  # which requires the file's id to equal its name
