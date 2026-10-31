"""Task manifest loader (Task 8; SD-002, SD-003, SD-010).

A manifest names registered operations only. It has no field for a method,
path, query, $select or bound, so it can narrow what a task may call but
cannot change the request the registry builds (clw.broker.operations).
Stage 2 of the policy (Task 9) derives method + path patterns from the
registry entries named here, never from the manifest.

Refused at load (ManifestError; the run fails to start, threat model §5):
unsafe or invalid YAML, unknown keys, wrong types, `mode` other than
app_only (SD-010), `approval_required: true` (no approval workflow exists
in Phase 1, so the flag could not be honoured), an allowed or prohibited
name that is not registered, an allowed write or non-executable operation,
duplicates, an overlap between allowed and prohibited, a missing or
invalid profile, a profile whose mode differs, and a timeout outside
10-900 seconds.

`sha256` is of the manifest's raw bytes (the audit chain's
task_manifest_sha256). The resolved profile is attached, with its own
sha256, so a run uses the profile that was checked here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from clw.broker import operations
from clw.broker._loading import ManifestError, read_yaml, validate
from clw.broker.profiles import PermissionProfile, Slug, load_profile_by_id

__all__ = ["DEFAULT_PROFILES_DIR", "ManifestError", "ParamSpec", "TaskManifest", "load_manifest"]

DEFAULT_PROFILES_DIR = Path(__file__).resolve().parents[3] / "profiles"
MIN_TIMEOUT_SECONDS = 10
MAX_TIMEOUT_SECONDS = 900

_NO_CONTROL = r"^[^\x00-\x1f\x7f]+$"
ParamName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
OpName = Annotated[str, StringConstraints(max_length=128)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class _ParamDoc(_Strict):
    type: Literal["integer"]
    minimum: int
    maximum: int
    default: int | None = None

    @model_validator(mode="after")
    def _bounds(self) -> _ParamDoc:
        if self.minimum > self.maximum:
            raise ValueError("minimum is greater than maximum")
        if self.default is not None and not self.minimum <= self.default <= self.maximum:
            raise ValueError("default is outside the bounds")
        return self


class _ManifestDoc(_Strict):
    schema_version: Literal[1]
    id: Slug
    version: int = Field(ge=1)
    name: Annotated[str, StringConstraints(pattern=_NO_CONTROL, max_length=100)]
    purpose: Annotated[str, StringConstraints(pattern=_NO_CONTROL, max_length=500)]
    permission_profile: Slug
    mode: Literal["app_only", "delegated"]
    allowed: list[OpName] = Field(min_length=1, max_length=64)
    prohibited: list[OpName] = Field(max_length=64)
    params: dict[ParamName, _ParamDoc] = Field(default_factory=dict, max_length=32)
    approval_required: bool
    timeout_seconds: int = Field(ge=MIN_TIMEOUT_SECONDS, le=MAX_TIMEOUT_SECONDS)
    # The change proposals an agent session under this profile may file (SD-054); none unless listed.
    proposals: list[Literal["disable_user"]] = Field(default_factory=list, max_length=8)
    # Who may start an agent session under this profile (decision A, 2026-10-31); nobody unless listed.
    start_roles: list[Literal["analyst", "security_lead"]] = Field(default_factory=list, max_length=2)


@dataclass(frozen=True, slots=True)
class ParamSpec:
    type: str
    minimum: int
    maximum: int
    default: int | None


@dataclass(frozen=True, slots=True)
class TaskManifest:
    schema_version: int
    id: str
    version: int
    name: str
    purpose: str
    permission_profile: str
    mode: str
    allowed: tuple[str, ...]
    prohibited: tuple[str, ...]
    params: Mapping[str, ParamSpec]
    approval_required: bool
    timeout_seconds: int
    sha256: str
    profile: PermissionProfile
    proposals: tuple[str, ...] = ()  # SD-054: the proposals this profile allows an agent to file
    start_roles: tuple[str, ...] = ()  # SD-055: the workbench roles that may start a session under it


def _check_operations(doc: _ManifestDoc, name: str) -> None:
    for field, entries in (("allowed", doc.allowed), ("prohibited", doc.prohibited)):
        if len(set(entries)) != len(entries):
            raise ManifestError(f"{name}: duplicate entries in {field}")
        for index, entry in enumerate(entries):
            if entry not in operations.REGISTRY:
                raise ManifestError(f"{name}: {field}[{index}] is not a registered operation")
    if set(doc.allowed) & set(doc.prohibited):
        raise ManifestError(f"{name}: an operation is both allowed and prohibited")
    for index, entry in enumerate(doc.allowed):
        spec = operations.get(entry)
        if spec.kind != "read" or not spec.executable:
            raise ManifestError(f"{name}: allowed[{index}] is a write or non-executable operation")
        if spec.internal_only:  # the broker's own (SD-054): no task or agent may call it
            raise ManifestError(f"{name}: allowed[{index}] is an internal operation")


def load_manifest(path: Path, *, profiles_dir: Path = DEFAULT_PROFILES_DIR) -> TaskManifest:
    path = Path(path)
    name = path.name
    loaded = read_yaml(path)
    doc = validate(_ManifestDoc, loaded.data, name)
    if doc.mode != "app_only":
        raise ManifestError(f"{name}: delegated mode is not executable in Phase 1 (SD-010)")
    if doc.approval_required:
        raise ManifestError(f"{name}: approval_required is not supported in Phase 1 (no approval workflow)")
    _check_operations(doc, name)
    profile = load_profile_by_id(doc.permission_profile, profiles_dir=profiles_dir)
    if profile.mode != doc.mode:
        raise ManifestError(f"{name}: profile mode differs from the manifest mode")
    return TaskManifest(
        schema_version=doc.schema_version,
        id=doc.id,
        version=doc.version,
        name=doc.name,
        purpose=doc.purpose,
        permission_profile=doc.permission_profile,
        mode=doc.mode,
        allowed=tuple(doc.allowed),
        prohibited=tuple(doc.prohibited),
        params=MappingProxyType({
            k: ParamSpec(type=v.type, minimum=v.minimum, maximum=v.maximum, default=v.default)
            for k, v in doc.params.items()
        }),
        approval_required=doc.approval_required,
        timeout_seconds=doc.timeout_seconds,
        sha256=loaded.sha256,
        profile=profile,
        proposals=tuple(doc.proposals),
        start_roles=tuple(doc.start_roles),
    )
