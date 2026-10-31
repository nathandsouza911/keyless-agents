"""Script manifests: what a script run may ask the facade for (SD-041).

A script manifest is a list of entries. Each entry allows exactly one kind of
read and nothing else is allowed (deny by default):

  id           a slug, recorded with every decision the entry makes
  method       GET only; a manifest with any other method is refused at load
               time, so a write can never be approved (Phase 1)
  versions     the API versions allowed, each named explicitly (v1.0, beta)
  path         a template, "/users" or "/users/{user_id}/memberOf"; every
               placeholder takes a GUID, nothing else
  select       the properties $select may name; `select_required` (default
               true) refuses a request without $select, since Graph's default
               property set is wider than any script needs
  filter       off, or on with an optional list of the properties it may name
  top          off, or a maximum
  count, orderby, search, expand
               each off unless the entry turns it on; expand is never allowed
               in Phase 1
  consistency_level
               whether the request may carry `ConsistencyLevel: eventual`
               (advanced queries with $count or $search need it)
  profile      the permission profile the run's credential comes from

`load_script_manifest` validates a manifest document and returns it with
its SHA-256 over canonical JSON, the digest approvals bind to.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator

from clw.audit.canonical import canonical_json
from clw.audit.events import valid_path_template

_SLUG = r"^[a-z0-9]+(-[a-z0-9]+)*$"
_PROPERTY = r"^[A-Za-z][A-Za-z0-9]{0,63}$"
Slug = Annotated[str, StringConstraints(pattern=_SLUG, max_length=64)]
Property = Annotated[str, StringConstraints(pattern=_PROPERTY)]


class ManifestRefused(ValueError):
    """A script manifest that cannot be approved. The message names the problem."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class _FilterDoc(_Strict):
    allowed: bool = False
    properties: list[Property] | None = None  # None: any property, once filters are allowed


class _EntryDoc(_Strict):
    id: Slug
    method: Literal["GET"]
    versions: list[Literal["v1.0", "beta"]] = Field(min_length=1, max_length=2)
    path: str
    select: list[Property] = Field(default_factory=list, max_length=64)
    select_required: bool = True
    filter: _FilterDoc = Field(default_factory=_FilterDoc)
    top: int | None = Field(default=None, ge=1, le=999)
    count: bool = False
    orderby: bool = False
    search: bool = False
    expand: Literal[False] = False
    consistency_level: bool = False

    @field_validator("path")
    @classmethod
    def _template(cls, value: str) -> str:
        # The audit chain's own template rule (literal first segment, {placeholders}),
        # and never $batch: a batch carries other requests the policy would not see.
        if not valid_path_template(value) or "$batch" in value.lower():
            raise ValueError("path must be a template such as /users or /users/{user_id}")
        return value


class _ManifestDoc(_Strict):
    schema_version: Literal[1]
    profile: Slug
    entries: list[_EntryDoc] = Field(min_length=1, max_length=32)


@dataclass(frozen=True, slots=True)
class Entry:
    id: str
    versions: frozenset[str]
    template: str                     # as written ("/users/{user_id}/memberOf")
    segments: tuple[str, ...]          # lowercased literals and "{placeholder}"s
    select: frozenset[str]             # lowercased
    select_required: bool
    filter_allowed: bool
    filter_properties: frozenset[str] | None  # lowercased; None = any
    top: int | None
    count: bool
    orderby: bool
    search: bool
    consistency_level: bool


@dataclass(frozen=True, slots=True)
class ScriptManifest:
    profile: str
    entries: tuple[Entry, ...]
    sha256: str
    document: dict


def load_script_manifest(document: object) -> ScriptManifest:
    if isinstance(document, dict) and any(isinstance(e, dict) and e.get("method") not in (None, "GET")
                                          for e in document.get("entries", []) or []):
        raise ManifestRefused("only GET entries can be approved (Phase 1 is read-only)")
    try:
        doc = _ManifestDoc.model_validate(document)
    except ValidationError as exc:
        raise ManifestRefused(f"invalid script manifest: {exc.error_count()} problem(s)") from None
    ids = [e.id for e in doc.entries]
    if len(set(ids)) != len(ids):
        raise ManifestRefused("entry ids must be unique")
    entries = []
    for e in doc.entries:
        segments = tuple(s if s.startswith("{") else s.lower() for s in e.path.split("/")[1:])
        entries.append(Entry(
            id=e.id, versions=frozenset(e.versions), template=e.path, segments=segments,
            select=frozenset(p.lower() for p in e.select), select_required=e.select_required,
            filter_allowed=e.filter.allowed,
            filter_properties=None if e.filter.properties is None else frozenset(p.lower() for p in e.filter.properties),
            top=e.top, count=e.count, orderby=e.orderby, search=e.search, consistency_level=e.consistency_level,
        ))
        if e.select_required and not e.select:
            raise ManifestRefused(f"entry {e.id}: select is required but lists no properties")
    canonical = doc.model_dump(mode="json")
    return ScriptManifest(profile=doc.profile, entries=tuple(entries),
                          sha256=hashlib.sha256(canonical_json(canonical)).hexdigest(), document=canonical)
