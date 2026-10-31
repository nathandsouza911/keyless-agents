"""Named operation registry and request builder (Task 7, SD-002, SD-018).

No interface accepts a URL, path, method or header. A caller names a
registered operation and passes parameters; the operation's strict params
model validates them; this module alone fills the fixed template.

Parameters (SD-018), per operation:
  users.list_with_sign_in_activity
    select  required, non-empty, no duplicates, each from the allowlist.
            Sets the returned properties, so it bounds the scope of returned
            data. Emitted as $select, sorted, whatever the input order, so
            equal selections build equal requests.
    top     optional, 1..500 (A-04: the documented maximum when $select
            includes signInActivity). Page size only; does not change which
            users or properties are returned. Emitted as $top.
  Path ids (users.update, users.delete, directory_roles.add_member)
    user_id / role_id  a GUID, checked by the params model and again before
            templating; emitted lowercase.

  directory.list_role_definitions, directory.list_role_assignments,
  service_principals.list, service_principals.list_app_role_assigned_to (v0.1, SD-053)
    The agent tools' reads. A registry entry may fix extra query parameters
    itself (fixed_query: $expand=principal on role assignments); a caller
    never supplies them. Each declares the properties its results may carry
    (response_properties, and nested_properties for an expanded or embedded
    object); the broker drops everything else before anything is returned.

  users.get_identity (v0.1, SD-054)
    One user by id, for a change proposal's display snapshot. Internal only:
    no manifest may list it (the loader refuses), so no task or agent can
    call it; the broker runs it itself inside the proposal flow, for the
    proposal's own target. Its $select is fixed by the registry; the
    response is a single object (single), not a collection.

Nothing else is accepted from a caller: no $expand, $filter, $search,
$orderby, $count or $skip. Pagination ($skiptoken, @odata.nextLink) is the broker's alone
(Task 11); it is never a parameter. The BuiltRequest is the normalized form
that is both authorized and executed.

Write operations are registered for display and prohibition only: they are
not executable in Phase 1 and build_request refuses them before reading
their parameters. Their request bodies are not modelled.
"""

from __future__ import annotations

import re
import string
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from clw.audit.events import GRAPH_VERSION_PREFIX, target_matches_template, valid_path_template

_GUID_PATTERN = r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"
# Explicit ASCII classes; \Z rejects a trailing newline that $ would allow.
_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")
# A-04 (verified against Microsoft Learn, user-list v1.0, 2026-10-20): when
# $select or $filter includes signInActivity, the maximum page size for $top is
# 500; Graph silently caps a larger $top to 500. This operation always selects
# signInActivity, so its $top is bounded at the documented maximum.
_MAX_TOP = 500

Guid = Annotated[str, StringConstraints(pattern=_GUID_PATTERN)]


class UnknownOperation(KeyError):
    """Not a registered operation. Callers treat it as unknown_operation."""


class NotExecutable(Exception):
    """A registered operation that may not be executed (every Phase 1 write)."""


class InvalidParams(ValueError):
    """Parameters that cannot be built into a safe request."""


@dataclass(frozen=True)
class OperationSpec:
    name: str
    kind: Literal["read", "write"]
    executable: bool
    method: Literal["GET", "POST", "PATCH", "DELETE"]
    path_template: str
    params_model: type[BaseModel]
    select_allowlist: frozenset[str] = frozenset()
    paginated: bool = False
    # Query parameters the registry itself fixes (SD-053); never from a caller.
    fixed_query: tuple[tuple[str, str], ...] = ()
    # When set, the only properties a returned item keeps (SD-053); an object
    # (or a list of objects) under a key in nested_properties keeps only those.
    response_properties: frozenset[str] | None = None
    nested_properties: Mapping[str, frozenset[str]] = field(default_factory=lambda: MappingProxyType({}))
    # One object, not a {"value": [...]} collection (SD-054); never paginated.
    single: bool = False
    # Run only by the broker itself; no manifest may list it (SD-054).
    internal_only: bool = False


@dataclass(frozen=True)
class BuiltRequest:
    method: str
    path_template: str
    path: str  # relative to /v1.0; starts with "/"; no "..", "//", "%", "\\"
    query: tuple[tuple[str, str], ...]


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


# --- users.list_with_sign_in_activity ---------------------------------------

_USER_SELECT = (
    "id", "displayName", "userPrincipalName", "accountEnabled", "createdDateTime", "userType", "signInActivity",
)
UserSelect = Literal[
    "id", "displayName", "userPrincipalName", "accountEnabled", "createdDateTime", "userType", "signInActivity",
]


class ListUsersParams(_Params):
    select: list[UserSelect] = Field(min_length=1)
    top: int | None = Field(default=None, ge=1, le=_MAX_TOP)

    @field_validator("select")
    @classmethod
    def _no_duplicates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate $select entries")
        return value


# --- v0.1 agent tools' reads (SD-053) ---------------------------------------

class NoParams(_Params):
    pass


_SP_SELECT = ("id", "appId", "displayName", "servicePrincipalType", "accountEnabled", "appRoles")
ServicePrincipalSelect = Literal["id", "appId", "displayName", "servicePrincipalType", "accountEnabled", "appRoles"]
# Graph's default and maximum page size for service principals (A-33).
_MAX_SP_TOP = 100


class ListServicePrincipalsParams(_Params):
    select: list[ServicePrincipalSelect] = Field(min_length=1)
    top: int | None = Field(default=None, ge=1, le=_MAX_SP_TOP)

    @field_validator("select")
    @classmethod
    def _no_duplicates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate $select entries")
        return value


_ASSIGNED_TO_SELECT = ("id", "appRoleId", "principalId", "principalDisplayName", "principalType", "createdDateTime")
AssignedToSelect = Literal["id", "appRoleId", "principalId", "principalDisplayName", "principalType",
                           "createdDateTime"]


class AppRoleAssignedToParams(_Params):
    sp_id: Guid
    select: list[AssignedToSelect] = Field(min_length=1)

    @field_validator("select")
    @classmethod
    def _no_duplicates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate $select entries")
        return value


# The user properties a change proposal's display snapshot holds (SD-054).
IDENTITY_SELECT = "accountEnabled,displayName,id,userPrincipalName"

# An expanded role-assignment principal keeps these and nothing else (owner ruling, 2026-10-30).
PRINCIPAL_PROPERTIES = frozenset({"id", "displayName", "userPrincipalName", "@odata.type"})


# --- write operations (not executable) --------------------------------------

class UserIdParams(_Params):
    user_id: Guid


class RoleIdParams(_Params):
    role_id: Guid


_SPECS = (
    OperationSpec(
        name="users.list_with_sign_in_activity", kind="read", executable=True, method="GET",
        path_template="/users", params_model=ListUsersParams,
        select_allowlist=frozenset(_USER_SELECT), paginated=True,
        response_properties=frozenset(_USER_SELECT),
        nested_properties=MappingProxyType({"signInActivity": frozenset({
            "lastSignInDateTime", "lastSuccessfulSignInDateTime", "lastNonInteractiveSignInDateTime"})}),
    ),
    OperationSpec(
        name="directory.list_role_definitions", kind="read", executable=True, method="GET",
        path_template="/roleManagement/directory/roleDefinitions", params_model=NoParams, paginated=True,
        response_properties=frozenset({"id", "displayName", "isBuiltIn", "templateId"}),
    ),
    OperationSpec(
        name="directory.list_role_assignments", kind="read", executable=True, method="GET",
        path_template="/roleManagement/directory/roleAssignments", params_model=NoParams, paginated=True,
        fixed_query=(("$expand", "principal"),),
        response_properties=frozenset({"id", "principalId", "roleDefinitionId", "directoryScopeId", "principal"}),
        nested_properties=MappingProxyType({"principal": PRINCIPAL_PROPERTIES}),
    ),
    OperationSpec(
        name="service_principals.list", kind="read", executable=True, method="GET",
        path_template="/servicePrincipals", params_model=ListServicePrincipalsParams,
        select_allowlist=frozenset(_SP_SELECT), paginated=True,
        response_properties=frozenset(_SP_SELECT),
        nested_properties=MappingProxyType({"appRoles": frozenset({"id", "value", "displayName",
                                                                   "allowedMemberTypes"})}),
    ),
    OperationSpec(
        name="service_principals.list_app_role_assigned_to", kind="read", executable=True, method="GET",
        path_template="/servicePrincipals/{sp_id}/appRoleAssignedTo", params_model=AppRoleAssignedToParams,
        select_allowlist=frozenset(_ASSIGNED_TO_SELECT), paginated=True,
        response_properties=frozenset(_ASSIGNED_TO_SELECT),
    ),
    OperationSpec(
        name="users.get_identity", kind="read", executable=True, method="GET",
        path_template="/users/{user_id}", params_model=UserIdParams,
        fixed_query=(("$select", IDENTITY_SELECT),), single=True, internal_only=True,
        response_properties=frozenset({"id", "displayName", "userPrincipalName", "accountEnabled", "@odata.type"}),
    ),
    OperationSpec(
        name="users.update", kind="write", executable=False, method="PATCH",
        path_template="/users/{user_id}", params_model=UserIdParams,
    ),
    OperationSpec(
        name="users.delete", kind="write", executable=False, method="DELETE",
        path_template="/users/{user_id}", params_model=UserIdParams,
    ),
    OperationSpec(
        name="directory_roles.add_member", kind="write", executable=False, method="POST",
        path_template="/directoryRoles/{role_id}/members/$ref", params_model=RoleIdParams,
    ),
)

# Query parameters a params model may declare, and the Graph name each becomes.
_QUERY_FIELDS = {"select": "$select", "top": "$top"}
# Query parameters a registry entry may fix itself (SD-053).
_FIXED_QUERY_NAMES = frozenset({"$expand", "$select"})


def _placeholders(template: str) -> list[str]:
    return [name for _, name, _, _ in string.Formatter().parse(template) if name is not None]


def _select_choices(model: type[BaseModel]) -> frozenset[str]:
    (item,) = get_args(model.model_fields["select"].annotation)
    return frozenset(get_args(item))


def _check_spec(spec: OperationSpec) -> None:
    """Registry invariants, checked at import: a bad entry stops the broker."""
    template = spec.path_template
    lowered = template.lower()
    config = spec.params_model.model_config
    fields = set(spec.params_model.model_fields)
    placeholders = _placeholders(template)
    problems = [
        not valid_path_template(template),
        "/beta" in lowered or "$batch" in lowered or "v1.0" in lowered,
        config.get("extra") != "forbid" or config.get("strict") is not True,
        len(set(placeholders)) != len(placeholders),
        not fields.issuperset(placeholders),
        not (fields - set(placeholders)) <= set(_QUERY_FIELDS),
        spec.kind == "read" and spec.method != "GET",
        spec.kind == "write" and spec.executable,  # Phase 1: read-only
        spec.paginated and spec.kind != "read",
        bool(spec.select_allowlist) != ("select" in fields),
        "select" in fields and _select_choices(spec.params_model) != spec.select_allowlist,
        # A fixed parameter is $expand or $select, with a plain value, set once, and never one a caller sets.
        any(name not in _FIXED_QUERY_NAMES or not re.fullmatch(r"[A-Za-z0-9,]+", value)
            for name, value in spec.fixed_query),
        any(name in {_QUERY_FIELDS[f] for f in fields if f in _QUERY_FIELDS} for name, _ in spec.fixed_query),
        spec.single and (spec.paginated or spec.kind != "read"),
        spec.internal_only and spec.kind != "read",
        len({n for n, _ in spec.fixed_query}) != len(spec.fixed_query),
        bool(spec.nested_properties) and (spec.response_properties is None
                                          or not set(spec.nested_properties) <= spec.response_properties),
    ]
    if any(problems):
        raise RuntimeError(f"invalid operation spec: {spec.name}")


def _registry() -> Mapping[str, OperationSpec]:
    specs: dict[str, OperationSpec] = {}
    for spec in _SPECS:
        _check_spec(spec)
        if spec.name in specs:
            raise RuntimeError(f"duplicate operation: {spec.name}")
        specs[spec.name] = spec
    return MappingProxyType(specs)


REGISTRY: Mapping[str, OperationSpec] = _registry()


def get(name: str) -> OperationSpec:
    spec = REGISTRY.get(name) if isinstance(name, str) else None
    if spec is None:
        raise UnknownOperation("unknown operation")
    return spec


def _render_path(template: str, values: Mapping[str, object]) -> str:
    """Fill the template. Every placeholder takes a GUID, checked here again,
    independently of the params model."""
    names = _placeholders(template)
    if set(values) != set(names):
        raise InvalidParams("path parameters do not match the template")
    rendered = {}
    for name in names:
        value = values[name]
        if not (isinstance(value, str) and _GUID.match(value)):
            raise InvalidParams(f"{name} must be a GUID")
        rendered[name] = value.lower()
    return template.format_map(rendered) if names else template


def build_request(spec: OperationSpec, params: Mapping[str, object]) -> BuiltRequest:
    """The one place a Graph request is shaped. Raises UnknownOperation for a
    spec that is not the registered object, NotExecutable for writes,
    ValidationError for parameters the schema refuses and InvalidParams for
    anything else that cannot be built safely."""
    if not isinstance(spec, OperationSpec) or REGISTRY.get(spec.name) is not spec:
        raise UnknownOperation("unknown operation")
    if not spec.executable:
        raise NotExecutable(spec.name)
    if not isinstance(params, Mapping):
        raise InvalidParams("params must be a mapping")
    model = spec.params_model.model_validate(dict(params))
    values = model.model_dump()

    placeholders = set(_placeholders(spec.path_template))
    path = _render_path(spec.path_template, {k: v for k, v in values.items() if k in placeholders})

    query: list[tuple[str, str]] = []
    select = values.get("select")
    if select is not None:
        if not set(select) <= spec.select_allowlist:
            raise InvalidParams("$select outside the allowlist")
        query.append(("$select", ",".join(sorted(select))))
    top = values.get("top")
    if top is not None:
        query.append(("$top", str(top)))
    query.extend(spec.fixed_query)

    # Post-check against the audit chain's own rule for request targets, so a
    # template or renderer bug cannot produce a target the approval would not
    # cover. Values are [A-Za-z0-9,] only, so no encoding is involved.
    target = GRAPH_VERSION_PREFIX + path + ("?" + "&".join(f"{k}={v}" for k, v in query) if query else "")
    if (
        not target_matches_template(target, spec.path_template)
        or any(bad in path for bad in ("..", "//", "%", "\\"))
        or not all(re.fullmatch(r"[A-Za-z0-9,]+", v) for _, v in query)
    ):
        raise InvalidParams("built request failed the safety check")
    return BuiltRequest(method=spec.method, path_template=spec.path_template, path=path, query=tuple(query))


def _keep(value: object, properties: frozenset[str]) -> object:
    if isinstance(value, Mapping):
        return {k: v for k, v in value.items() if k in properties}
    if isinstance(value, list):
        return [_keep(v, properties) for v in value if isinstance(v, Mapping)]
    return None


def filter_items(spec: OperationSpec, items: list) -> list:
    """The items as the caller may see them (SD-053): only the operation's
    response_properties, and inside each nested object only its own. An
    operation that declares none returns its items unchanged ($select bounds them)."""
    if spec.response_properties is None:
        return items
    kept = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        out = {k: v for k, v in item.items() if k in spec.response_properties}
        for key, properties in spec.nested_properties.items():
            if key in out:
                out[key] = _keep(out[key], properties)
        kept.append(out)
    return kept
