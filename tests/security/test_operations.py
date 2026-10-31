"""Operation registry and request builder (Task 7, SD-002, SD-018; threat
model T11-T14). No interface accepts a URL, path, method or header: a
caller names a registered operation and passes parameters that the
operation's strict schema validates. The broker builds the request."""

from __future__ import annotations

import dataclasses
import itertools
import random
import re
import uuid
from types import MappingProxyType
from typing import Literal

import pytest
from pydantic import ConfigDict, ValidationError

from clw.audit.events import target_matches_template, valid_path_template
from clw.broker import operations
from clw.broker.operations import (
    BuiltRequest,
    InvalidParams,
    NotExecutable,
    OperationSpec,
    UnknownOperation,
    build_request,
    get,
)

LIST_USERS = "users.list_with_sign_in_activity"
SELECT_ALLOWLIST = (
    "id", "displayName", "userPrincipalName", "accountEnabled", "createdDateTime", "userType", "signInActivity",
)
WRITE_OPS = ("users.update", "users.delete", "directory_roles.add_member")
# The v0.1 agent tools' reads (SD-053).
AGENT_READS = ("directory.list_role_definitions", "directory.list_role_assignments", "service_principals.list",
               "service_principals.list_app_role_assigned_to")
INTERNAL_READS = ("users.get_identity",)  # the broker's own (SD-054)
GUID = "0f8fad5b-d9cb-469f-a165-70867728950e"


def _list(**params):
    return build_request(get(LIST_USERS), {"select": ["id"], **params})


def _audit_target(req: BuiltRequest) -> str:
    query = "&".join(f"{k}={v}" for k, v in req.query)
    return "/v1.0" + req.path + (f"?{query}" if query else "")


# --- registry contents ------------------------------------------------------

def test_the_registry_is_exactly_these_operations():
    assert set(operations.REGISTRY) == {LIST_USERS, *AGENT_READS, *INTERNAL_READS, *WRITE_OPS}


def test_registry_is_read_only():
    assert isinstance(operations.REGISTRY, MappingProxyType)
    with pytest.raises(TypeError):
        operations.REGISTRY["users.list_all"] = get(LIST_USERS)  # type: ignore[index]


def test_specs_are_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        get(LIST_USERS).path_template = "/me"  # type: ignore[misc]


def test_list_users_spec():
    spec = get(LIST_USERS)
    assert (spec.kind, spec.executable, spec.method, spec.path_template, spec.paginated) == (
        "read", True, "GET", "/users", True)
    assert spec.select_allowlist == frozenset(SELECT_ALLOWLIST)


@pytest.mark.parametrize(("name", "method", "template"), [
    ("users.update", "PATCH", "/users/{user_id}"),
    ("users.delete", "DELETE", "/users/{user_id}"),
    ("directory_roles.add_member", "POST", "/directoryRoles/{role_id}/members/$ref"),
])
def test_write_ops_registered_for_display_only(name, method, template):
    spec = get(name)
    assert (spec.kind, spec.executable, spec.method, spec.path_template, spec.paginated) == (
        "write", False, method, template, False)


def test_every_write_op_is_not_executable():
    assert all(not s.executable for s in operations.REGISTRY.values() if s.kind == "write")


def test_every_read_op_is_get():
    assert all(s.method == "GET" for s in operations.REGISTRY.values() if s.kind == "read")


def test_templates_never_use_beta_batch_or_a_version():
    for spec in operations.REGISTRY.values():
        lowered = spec.path_template.lower()
        assert "/beta" not in lowered and "$batch" not in lowered and "v1.0" not in lowered
        assert "?" not in lowered and "%" not in lowered and "\\" not in lowered


def test_templates_pass_the_audit_template_check():
    # The audit chain (Task 2b) only accepts approvals whose template it can
    # check; every registered template must be one of those.
    assert all(valid_path_template(s.path_template) for s in operations.REGISTRY.values())


def test_params_models_are_strict_and_forbid_extra():
    for spec in operations.REGISTRY.values():
        config = spec.params_model.model_config
        assert config.get("extra") == "forbid" and config.get("strict") is True, spec.name


# --- get --------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "users.list", "USERS.LIST_WITH_SIGN_IN_ACTIVITY", " users.list_with_sign_in_activity",
    "users.list_with_sign_in_activity ", "", "/users", "https://graph.microsoft.com/v1.0/users",
])
def test_unknown_names_raise_keyerror(name):
    with pytest.raises(KeyError):
        get(name)
    with pytest.raises(UnknownOperation):
        get(name)


@pytest.mark.parametrize("name", [None, 1, b"users.delete", ("users.delete",)])
def test_non_string_names_are_unknown(name):
    with pytest.raises(UnknownOperation):
        get(name)  # type: ignore[arg-type]


def test_build_refuses_a_spec_not_in_the_registry():
    forged = dataclasses.replace(get(LIST_USERS), path_template="/users/{user_id}/memberOf")
    with pytest.raises(UnknownOperation):
        build_request(forged, {"select": ["id"]})
    lookalike = dataclasses.replace(get(LIST_USERS))  # equal, but not the registered object
    with pytest.raises(UnknownOperation):
        build_request(lookalike, {"select": ["id"]})


# --- write operations are never built ---------------------------------------

@pytest.mark.parametrize("name", WRITE_OPS)
@pytest.mark.parametrize("params", [{"user_id": GUID}, {"role_id": GUID}, {}, {"url": "/users"}])
def test_build_request_for_write_op_raises_not_executable(name, params):
    with pytest.raises(NotExecutable):
        build_request(get(name), params)


# --- list users: the request ------------------------------------------------

def test_list_users_builds_fixed_get_users():
    req = _list()
    assert req == BuiltRequest(method="GET", path_template="/users", path="/users", query=(("$select", "id"),))


def test_select_is_emitted_sorted_whatever_the_input_order():
    a = build_request(get(LIST_USERS), {"select": ["signInActivity", "id", "displayName"]})
    b = build_request(get(LIST_USERS), {"select": ["displayName", "signInActivity", "id"]})
    assert a == b
    assert a.query == (("$select", "displayName,id,signInActivity"),)


def test_full_allowlist_and_top():
    # A-04: 500 is the documented maximum $top when $select includes signInActivity.
    req = build_request(get(LIST_USERS), {"select": list(reversed(SELECT_ALLOWLIST)), "top": 500})
    assert req.query == (("$select", ",".join(sorted(SELECT_ALLOWLIST))), ("$top", "500"))


@pytest.mark.parametrize("top", [1, 100, 500])
def test_top_in_bounds(top):
    assert _list(top=top).query[-1] == ("$top", str(top))


# --- list users: T14 parameter abuse ----------------------------------------

def test_select_outside_allowlist_rejected():
    with pytest.raises(ValidationError):
        _list(select=["id", "manager"])


@pytest.mark.parametrize("select", [
    ["ID"], ["id "], ["signinactivity"], ["id,manager"], ["*"], ["id", "id"], [], "id", ("id",), [1], None,
    ["signInActivity/lastSignInDateTime"], ["$expand=memberOf"],
])
def test_bad_select_rejected(select):
    with pytest.raises(ValidationError):
        build_request(get(LIST_USERS), {"select": select})


def test_select_is_required():
    # Without $select Graph returns its default property set, which is not the allowlist.
    with pytest.raises(ValidationError):
        build_request(get(LIST_USERS), {})


def test_expand_rejected():
    with pytest.raises(ValidationError):
        _list(expand="memberOf")


@pytest.mark.parametrize("key", [
    "$expand", "$filter", "filter", "$search", "$orderby", "$count", "$skip", "$skiptoken", "skiptoken",
    "nextLink", "@odata.nextLink", "$select", "$top", "path", "url", "method", "headers", "body", "api_version",
    "user_id", "Select", "TOP",
])
def test_unlisted_parameters_rejected(key):
    with pytest.raises(ValidationError):
        _list(**{key: "x"})


def test_explicit_null_top_is_the_same_as_absent():
    assert _list(top=None) == _list()


@pytest.mark.parametrize("top", [0, -1, 501, 1000, 10**9, True, False, 5.0, "5", [5], {"value": 5}])
def test_top_out_of_bounds_or_wrong_type_rejected(top):
    with pytest.raises(ValidationError):
        _list(top=top)


@pytest.mark.parametrize("params", [None, [("select", ["id"])], "select=id", 42])
def test_params_must_be_a_mapping(params):
    with pytest.raises(InvalidParams):
        build_request(get(LIST_USERS), params)  # type: ignore[arg-type]


def test_non_string_keys_rejected():
    with pytest.raises(ValidationError):
        build_request(get(LIST_USERS), {"select": ["id"], 1: "x"})  # type: ignore[dict-item]


# --- path parameters (T13) --------------------------------------------------

BAD_IDS = [
    "../me", "%2E%2E", "a/b", "me", "alice@contoso.onmicrosoft.com", "..", ".", "",
    GUID + "/memberOf", GUID + "%2F", GUID + "?$expand=manager", GUID + "#x", " " + GUID, GUID + "\n",
    GUID.replace("-", ""), "{" + GUID + "}", GUID + GUID, "delta", "microsoft.graph.user",
    "0f8fad5b-d9cb-469f-a165-70867728950g", "0f8fad5b\\d9cb-469f-a165-70867728950e", "０" + GUID[1:],
]


@pytest.mark.parametrize("name", ["users.update", "users.delete"])
@pytest.mark.parametrize("bad", BAD_IDS)
def test_user_id_must_be_a_guid(name, bad):
    with pytest.raises(ValidationError):
        get(name).params_model.model_validate({"user_id": bad})


@pytest.mark.parametrize("bad", BAD_IDS)
def test_role_id_must_be_a_guid(bad):
    with pytest.raises(ValidationError):
        get("directory_roles.add_member").params_model.model_validate({"role_id": bad})


@pytest.mark.parametrize("bad", [GUID.encode(), uuid.UUID(GUID), 1, None])
def test_path_params_must_be_strings(bad):
    with pytest.raises(ValidationError):
        get("users.delete").params_model.model_validate({"user_id": bad})


@pytest.mark.parametrize("bad", BAD_IDS)
def test_renderer_rechecks_guid_before_templating(bad):
    # Second check, independent of the params model.
    with pytest.raises(InvalidParams):
        operations._render_path("/users/{user_id}", {"user_id": bad})


def test_renderer_requires_exactly_the_placeholders():
    with pytest.raises(InvalidParams):
        operations._render_path("/users/{user_id}", {})
    with pytest.raises(InvalidParams):
        operations._render_path("/users/{user_id}", {"user_id": GUID, "role_id": GUID})
    with pytest.raises(InvalidParams):
        operations._render_path("/users", {"user_id": GUID})


def test_renderer_lowercases_guids():
    assert operations._render_path("/users/{user_id}", {"user_id": GUID.upper()}) == f"/users/{GUID}"
    assert operations._render_path(
        "/directoryRoles/{role_id}/members/$ref", {"role_id": GUID}) == f"/directoryRoles/{GUID}/members/$ref"


# --- every built request is safe and audit-compatible -----------------------

def _max_top(spec: OperationSpec) -> int | None:
    field = spec.params_model.model_fields.get("top")
    if field is None:
        return None
    return next(m.le for m in field.metadata if getattr(m, "le", None) is not None)


def _valid_param_sets(spec: OperationSpec, rng: random.Random):
    """Valid parameters for read operations: a GUID for each path placeholder;
    every non-empty $select subset, each with $top absent, at both bounds and
    at random values (when the operation has $top). One set for an operation
    without either."""
    path = {name: GUID for name in operations._placeholders(spec.path_template)}
    allow = sorted(spec.select_allowlist)
    top_max = _max_top(spec)
    if not allow:
        yield path
        return
    for size in range(1, len(allow) + 1):
        for subset in itertools.combinations(allow, size):
            fields = list(subset)
            rng.shuffle(fields)
            tops = (None,) if top_max is None else (None, 1, top_max, rng.randint(1, top_max))
            for top in tops:
                yield path | ({"select": fields} if top is None else {"select": fields, "top": top})


def _expected_sets(spec: OperationSpec) -> int:
    if not spec.select_allowlist:
        return 1
    return (2 ** len(spec.select_allowlist) - 1) * (1 if _max_top(spec) is None else 4)


def test_built_requests_are_always_safe_and_match_their_template():
    rng = random.Random(7)
    count = expected = 0
    for spec in operations.REGISTRY.values():
        if not spec.executable:
            continue
        expected += _expected_sets(spec)
        for params in _valid_param_sets(spec, rng):
            req = build_request(spec, params)
            count += 1
            assert req.method == spec.method and req.path_template == spec.path_template
            assert req.path.startswith("/") and not req.path.startswith("/v1.0")
            for bad in ("..", "//", "%2f", "%5c", "%", "\\", "?", "#", "/beta", "$batch"):
                assert bad not in req.path.lower(), (bad, req.path)
            for key, value in req.query:
                assert key in ("$select", "$top") or (key, value) in spec.fixed_query
                assert re.fullmatch(r"[A-Za-z0-9,]+", value), value
            assert len({k for k, _ in req.query}) == len(req.query)
            assert target_matches_template(_audit_target(req), req.path_template), req
    assert count == expected == 127 * 4 + 1 + 1 + 63 * 4 + 63 + 1


def test_built_request_is_immutable():
    req = _list()
    with pytest.raises(dataclasses.FrozenInstanceError):
        req.path = "/me"  # type: ignore[misc]
    assert isinstance(req.query, tuple) and all(isinstance(p, tuple) for p in req.query)


def test_builder_postcheck_refuses_a_target_the_audit_would_reject(monkeypatch):
    # If a template or renderer bug ever produced an unsafe path, the builder
    # refuses it rather than handing it to the transport.
    monkeypatch.setattr(operations, "_render_path", lambda template, values: "/users/../me")
    with pytest.raises(InvalidParams):
        _list()
    monkeypatch.setattr(operations, "_render_path", lambda template, values: "/groups")
    with pytest.raises(InvalidParams):
        _list()


# --- registry invariants, checked at import ---------------------------------

class _Loose(operations._Params):
    model_config = ConfigDict(extra="ignore", strict=True)
    user_id: operations.Guid


class _Lax(operations._Params):
    model_config = ConfigDict(extra="forbid", strict=False)
    user_id: operations.Guid


class _WithFilter(operations._Params):
    user_id: operations.Guid
    filter: str


class _SelectWider(operations._Params):
    select: list[Literal["id", "manager"]]


@pytest.mark.parametrize("change", [
    # Each change keeps {user_id}, so only the property under test is wrong.
    {"path_template": "/beta/users/{user_id}"},
    {"path_template": "/users/{user_id}/BETA"},
    {"path_template": "/users/{user_id}/$batch"},
    {"path_template": "/$Batch/{user_id}"},
    {"path_template": "/v1.0/users/{user_id}"},
    {"path_template": "/users/{user_id}/v1.0"},
    {"path_template": "/users/{user_id}?$expand=manager"},
    {"path_template": "/users/{user_id}/../me"},
    {"path_template": "/{user_id}"},
    {"path_template": "/users/{user_id}/{user_id}"},
    {"path_template": "/users/{role_id}"},
    {"executable": True},
    {"kind": "read", "method": "DELETE", "executable": True},
    {"paginated": True},
    {"params_model": _Loose},
    {"params_model": _Lax},
    {"params_model": _WithFilter},
    {"select_allowlist": frozenset({"id"})},
])
def test_check_spec_refuses_bad_entries(change):
    bad = dataclasses.replace(get("users.delete"), **change)
    with pytest.raises(RuntimeError):
        operations._check_spec(bad)


def test_check_spec_refuses_a_select_model_wider_than_the_allowlist():
    bad = dataclasses.replace(get(LIST_USERS), params_model=_SelectWider)
    with pytest.raises(RuntimeError):
        operations._check_spec(bad)
    with pytest.raises(RuntimeError):
        operations._check_spec(dataclasses.replace(get(LIST_USERS), select_allowlist=frozenset()))


def test_registered_specs_pass_their_own_check():
    for spec in operations.REGISTRY.values():
        operations._check_spec(spec)
