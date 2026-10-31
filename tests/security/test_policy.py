"""Two-stage, deny-by-default policy (Task 9, SD-003; threat model T10-T13).

Stage 1 authorizes the operation NAME against the manifest and builds the
request from the registry; stage 2 checks the BUILT request (method, path
and query) against rules taken from the registry at import, for the
operations the manifest allows. `evaluate` runs both, turns any exception
or malformed engine result into `policy_error`, and allows only when both
stages allow and the request belongs to the named operation.

Every check here is made at decision time, so it holds for a TaskManifest
that never went through the loader (built with dataclasses.replace)."""

from __future__ import annotations

import dataclasses
import itertools
import uuid
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from clw.broker import operations, policy
from clw.broker.manifest import load_manifest
from clw.broker.operations import BuiltRequest, OperationSpec, UserIdParams, build_request
from clw.broker.policy import ALLOWED, AllowlistPolicyEngine, Decision, evaluate

REPO = Path(__file__).resolve().parents[2]
MANIFEST = load_manifest(REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml")
LIST = "users.list_with_sign_in_activity"
WRITES = ("users.update", "users.delete", "directory_roles.add_member")
GUID = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
SELECT = ["id", "signInActivity"]
SENTINEL = "SENTINEL-4c1e88"
ENGINE = AllowlistPolicyEngine()


def _list_request(**changes) -> BuiltRequest:
    built = build_request(operations.get(LIST), {"select": list(SELECT), "top": 50})
    return dataclasses.replace(built, **changes)


_DEFAULT = object()


def _eval(op=LIST, params=_DEFAULT, manifest=MANIFEST, engine=ENGINE):
    return evaluate(engine, manifest, op, {"select": list(SELECT)} if params is _DEFAULT else params)


# --- Decision -----------------------------------------------------------------


def test_decision_reason_and_allowed_must_agree():
    assert Decision(True, "allowed").allowed
    assert not Decision(False, "prohibited").allowed
    with pytest.raises(ValueError):
        Decision(True, "prohibited")
    with pytest.raises(ValueError):
        Decision(False, "allowed")


@pytest.mark.parametrize("reason", ["", "ALLOWED", "denied", "run_halted", None])
def test_decision_reason_must_be_known(reason):
    with pytest.raises(ValueError):
        Decision(False, reason)


@pytest.mark.parametrize("allowed", [1, 0, "yes", None])
def test_decision_allowed_must_be_a_bool(allowed):
    with pytest.raises(ValueError):
        Decision(allowed, "allowed" if allowed else "prohibited")


def test_decision_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        Decision(False, "prohibited").allowed = True  # type: ignore[misc]


# --- Plan acceptance ----------------------------------------------------------


def test_valid_list_op_allowed():
    decision, built = _eval()
    assert decision == Decision(True, "allowed")
    assert built == build_request(operations.get(LIST), {"select": list(SELECT)})


def test_users_update_in_dormant_manifest_is_prohibited():
    # It is in `prohibited` and not in `allowed`; prohibited is checked first.
    assert _eval("users.update", {"user_id": GUID}) == (Decision(False, "prohibited"), None)


def test_unregistered_operation_is_unknown():
    assert _eval("graph.raw", {}) == (Decision(False, "unknown_operation"), None)


def test_stage1_exception_is_policy_error():
    class Broken(AllowlistPolicyEngine):
        def authorize_operation(self, manifest, op_name, params):
            raise RuntimeError(SENTINEL)

    decision, built = _eval(engine=Broken())
    assert decision == Decision(False, "policy_error") and built is None


def test_template_bug_is_request_pattern_mismatch(monkeypatch):
    # A broker bug: building the list op produces /users/<id>/memberOf.
    real = operations.build_request

    def buggy(spec, params):
        return dataclasses.replace(real(spec, params), path=f"/users/{GUID}/memberOf")

    monkeypatch.setattr(operations, "build_request", buggy)
    assert _eval() == (Decision(False, "request_pattern_mismatch"), None)


def test_registry_entry_swapped_at_runtime_is_request_pattern_mismatch(monkeypatch):
    # Stage 2 rules are taken from the registry at import, so a spec replaced
    # later (here one that builds /users/{user_id}/memberOf under the list
    # op's name) passes build_request's own checks but not stage 2.
    bad = OperationSpec(
        name=LIST, kind="read", executable=True, method="GET",
        path_template="/users/{user_id}/memberOf", params_model=UserIdParams,
    )
    monkeypatch.setattr(operations, "REGISTRY", MappingProxyType({**operations.REGISTRY, LIST: bad}))
    assert _eval(params={"user_id": GUID}) == (Decision(False, "request_pattern_mismatch"), None)


# --- Stage 1: order and reasons -------------------------------------------------


def _manifest(**changes):
    return dataclasses.replace(MANIFEST, **changes)


def test_registered_op_neither_allowed_nor_prohibited_is_not_in_manifest():
    manifest = _manifest(prohibited=())
    for name in WRITES:
        assert _eval(name, {"user_id": GUID}, manifest)[0].reason == "not_in_manifest"


def test_empty_allowed_denies_everything():
    assert _eval(manifest=_manifest(allowed=()))[0].reason == "not_in_manifest"


def test_prohibited_wins_over_allowed():
    # The loader refuses this overlap; the policy does not rely on that.
    manifest = _manifest(prohibited=(LIST,))
    assert _eval(manifest=manifest) == (Decision(False, "prohibited"), None)


@pytest.mark.parametrize("name", WRITES)
def test_write_allowed_by_a_manifest_is_not_executable(name):
    # The loader refuses writes in `allowed`; the policy does not rely on that.
    manifest = _manifest(allowed=(LIST, name), prohibited=())
    params = {"role_id": GUID} if name.startswith("directory_roles") else {"user_id": GUID}
    assert _eval(name, params, manifest) == (Decision(False, "not_executable"), None)


def test_non_executable_read_is_not_executable(monkeypatch):
    spec = dataclasses.replace(operations.get(LIST), executable=False)
    monkeypatch.setattr(operations, "REGISTRY", MappingProxyType({**operations.REGISTRY, LIST: spec}))
    assert _eval()[0].reason == "not_executable"


def _permissive_builder(spec, params):
    return BuiltRequest(method=spec.method, path_template=spec.path_template, path="/users", query=())


@pytest.mark.parametrize("executable_write", [False, True])
def test_not_executable_does_not_rely_on_the_builder(monkeypatch, executable_write):
    # A builder that no longer refuses, and a registry with either a
    # non-executable read or (impossible at import) an executable write.
    monkeypatch.setattr(operations, "build_request", _permissive_builder)
    if executable_write:
        name, params = "users.delete", {"user_id": GUID}
        spec = dataclasses.replace(operations.get(name), executable=True)
    else:
        name, params = LIST, {"select": list(SELECT)}
        spec = dataclasses.replace(operations.get(LIST), executable=False)
    monkeypatch.setattr(operations, "REGISTRY", MappingProxyType({**operations.REGISTRY, name: spec}))
    manifest = _manifest(allowed=(LIST, name) if name != LIST else (LIST,), prohibited=())
    assert _eval(name, params, manifest) == (Decision(False, "not_executable"), None)


def test_unregistered_name_in_allowed_is_still_unknown():
    manifest = _manifest(allowed=(LIST, "graph.raw"))
    assert _eval("graph.raw", {}, manifest)[0].reason == "unknown_operation"


def test_unknown_is_checked_before_prohibited():
    manifest = _manifest(prohibited=(*MANIFEST.prohibited, "graph.raw"))
    assert _eval("graph.raw", {}, manifest)[0].reason == "unknown_operation"


def test_not_in_manifest_is_checked_before_invalid_params():
    manifest = _manifest(prohibited=())
    assert _eval("users.update", {"user_id": "../x"}, manifest)[0].reason == "not_in_manifest"


def test_prohibited_is_checked_before_invalid_params():
    assert _eval("users.update", {"path": "/users"})[0].reason == "prohibited"


@pytest.mark.parametrize("name", [
    "Users.List_With_Sign_In_Activity", "users.list_with_sign_in_activity ", " users.list_with_sign_in_activity",
    "users.list_with_sign_in_activity\n", "GET /users", "/users", "/v1.0/users",
    "https://graph.microsoft.com/v1.0/users", "users.*", "*", "", "users.list", "$batch",
])
def test_lookalike_names_are_unknown(name):
    assert _eval(name)[0].reason == "unknown_operation"


@pytest.mark.parametrize("name", [None, 1, b"users.list_with_sign_in_activity", ("users.list_with_sign_in_activity",)])
def test_non_string_names_are_unknown(name):
    assert _eval(name)[0].reason == "unknown_operation"


def test_str_subclass_names_are_unknown():
    class Name(str):
        pass

    assert _eval(Name(LIST))[0].reason == "unknown_operation"


# --- Stage 1: unsafe parameters ---------------------------------------------------


@pytest.mark.parametrize("key", [
    "path", "url", "uri", "method", "headers", "host", "path_template", "query",
    "$select", "$top", "$expand", "$filter", "$skiptoken", "nextLink", "@odata.nextLink", "tenant_id", "user_id",
])
def test_request_shaping_params_are_invalid(key):
    assert _eval(params={"select": list(SELECT), key: "x"}) == (Decision(False, "invalid_params"), None)


@pytest.mark.parametrize("select", [
    [], ["id", "id"], ["*"], ["id,signInActivity"], ["mail"], ["memberOf"], ["../users"], ["id%2C"],
    "id", ["ID"], [None], [1],
])
def test_bad_select_is_invalid(select):
    assert _eval(params={"select": select})[0].reason == "invalid_params"


@pytest.mark.parametrize("top", [0, 1000, -1, "5", 5.0, True, "1;$expand=manager"])
def test_bad_top_is_invalid(top):
    assert _eval(params={"select": list(SELECT), "top": top})[0].reason == "invalid_params"


@pytest.mark.parametrize("params", [None, [], "select=id", ("select", "id"), 1])
def test_non_mapping_params_are_invalid(params):
    assert _eval(params=params)[0].reason == "invalid_params"


def test_missing_select_is_invalid():
    assert _eval(params={})[0].reason == "invalid_params"


@pytest.mark.parametrize("bad", [
    "../x", f"{GUID}/memberOf", f"{GUID}%2F..", f"{GUID}?$expand=x", f" {GUID}", f"{GUID}\n", GUID.replace("-", ""),
])
def test_path_param_ops_stop_at_not_executable_whatever_the_ids(bad):
    # Every path-param operation is a write, so even a manifest the loader
    # would refuse never gets its ids templated: not_executable comes first.
    manifest = _manifest(allowed=(LIST, "users.delete"), prohibited=())
    assert _eval("users.delete", {"user_id": bad}, manifest)[0].reason == "not_executable"


def test_params_mapping_that_raises_is_policy_error():
    class Hostile(dict):
        def keys(self):
            raise RuntimeError(SENTINEL)

        def __iter__(self):
            raise RuntimeError(SENTINEL)

    assert _eval(params=Hostile(select=SELECT)) == (Decision(False, "policy_error"), None)


def test_every_valid_parameter_set_is_allowed_and_built_by_the_registry():
    allowlist = sorted(operations.get(LIST).select_allowlist)
    count = 0
    for size in range(1, len(allowlist) + 1):
        for select in itertools.combinations(allowlist, size):
            for top in (None, 1, 500):
                params = {"select": list(reversed(select))} | ({} if top is None else {"top": top})
                decision, built = _eval(params=params)
                assert decision.allowed, params
                assert built == build_request(operations.get(LIST), params)
                count += 1
    assert count == 127 * 3


# --- Stage 2: the built request -----------------------------------------------------


def test_stage2_allows_the_registry_built_request():
    assert ENGINE.authorize_request(MANIFEST, _list_request()) == Decision(True, "allowed")


@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE", "get", "HEAD", "GET "])
def test_stage2_method_must_match(method):
    assert ENGINE.authorize_request(MANIFEST, _list_request(method=method)).reason == "request_pattern_mismatch"


@pytest.mark.parametrize("path", [
    "/Users", "/users/", "/users?x=1", "/users#x", "/users/../users", "//users", "/beta/users", "/v1.0/users",
    f"/users/{GUID}", f"/users/{GUID}/memberOf", "/users/delta", "/users/$count", "users", "", "/users\n",
    "/users%2F", "/groups",
])
def test_stage2_path_must_match(path):
    assert ENGINE.authorize_request(MANIFEST, _list_request(path=path)).reason == "request_pattern_mismatch"


@pytest.mark.parametrize("template", ["/users/{user_id}", "/Users", "/users/", "/groups"])
def test_stage2_declared_template_must_match(template):
    request = _list_request(path_template=template)
    assert ENGINE.authorize_request(MANIFEST, request).reason == "request_pattern_mismatch"


@pytest.mark.parametrize("query", [
    (),                                                       # $select is required
    (("$top", "50"),),
    (("$select", "signInActivity,id"),),                       # not normalized (sorted)
    (("$select", "id,id"),),
    (("$select", "id,mail"),),
    (("$select", "id,"),),
    (("$select", ""),),
    (("$select", "*"),),
    (("$select", "id"), ("$select", "id")),
    (("$top", "50"), ("$select", "id")),                       # not normalized (order)
    (("$select", "id"), ("$top", "0")),
    (("$select", "id"), ("$top", "1000")),
    (("$select", "id"), ("$top", "050")),
    (("$select", "id"), ("$top", "+5")),
    (("$select", "id"), ("$top", "5 ")),
    (("$select", "id"), ("$top", "")),
    (("$select", "id"), ("$top", "50"), ("$top", "50")),
    (("$select", "id"), ("$expand", "manager")),
    (("$select", "id"), ("$filter", "x")),
    (("$select", "id"), ("$skiptoken", "x")),
    (("$select", "id"), ("$count", "true")),
    (("select", "id"),),
    (("$SELECT", "id"),),
    (("$select", "id", "x"),),
    (("$select",),),
    (("$select", ["id"]),),
    (("$select", None),),
    ["$select", "id"],
    [("$select", "id")],
    "$select=id",
    None,
])
def test_stage2_query_must_be_the_normalized_permitted_form(query):
    request = _list_request(query=query)
    assert ENGINE.authorize_request(MANIFEST, request).reason == "request_pattern_mismatch"


@pytest.mark.parametrize("query", [
    (("$select", "id"),),
    (("$select", "id"), ("$top", "1")),
    (("$select", "id"), ("$top", "500")),
    (("$select", "accountEnabled,createdDateTime,displayName,id,signInActivity,userPrincipalName,userType"),),
])
def test_stage2_accepts_normalized_queries(query):
    assert ENGINE.authorize_request(MANIFEST, _list_request(query=query)).allowed


def test_stage2_refuses_a_lookalike_request_type():
    @dataclasses.dataclass(frozen=True)
    class Lookalike:
        method: str
        path_template: str
        path: str
        query: tuple

    built = _list_request()
    fake = Lookalike(built.method, built.path_template, built.path, built.query)
    assert ENGINE.authorize_request(MANIFEST, fake).reason == "request_pattern_mismatch"


@pytest.mark.parametrize("field", ["method", "path_template", "path"])
def test_stage2_refuses_non_string_fields(field):
    request = _list_request(**{field: None})
    assert ENGINE.authorize_request(MANIFEST, request).reason == "request_pattern_mismatch"


def test_stage2_ignores_operations_the_manifest_does_not_allow():
    assert ENGINE.authorize_request(_manifest(allowed=()), _list_request()).reason == "request_pattern_mismatch"


def test_stage2_ignores_prohibited_operations():
    manifest = _manifest(prohibited=(LIST,))
    assert ENGINE.authorize_request(manifest, _list_request()).reason == "request_pattern_mismatch"


@pytest.mark.parametrize("method,template,name", [
    ("PATCH", "/users/{user_id}", "users.update"),
    ("DELETE", "/users/{user_id}", "users.delete"),
])
def test_stage2_has_no_rules_for_writes(method, template, name):
    manifest = _manifest(allowed=(LIST, name), prohibited=())
    request = BuiltRequest(method=method, path_template=template, path=f"/users/{GUID}", query=())
    assert ENGINE.authorize_request(manifest, request).reason == "request_pattern_mismatch"


def test_stage2_rules_are_fixed_at_import():
    # Every executable read, and only those (SD-053 adds the agent tools' four).
    assert set(policy.RULES) == {LIST, "directory.list_role_definitions", "directory.list_role_assignments",
                                 "service_principals.list", "service_principals.list_app_role_assigned_to",
                                 "users.get_identity"}
    rule = policy.RULES[LIST]
    assert (rule.method, rule.path_template) == ("GET", "/users")
    assert {(r.method, r.path_template) for r in policy.RULES.values()} == {
        ("GET", "/users"), ("GET", "/roleManagement/directory/roleDefinitions"),
        ("GET", "/roleManagement/directory/roleAssignments"), ("GET", "/servicePrincipals"),
        ("GET", "/servicePrincipals/{sp_id}/appRoleAssignedTo"), ("GET", "/users/{user_id}")}
    with pytest.raises(TypeError):
        policy.RULES["x"] = rule  # type: ignore[index]


def test_rule_literals_are_escaped():
    rule = policy._rule_for(OperationSpec(
        name="t", kind="read", executable=True, method="GET",
        path_template="/directoryRoles/{role_id}/members/$ref", params_model=operations.RoleIdParams,
    ))
    assert rule.path.fullmatch(f"/directoryRoles/{GUID}/members/$ref")
    assert not rule.path.fullmatch(f"/directoryRoles/{GUID}/members/")
    dotted = policy._rule_for(OperationSpec(
        name="t", kind="read", executable=True, method="GET", path_template="/a.b", params_model=operations.ListUsersParams,
    ))
    assert dotted.path.fullmatch("/a.b") and not dotted.path.fullmatch("/axb")


def test_a_params_field_without_a_query_rule_stops_the_import():
    class Expand(operations.ListUsersParams):
        expand: str | None = None

    spec = OperationSpec(
        name="t", kind="read", executable=True, method="GET", path_template="/users", params_model=Expand,
        select_allowlist=operations.get(LIST).select_allowlist,
    )
    with pytest.raises(RuntimeError):
        policy._rule_for(spec)


def test_placeholder_rules_take_lowercase_guids_only():
    rule = policy._rule_for(OperationSpec(
        name="t", kind="read", executable=True, method="GET",
        path_template="/users/{user_id}/x", params_model=UserIdParams,
    ))
    assert rule.path.fullmatch(f"/users/{GUID}/x")
    for bad in (f"/users/{GUID.upper()}/x", "/users/x/x", f"/users/{GUID}/X", f"/users/{GUID}/x/", f"/users/{GUID}"):
        assert not rule.path.fullmatch(bad), bad


# --- evaluate: engine results it does not trust ---------------------------------------


def _exact():
    """What the registry builds from _eval's default params."""
    return build_request(operations.get(LIST), {"select": list(SELECT)})


class Scripted(AllowlistPolicyEngine):
    """An engine that returns fixed results, to test evaluate's own checks."""

    def __init__(self, stage1=None, stage2=None):
        self.stage1, self.stage2, self.stage2_calls = stage1, stage2, 0

    def authorize_operation(self, manifest, op_name, params):
        return super().authorize_operation(manifest, op_name, params) if self.stage1 is None else self.stage1

    def authorize_request(self, manifest, request):
        self.stage2_calls += 1
        return super().authorize_request(manifest, request) if self.stage2 is None else self.stage2


def test_stage2_exception_is_policy_error():
    class Broken(AllowlistPolicyEngine):
        def authorize_request(self, manifest, request):
            raise RuntimeError(SENTINEL)

    assert _eval(engine=Broken()) == (Decision(False, "policy_error"), None)


@pytest.mark.parametrize("stage1", [
    object(),                                        # not a tuple
    (True, None),
    ((True, "allowed"), None),
    (Decision(True, "allowed"),),
    (Decision(True, "allowed"), None),               # allowed with no request
    (Decision(True, "allowed"), {"method": "GET"}),
    (Decision(True, "allowed"), _list_request(), "extra"),
    (SimpleNamespace(allowed=True, reason="allowed"), _list_request(query=(("$select", "id,signInActivity"),))),
    "allowed",
    True,
])
def test_malformed_stage1_result_is_policy_error(stage1):
    assert _eval(engine=Scripted(stage1=stage1)) == (Decision(False, "policy_error"), None)


@pytest.mark.parametrize("stage2", [True, "allowed", (True, "allowed"), None, SimpleNamespace(allowed=True, reason="allowed")])
def test_malformed_stage2_result_is_policy_error(stage2):
    engine = Scripted(stage2=stage2)
    if stage2 is None:
        engine.authorize_request = lambda manifest, request: None  # type: ignore[method-assign]
    assert _eval(engine=engine) == (Decision(False, "policy_error"), None)


def test_stage1_denial_returns_no_request_and_skips_stage2():
    engine = Scripted(stage1=(Decision(False, "prohibited"), _list_request()))
    assert _eval(engine=engine) == (Decision(False, "prohibited"), None)
    assert engine.stage2_calls == 0


def test_stage2_denial_is_returned_without_the_request():
    engine = Scripted(stage2=Decision(False, "request_pattern_mismatch"))
    assert _eval(engine=engine) == (Decision(False, "request_pattern_mismatch"), None)


def test_evaluate_returns_the_request_stage2_checked():
    seen = []

    class Recording(AllowlistPolicyEngine):
        def authorize_request(self, manifest, request):
            seen.append(request)
            return super().authorize_request(manifest, request)

    decision, built = _eval(engine=Recording())
    assert decision.allowed and seen == [built] and seen[0] is built


def test_permissive_engine_cannot_allow_an_op_outside_the_manifest():
    # A replacement engine (SD-003: e.g. OPA) that allows everything still
    # cannot allow an operation the manifest does not allow.
    permissive = Scripted(stage1=(Decision(True, "allowed"), _exact()), stage2=Decision(True, "allowed"))
    for manifest in (_manifest(allowed=()), _manifest(prohibited=(LIST,))):
        assert _eval(manifest=manifest, engine=permissive) == (Decision(False, "policy_error"), None)


def test_permissive_engine_cannot_allow_an_unknown_op():
    permissive = Scripted(stage1=(Decision(True, "allowed"), _exact()), stage2=Decision(True, "allowed"))
    manifest = _manifest(allowed=(LIST, "graph.raw"))
    assert _eval("graph.raw", {}, manifest, permissive) == (Decision(False, "policy_error"), None)


@pytest.mark.parametrize("changes", [
    {"method": "DELETE"},
    {"path": f"/users/{GUID}"},
    {"path_template": "/users/{user_id}"},
    {"query": (("$select", "id"), ("$expand", "manager"))},
    {"query": ()},
])
def test_permissive_engine_cannot_alter_the_request(changes):
    permissive = Scripted(stage1=(Decision(True, "allowed"), dataclasses.replace(_exact(), **changes)), stage2=Decision(True, "allowed"))
    assert _eval(engine=permissive) == (Decision(False, "policy_error"), None)


def test_permissive_engine_is_allowed_only_what_the_policy_allows():
    permissive = Scripted(stage1=(Decision(True, "allowed"), _exact()), stage2=Decision(True, "allowed"))
    assert _eval(engine=permissive) == (ALLOWED, _exact())


def test_permissive_engine_with_a_template_bug_is_still_denied(monkeypatch):
    # The registry rebuild shares the bug, so only the rule check catches it.
    real = operations.build_request

    def buggy(spec, params):
        return dataclasses.replace(real(spec, params), path=f"/users/{GUID}/memberOf")

    monkeypatch.setattr(operations, "build_request", buggy)
    bad = buggy(operations.get(LIST), {"select": list(SELECT)})
    permissive = Scripted(stage1=(Decision(True, "allowed"), bad), stage2=Decision(True, "allowed"))
    assert _eval(engine=permissive) == (Decision(False, "policy_error"), None)


def test_permissive_engine_cannot_swap_the_parameters():
    # A different, otherwise permitted, $select from the one requested.
    other = build_request(operations.get(LIST), {"select": ["id", "displayName"]})
    permissive = Scripted(stage1=(Decision(True, "allowed"), other), stage2=Decision(True, "allowed"))
    assert _eval(engine=permissive) == (Decision(False, "policy_error"), None)


def test_permissive_engine_cannot_return_a_lookalike_request():
    built = _list_request()
    fake = SimpleNamespace(method=built.method, path_template=built.path_template, path=built.path, query=built.query)
    permissive = Scripted(stage1=(Decision(True, "allowed"), fake), stage2=Decision(True, "allowed"))
    assert _eval(engine=permissive) == (Decision(False, "policy_error"), None)


def test_non_manifest_is_policy_error():
    fake = SimpleNamespace(**{f.name: getattr(MANIFEST, f.name) for f in dataclasses.fields(MANIFEST)})
    for manifest in (fake, None, {"allowed": (LIST,)}):
        assert _eval(manifest=manifest) == (Decision(False, "policy_error"), None)


@pytest.mark.parametrize("changes", [
    {"allowed": LIST},                              # a str: `in` would match substrings
    {"allowed": [LIST]},
    {"prohibited": "users.update"},
    {"allowed": (LIST, None)},
])
def test_manifest_with_malformed_name_lists_is_policy_error(changes):
    assert _eval(manifest=_manifest(**changes)) == (Decision(False, "policy_error"), None)


def test_stage_methods_refuse_a_non_manifest():
    fake = SimpleNamespace(allowed=(LIST,), prohibited=())
    with pytest.raises(TypeError):
        ENGINE.authorize_operation(fake, LIST, {"select": SELECT})
    with pytest.raises(TypeError):
        ENGINE.authorize_request(fake, _list_request())


def test_policy_error_carries_no_detail():
    class Broken(AllowlistPolicyEngine):
        def authorize_operation(self, manifest, op_name, params):
            raise RuntimeError(SENTINEL)

    decision, _ = _eval(engine=Broken())
    assert SENTINEL not in repr(decision) and dataclasses.asdict(decision) == {"allowed": False, "reason": "policy_error"}


def test_evaluate_changes_neither_registry_nor_manifest():
    registry = dict(operations.REGISTRY)
    manifest = dataclasses.replace(MANIFEST)
    for op, params in [(LIST, {"select": SELECT}), ("users.update", {"user_id": GUID}), ("graph.raw", {})]:
        _eval(op, params)
    assert dict(operations.REGISTRY) == registry and MANIFEST == manifest


def test_params_are_not_mutated():
    params = {"select": ["signInActivity", "id"], "top": 5}
    _eval(params=params)
    assert params == {"select": ["signInActivity", "id"], "top": 5}


def test_random_guid_template_values_never_reach_stage2_for_a_list_op():
    # The list op has no path params, so any id-shaped param is refused in stage 1.
    for _ in range(20):
        assert _eval(params={"select": SELECT, "user_id": str(uuid.uuid4())})[0].reason == "invalid_params"
