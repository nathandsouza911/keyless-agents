"""The v0.1 agent tools' read operations (SD-053): fixed query parameters and response filtering.

A caller can never set $expand (or any other parameter the registry fixes);
the registry refuses any fixed parameter but $expand; Graph's continuation
must keep it; and whatever Graph returns, only the declared properties leave
the broker: for an expanded role-assignment principal, exactly id,
displayName, userPrincipalName and @odata.type (owner ruling, 2026-10-30).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from clw.broker import operations
from clw.broker.operations import (
    PRINCIPAL_PROPERTIES, InvalidParams, OperationSpec, build_request, filter_items, get,
)
from clw.broker.pagination import GraphError, request_target, validate_next_link

ASSIGNMENTS = "directory.list_role_assignments"
DEFINITIONS = "directory.list_role_definitions"
SPS = "service_principals.list"
ASSIGNED_TO = "service_principals.list_app_role_assigned_to"
GUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
GRAPH = "https://graph.microsoft.com/v1.0"


# --- what a caller can set -------------------------------------------------------

@pytest.mark.parametrize("op, params", [
    (ASSIGNMENTS, {"expand": "principal"}), (ASSIGNMENTS, {"expand": "*"}), (ASSIGNMENTS, {"select": ["id"]}),
    (ASSIGNMENTS, {"filter": "x"}), (ASSIGNMENTS, {"top": 5}), (DEFINITIONS, {"expand": "inheritsPermissionsFrom"}),
    (SPS, {"select": ["id"], "expand": "owners"}), (SPS, {"select": ["keyCredentials"]}),
    (SPS, {"select": ["passwordCredentials"]}), (SPS, {"select": ["id"], "top": 101}),
    (ASSIGNED_TO, {"sp_id": GUID, "select": ["id"], "filter": "x"}),
    ("users.list_with_sign_in_activity", {"select": ["id"], "expand": "manager"}),
])
def test_a_caller_cannot_add_or_widen_query_parameters(op, params):
    with pytest.raises(ValidationError):
        build_request(get(op), params)


@pytest.mark.parametrize("sp_id", ["..", "x/../../users", "0f8fad5b-d9cb-469f-a165-70867728950e/owners", "me",
                                   "%2e%2e", ""])
def test_the_service_principal_id_must_be_a_guid(sp_id):
    with pytest.raises((ValidationError, InvalidParams)):
        build_request(get(ASSIGNED_TO), {"sp_id": sp_id, "select": ["id"]})


def test_the_registry_fixes_expand_principal_on_role_assignments_only():
    assert request_target(build_request(get(ASSIGNMENTS), {})) == \
        "/v1.0/roleManagement/directory/roleAssignments?$expand=principal"
    fixed = {name: spec.fixed_query for name, spec in operations.REGISTRY.items() if spec.fixed_query}
    assert fixed == {ASSIGNMENTS: (("$expand", "principal"),),
                     "users.get_identity": (("$select", "accountEnabled,displayName,id,userPrincipalName"),)}


@pytest.mark.parametrize("fixed", [(("$filter", "x"),), (("$top", "5"),), (("$expand", "principal($select=*)"),),
                                   (("$expand", "a"), ("$expand", "b")), (("$select", "id,mail;x"),)])
def test_the_registry_refuses_any_other_fixed_parameter(fixed):
    spec = OperationSpec(name="t", kind="read", executable=True, method="GET", path_template="/t",
                         params_model=operations.NoParams, fixed_query=fixed)
    with pytest.raises(RuntimeError):
        operations._check_spec(spec)


def test_nested_filters_need_a_declared_parent():
    spec = OperationSpec(name="t", kind="read", executable=True, method="GET", path_template="/t",
                         params_model=operations.NoParams, nested_properties={"principal": frozenset({"id"})})
    with pytest.raises(RuntimeError):
        operations._check_spec(spec)


# --- Graph's continuation keeps the fixed parameter ------------------------------

def test_a_next_link_keeping_expand_is_followed():
    original = build_request(get(ASSIGNMENTS), {})
    target = validate_next_link(f"{GRAPH}/roleManagement/directory/roleAssignments?$expand=principal&$skiptoken=abc",
                                original=original)
    assert target == "/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$skiptoken=abc"


@pytest.mark.parametrize("query", ["$skiptoken=abc", "$expand=principal,roleDefinition&$skiptoken=abc",
                                   "$expand=*&$skiptoken=abc", "$expand=principal&$select=id&$skiptoken=abc"])
def test_a_next_link_dropping_or_changing_expand_is_refused(query):
    original = build_request(get(ASSIGNMENTS), {})
    with pytest.raises(GraphError):
        validate_next_link(f"{GRAPH}/roleManagement/directory/roleAssignments?{query}", original=original)


# --- what leaves the broker -------------------------------------------------------

FULL_PRINCIPAL = {
    "@odata.type": "#microsoft.graph.user", "id": GUID, "displayName": "Ann", "userPrincipalName": "ann@x.test",
    "mail": "ann@x.test", "otherMails": ["a@b.test"], "mobilePhone": "+1", "accountEnabled": True,
    "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}, "onPremisesSecurityIdentifier": "S-1",
    "passwordProfile": {"password": "x"}, "identities": [{"issuer": "x"}],
}


def test_an_expanded_principal_keeps_only_its_four_properties():
    item = {"id": "a1", "principalId": GUID, "roleDefinitionId": "r1", "directoryScopeId": "/",
            "principal": FULL_PRINCIPAL, "resourceScope": "/", "condition": None, "@odata.etag": "x"}
    (kept,) = filter_items(get(ASSIGNMENTS), [item])
    assert set(kept) == {"id", "principalId", "roleDefinitionId", "directoryScopeId", "principal"}
    assert set(kept["principal"]) == PRINCIPAL_PROPERTIES == {"id", "displayName", "userPrincipalName",
                                                              "@odata.type"}
    assert kept["principal"]["displayName"] == "Ann"


@pytest.mark.parametrize("principal", ["a string", 5, None, ["list"]])
def test_a_principal_that_is_not_an_object_carries_nothing(principal):
    (kept,) = filter_items(get(ASSIGNMENTS), [{"id": "a", "principal": principal}])
    assert kept["principal"] in (None, [])


def test_embedded_app_roles_keep_only_their_declared_properties():
    sp = {"id": GUID, "appId": "x", "displayName": "Microsoft Graph", "keyCredentials": [{"key": "secret"}],
          "passwordCredentials": [{"hint": "x"}], "appRoles": [
              {"id": "r", "value": "User.Read.All", "displayName": "Read users", "allowedMemberTypes": ["Application"],
               "description": "long", "isEnabled": True, "origin": "Application"}, "not-an-object"]}
    (kept,) = filter_items(get(SPS), [sp])
    assert "keyCredentials" not in kept and "passwordCredentials" not in kept
    assert kept["appRoles"] == [{"id": "r", "value": "User.Read.All", "displayName": "Read users",
                                 "allowedMemberTypes": ["Application"]}]


def test_items_that_are_not_objects_are_dropped():
    assert filter_items(get(DEFINITIONS), [{"id": "1", "displayName": "R", "rolePermissions": []}, "x", 3]) == [
        {"id": "1", "displayName": "R"}]


def test_the_user_list_is_filtered_too():
    # Review F7 (2026-10-31): $select alone bounded it before; now the broker enforces it as well.
    items = [{"id": "u", "displayName": "D", "unexpected": 1, "@odata.etag": "x", "signInActivity": {
        "lastSignInDateTime": "2026-01-01T00:00:00Z", "lastSignInRequestId": "r", "extra": 1}}]
    assert filter_items(get("users.list_with_sign_in_activity"), items) == [
        {"id": "u", "displayName": "D", "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}}]


# --- stage 2 and the transport each refuse a forged fixed parameter on their own -----

from clw.broker import policy  # noqa: E402
from clw.broker.operations import BuiltRequest  # noqa: E402
from clw.broker.transport import _checked_target  # noqa: E402

USERS_REQ = build_request(get("users.list_with_sign_in_activity"), {"select": ["id"]})
ASSIGN_REQ = build_request(get(ASSIGNMENTS), {})

FORGED = [
    BuiltRequest(USERS_REQ.method, USERS_REQ.path_template, USERS_REQ.path, USERS_REQ.query + (("$expand", "manager"),)),
    BuiltRequest(ASSIGN_REQ.method, ASSIGN_REQ.path_template, ASSIGN_REQ.path, (("$expand", "roleDefinition"),)),
    BuiltRequest(ASSIGN_REQ.method, ASSIGN_REQ.path_template, ASSIGN_REQ.path, ()),
    BuiltRequest(ASSIGN_REQ.method, ASSIGN_REQ.path_template, ASSIGN_REQ.path,
                 (("$expand", "principal"), ("$expand", "principal"))),
    BuiltRequest(ASSIGN_REQ.method, ASSIGN_REQ.path_template, ASSIGN_REQ.path,
                 (("$filter", "x"), ("$expand", "principal"))),
]


@pytest.mark.parametrize("request_", FORGED, ids=range(len(FORGED)))
def test_stage_two_refuses_a_forged_query(request_):
    rule = policy.RULES[ASSIGNMENTS if request_.path_template == ASSIGN_REQ.path_template
                        else "users.list_with_sign_in_activity"]
    assert policy._matches(rule, request_) is False


@pytest.mark.parametrize("request_", FORGED[:2] + FORGED[4:], ids=range(3))
def test_the_transport_refuses_a_foreign_query_parameter(request_):
    assert _checked_target(request_) is None


def test_the_real_requests_pass_both():
    assert policy._matches(policy.RULES[ASSIGNMENTS], ASSIGN_REQ)
    assert _checked_target(ASSIGN_REQ) == ("/v1.0/roleManagement/directory/roleAssignments?$expand=principal", True,
                                           False)
