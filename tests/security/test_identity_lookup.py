"""users.get_identity, the broker's own single-user read for change proposals (SD-054).

No manifest can list it, so no task or agent can call it; its $select is the
registry's; the transport accepts only one object back; and only the four
snapshot properties (and the object's type) leave the broker.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from pydantic import ValidationError

from clw.broker import operations
from clw.broker.manifest import ManifestError, load_manifest
from clw.broker.operations import BuiltRequest, OperationSpec, build_request, filter_items, get
from clw.broker.pagination import request_target
from clw.broker.transport import _checked_target, _page

LOOKUP = "users.get_identity"
GUID = "0f8fad5b-d9cb-469f-a165-70867728950e"
REQ = build_request(get(LOOKUP), {"user_id": GUID.upper()})


def test_the_lookup_is_one_user_with_the_registrys_select():
    assert request_target(REQ) == f"/v1.0/users/{GUID}?$select=accountEnabled,displayName,id,userPrincipalName"


@pytest.mark.parametrize("params", [{"user_id": GUID, "select": ["passwordProfile"]}, {"user_id": GUID, "top": 1},
                                    {"user_id": GUID, "expand": "manager"}, {"user_id": "me"}, {}])
def test_nothing_about_the_lookup_can_be_chosen_by_a_caller(params):
    with pytest.raises(ValidationError):
        build_request(get(LOOKUP), params)


def test_no_manifest_may_list_it(tmp_path: Path):
    source = (Path(__file__).resolve().parents[2] / "agent_profiles" / "read-only-investigation" / "manifest.yaml")
    text = source.read_text(encoding="utf-8").replace(
        "  - users.list_with_sign_in_activity\n", "  - users.list_with_sign_in_activity\n  - users.get_identity\n")
    path = tmp_path / "manifest.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match="internal"):
        load_manifest(path)


def test_only_the_lookup_is_internal_and_it_is_single_and_unpaginated():
    internal = {name for name, spec in operations.REGISTRY.items() if spec.internal_only}
    assert internal == {LOOKUP}
    spec = get(LOOKUP)
    assert spec.single and not spec.paginated and spec.kind == "read"


@pytest.mark.parametrize("bad", [
    dict(single=True, paginated=True), dict(single=True, kind="write", executable=False, method="PATCH"),
    dict(internal_only=True, kind="write", executable=False, method="PATCH"),
])
def test_the_registry_refuses_contradictory_flags(bad):
    spec = dataclasses.replace(get(LOOKUP), **bad)
    with pytest.raises(RuntimeError):
        operations._check_spec(spec)


@pytest.mark.parametrize("query", [
    (), (("$select", "accountEnabled,displayName,id,passwordProfile,userPrincipalName"),),
    (("$select", "accountEnabled,displayName,id,userPrincipalName"), ("$top", "1")),
    (("$select", "accountEnabled,displayName,id,userPrincipalName"), ("$expand", "manager")),
])
def test_the_transport_refuses_a_lookup_without_exactly_its_fixed_select(query):
    assert _checked_target(BuiltRequest(REQ.method, REQ.path_template, REQ.path, query)) is None


def test_the_transport_marks_the_lookup_single():
    assert _checked_target(REQ)[1:] == (False, True)


def test_a_single_response_is_one_object_and_never_a_collection_or_a_continuation():
    assert _page(b'{"id": "u", "displayName": "D"}', single=True) == ([{"id": "u", "displayName": "D"}], None)
    for raw in (b'{"value": [{"id": "u"}]}', b'{"id": "u", "@odata.nextLink": "https://graph.microsoft.com/x"}',
                b'[{"id": "u"}]', b'"u"', b'not json'):
        assert _page(raw, single=True) is None
    assert _page(b'{"id": "u"}') is None  # a collection operation still needs a collection


def test_only_the_snapshot_properties_leave_the_broker():
    item = {"@odata.context": "x", "@odata.type": "#microsoft.graph.user", "id": GUID, "displayName": "D",
            "userPrincipalName": "d@x.test", "accountEnabled": True, "mail": "d@x.test", "passwordProfile": {}}
    assert filter_items(get(LOOKUP), [item]) == [{"@odata.type": "#microsoft.graph.user", "id": GUID,
                                                  "displayName": "D", "userPrincipalName": "d@x.test",
                                                  "accountEnabled": True}]


def test_a_spec_with_a_caller_select_cannot_also_fix_one():
    spec = OperationSpec(name="t", kind="read", executable=True, method="GET", path_template="/users",
                         params_model=operations.ListUsersParams, select_allowlist=get(
                             "users.list_with_sign_in_activity").select_allowlist,
                         fixed_query=(("$select", "id"),))
    with pytest.raises(RuntimeError):
        operations._check_spec(spec)
