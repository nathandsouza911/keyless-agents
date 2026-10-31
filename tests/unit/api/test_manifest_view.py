"""The manifest view and task summary are pure functions of the manifest
(Task 16). No database: the per-tenant `audit.chain_valid` is added by the
route, tested in tests/security/test_api_tenant_isolation.py."""

from __future__ import annotations

from pathlib import Path

from clw.api.catalog import load_api_catalog
from clw.api.runtime import ParamsInvalid, normalized_params
from clw.api.routes.tasks import manifest_view, task_summary
from clw.broker import operations
from clw.broker.manifest import load_manifest

import pytest

REPO = Path(__file__).resolve().parents[3]
MANIFEST = load_manifest(REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml")


def test_manifest_view_shows_method_and_path_for_allowed_and_prohibited():
    view = manifest_view(MANIFEST)
    assert view["id"] == MANIFEST.id and view["mode"] == "app_only"
    assert view["timeout_seconds"] == MANIFEST.timeout_seconds
    assert view["approval_required"] is False
    # Every allowed and prohibited op names its method and template, from the
    # operation registry (not from the manifest, which has no such fields).
    for group in ("allowed", "prohibited"):
        names = {op["op"] for op in view[group]}
        assert names == set(getattr(MANIFEST, group))
        for op in view[group]:
            spec = operations.get(op["op"])
            assert (op["method"], op["path_template"]) == (spec.method, spec.path_template)
    # The one allowed op is the read; the prohibited ones are the writes.
    assert [op["op"] for op in view["allowed"]] == ["users.list_with_sign_in_activity"]
    assert {op["method"] for op in view["prohibited"]} == {"PATCH", "DELETE", "POST"}


def test_manifest_view_reports_profile_and_audit_status():
    view = manifest_view(MANIFEST)
    profile = view["permission_profile"]
    assert profile["id"] == MANIFEST.profile.id and profile["version"] == MANIFEST.profile.version
    assert profile["expected_permissions"] == sorted(MANIFEST.profile.expected_permissions)
    # audit.enabled is always true; chain_valid is added by the route only.
    assert view["audit"] == {"enabled": True}


def test_manifest_view_exposes_no_credential_or_url():
    view = manifest_view(MANIFEST)
    blob = repr(view)
    cred = MANIFEST.profile.credential
    for secret_name in (cred.client_id_env, cred.certificate_path_env, cred.thumbprint_env):
        assert secret_name not in blob
    # No field a caller could pass back as a URL or raw path/host.
    assert "graph.microsoft.com" not in blob and "https://" not in blob


def test_task_summary_is_a_short_card():
    summary = task_summary(MANIFEST)
    assert set(summary) == {"id", "name", "purpose", "mode", "approval_required", "timeout_seconds"}
    assert summary["id"] == MANIFEST.id


def test_catalog_loads_the_dormant_task():
    catalog = load_api_catalog()
    assert MANIFEST.id in catalog
    assert catalog[MANIFEST.id].sha256 == MANIFEST.sha256


def test_normalized_params_fills_default_and_bounds():
    (name, spec), = MANIFEST.params.items()
    assert normalized_params(MANIFEST, {}) == {name: spec.default}
    assert normalized_params(MANIFEST, {name: spec.minimum}) == {name: spec.minimum}
    for bad in ({name: spec.minimum - 1}, {name: spec.maximum + 1}, {name: True}, {"unknown": 1}):
        with pytest.raises(ParamsInvalid):
            normalized_params(MANIFEST, bad)
