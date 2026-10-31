"""deploy/test-tenant/{setup,uninstall}.ps1 (v0.1 V10): what they ask a tenant for, checked without a tenant.

The scripts are run by a person, on their own test tenant; these checks keep them honest: they request
exactly the profiles' read-only permissions, sign in with the one scope needed to create an app, never
grant consent themselves, and the uninstall deletes only the app it recorded.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SETUP = (ROOT / "deploy" / "test-tenant" / "setup.ps1").read_text(encoding="utf-8")
UNINSTALL = (ROOT / "deploy" / "test-tenant" / "uninstall.ps1").read_text(encoding="utf-8")
ROTATE = (ROOT / "deploy" / "test-tenant" / "rotate.ps1").read_text(encoding="utf-8")


def _expected(profile_file: str) -> list[str]:
    return yaml.safe_load((ROOT / "profiles" / profile_file).read_text(encoding="utf-8"))["expected_permissions"]


def _requested(profile: str) -> list[str]:
    line = re.search(rf"'{profile}'\s*=\s*@\(([^)]*)\)", SETUP).group(1)
    return re.findall(r"'([^']+)'", line)


@pytest.mark.parametrize("profile, profile_file", [("agent-read-only-investigation", "agent-read-only-investigation.yaml"),
                                                   ("dormant-accounts", "directory-read-auditlog-read.yaml")])
def test_the_script_requests_exactly_the_profiles_permissions(profile, profile_file):
    assert sorted(_requested(profile)) == sorted(_expected(profile_file))


def test_every_requested_permission_is_read_only():
    for profile in ("agent-read-only-investigation", "dormant-accounts"):
        assert all(".Read." in p or p.endswith(".Read.All") for p in _requested(profile))
    assert "Directory.Read.All" not in SETUP.split("Connect-MgGraph")[0].split("$Permissions = @{")[1]


def test_the_only_sign_in_scope_is_the_one_that_creates_an_app():
    for script in (SETUP, UNINSTALL, ROTATE):
        assert re.findall(r"-Scopes\s+'([^']+)'", script) == ["Application.ReadWrite.All"]


def test_the_scripts_never_grant_consent_themselves():
    for forbidden in ("New-MgServicePrincipalAppRoleAssignment", "New-MgOauth2PermissionGrant",
                      "AppRoleAssignment.ReadWrite.All", "New-MgServicePrincipalAppRoleAssignedTo"):
        assert forbidden not in SETUP and forbidden not in UNINSTALL and forbidden not in ROTATE
    assert "Grant admin consent" in SETUP and "/adminconsent" not in SETUP  # the person grants it, in the portal


def test_setup_records_the_app_before_anything_else_can_fail():
    record, service_principal = SETUP.index("$state | ConvertTo-Json"), SETUP.index("New-MgServicePrincipal")
    assert SETUP.index("New-MgApplication") < record < service_principal


def test_rotate_changes_only_the_recorded_matching_apps_certificate():
    assert "Remove-MgApplication" not in ROTATE and ROTATE.count("Update-MgApplication") == 1
    assert ROTATE.index("$app.AppId -ne $state.appId") < ROTATE.index("Update-MgApplication")
    assert "-KeyCredentials" in ROTATE and "RequiredResourceAccess" not in ROTATE


def test_setup_needs_the_tenant_confirmed_and_supports_a_dry_run():
    assert "SupportsShouldProcess" in SETUP and "$WhatIfPreference" in SETUP
    assert "Read-Host" in SETUP and "The tenant IDs differ. Nothing was done." in SETUP
    assert "TEST TENANT ONLY" in SETUP
    assert re.search(r"SignInAudience\s+'AzureADMyOrg'", SETUP)
    assert "passwordcredentials" not in SETUP.lower()  # a certificate only, never a client secret


def test_uninstall_deletes_only_the_recorded_matching_app():
    assert UNINSTALL.count("Remove-MgApplication") == 1
    guard = UNINSTALL.index("$app.AppId -ne $state.appId")
    assert guard < UNINSTALL.index("Remove-MgApplication")
    assert "$state.tenantId -ne $TenantId" in UNINSTALL


@pytest.mark.skipif(not (shutil.which("pwsh") or shutil.which("powershell")), reason="no PowerShell")
@pytest.mark.parametrize("name", ["setup.ps1", "uninstall.ps1", "rotate.ps1"])
def test_the_scripts_parse(name):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    path = ROOT / "deploy" / "test-tenant" / name
    command = ("$errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
               f"'{path}', [ref]$null, [ref]$errs); $errs.Count")
    out = subprocess.run([shell, "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "0", out.stdout + out.stderr
