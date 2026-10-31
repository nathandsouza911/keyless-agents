"""Manifest and profile loader (Task 8; SD-002, SD-003, SD-010).

A manifest names registered operations only: it cannot define a method,
path, query or parameter bound, so it can narrow what a task may call but
never change the request the registry builds. Load failures are
ManifestError and never echo file content."""

from __future__ import annotations

import copy
import hashlib
import traceback
from pathlib import Path

import pytest
import yaml

from clw.broker import operations
from clw.broker.manifest import DEFAULT_PROFILES_DIR, ManifestError, TaskManifest, load_manifest
from clw.broker.profiles import PermissionProfile, load_profile, load_profile_by_id

REPO = Path(__file__).resolve().parents[3]
DORMANT = REPO / "tasks" / "dormant_account_investigation" / "manifest.yaml"
PROFILE = REPO / "profiles" / "directory-read-auditlog-read.yaml"

MANIFEST_DOC = yaml.safe_load(DORMANT.read_text(encoding="utf-8"))
PROFILE_DOC = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
SENTINEL = "SENTINEL-7d3f19"


@pytest.fixture
def dirs(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    return tmp_path, profiles


def _write_profile(profiles: Path, doc=None, *, text: str | None = None, name: str | None = None) -> Path:
    doc = copy.deepcopy(PROFILE_DOC) if doc is None else doc
    path = profiles / (name or f"{doc.get('id', 'x') if isinstance(doc, dict) else 'x'}.yaml")
    path.write_text(text if text is not None else yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


def _load(dirs, manifest=None, *, text: str | None = None, profile=None):
    tmp, profiles = dirs
    _write_profile(profiles, profile)
    path = tmp / "manifest.yaml"
    doc = copy.deepcopy(MANIFEST_DOC) if manifest is None else manifest
    path.write_text(text if text is not None else yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return load_manifest(path, profiles_dir=profiles)


def _manifest(**changes):
    doc = copy.deepcopy(MANIFEST_DOC)
    for key, value in changes.items():
        if value is _DROP:
            doc.pop(key)
        else:
            doc[key] = value
    return doc


def _profile(**changes):
    doc = copy.deepcopy(PROFILE_DOC)
    for key, value in changes.items():
        if value is _DROP:
            doc.pop(key)
        else:
            doc[key] = value
    return doc


_DROP = object()


def _no_leak(exc: BaseException, *secrets: str) -> None:
    rendered = "".join(traceback.format_exception(exc)) + repr(exc) + str(exc.args)
    for secret in secrets:
        assert secret not in rendered
    assert exc.__context__ is None and exc.__cause__ is None


# --- the shipped files ------------------------------------------------------

def test_dormant_manifest_loads():
    m = load_manifest(DORMANT)
    assert isinstance(m, TaskManifest)
    assert (m.id, m.version, m.mode, m.timeout_seconds, m.approval_required) == (
        "dormant-account-investigation", 1, "app_only", 300, False)
    assert m.allowed == ("users.list_with_sign_in_activity",)
    assert m.prohibited == ("users.update", "users.delete", "directory_roles.add_member")
    assert m.permission_profile == "directory-read-auditlog-read"
    assert m.profile.id == m.permission_profile and m.profile.mode == m.mode
    p = m.params["inactive_days"]
    assert (p.type, p.minimum, p.maximum, p.default) == ("integer", 30, 365, 90)


def test_default_profiles_dir_is_the_repo_profiles_folder():
    assert DEFAULT_PROFILES_DIR == REPO / "profiles"


def test_sha256_is_of_the_raw_bytes_and_stable(dirs):
    a, b = load_manifest(DORMANT), load_manifest(DORMANT)
    assert a.sha256 == b.sha256 == hashlib.sha256(DORMANT.read_bytes()).hexdigest()
    assert len(a.sha256) == 64 and a.sha256 == a.sha256.lower()
    tmp, profiles = dirs
    _write_profile(profiles)
    changed = tmp / "manifest.yaml"
    changed.write_bytes(DORMANT.read_bytes() + b"# comment\n")
    assert load_manifest(changed, profiles_dir=profiles).sha256 != a.sha256


def test_profile_loads():
    p = load_profile(PROFILE)
    assert isinstance(p, PermissionProfile)
    assert (p.id, p.version, p.mode) == ("directory-read-auditlog-read", 1, "app_only")
    assert p.expected_permissions == frozenset({"AuditLog.Read.All", "User.Read.All"})
    assert (p.credential.client_id_env, p.credential.certificate_path_env, p.credential.thumbprint_env) == (
        "CLW_PROFILE_DIRREAD_CLIENT_ID", "CLW_PROFILE_DIRREAD_CERT_PATH", "CLW_PROFILE_DIRREAD_CERT_THUMBPRINT")
    assert p.sha256 == hashlib.sha256(PROFILE.read_bytes()).hexdigest()


def test_profile_loader_does_not_resolve_environment_values(monkeypatch):
    monkeypatch.setenv("CLW_PROFILE_DIRREAD_CLIENT_ID", SENTINEL)
    p = load_profile(PROFILE)
    assert SENTINEL not in repr(p)


def test_loaded_objects_are_immutable():
    m = load_manifest(DORMANT)
    with pytest.raises(AttributeError):
        m.allowed = ("users.delete",)  # type: ignore[misc]
    with pytest.raises(TypeError):
        m.params["x"] = m.params["inactive_days"]  # type: ignore[index]
    assert isinstance(m.allowed, tuple) and isinstance(m.profile.expected_permissions, frozenset)


# --- the plan's ManifestError cases -----------------------------------------

def test_python_object_tag_rejected(dirs):
    text = DORMANT.read_text(encoding="utf-8") + "extra: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(ManifestError):
        _load(dirs, text=text)


def test_unknown_top_level_key_rejected(dirs):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(owner="someone"))


def test_allowed_and_prohibited_overlap_rejected(dirs):
    with pytest.raises(ManifestError, match="both allowed and prohibited"):
        _load(dirs, _manifest(prohibited=["users.list_with_sign_in_activity", "users.delete"]))


def test_unregistered_allowed_entry_rejected(dirs):
    with pytest.raises(ManifestError, match="not a registered operation"):
        _load(dirs, _manifest(allowed=["users.list_with_sign_in_activity", "graph.raw"]))


def test_allowed_write_operation_rejected(dirs):
    with pytest.raises(ManifestError, match="write"):
        _load(dirs, _manifest(allowed=["users.update"], prohibited=["users.delete"]))


@pytest.mark.parametrize("mode", ["delegated", "Delegated", "app-only", "", None, 1])
def test_mode_other_than_app_only_rejected(dirs, mode):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(mode=mode))


def test_delegated_rejected_even_with_a_delegated_profile(dirs):
    with pytest.raises(ManifestError, match="delegated"):
        _load(dirs, _manifest(mode="delegated"), profile=_profile(mode="delegated"))


def test_missing_profile_rejected(dirs):
    with pytest.raises(ManifestError, match="profile"):
        _load(dirs, _manifest(permission_profile="no-such-profile"))


def test_profile_mode_must_equal_manifest_mode(dirs):
    with pytest.raises(ManifestError, match="mode"):
        _load(dirs, profile=_profile(mode="delegated"))


@pytest.mark.parametrize("timeout", [9, 0, -1, 901, 10**6, "300", 300.0, True, None])
def test_timeout_outside_10_to_900_rejected(dirs, timeout):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(timeout_seconds=timeout))


@pytest.mark.parametrize("timeout", [10, 900])
def test_timeout_bounds_inclusive(dirs, timeout):
    assert _load(dirs, _manifest(timeout_seconds=timeout)).timeout_seconds == timeout


def test_profile_with_pem_header_rejected(dirs):
    tmp, profiles = dirs
    text = PROFILE.read_text(encoding="utf-8") + "# -----BEGIN PRIVATE KEY-----\n"
    path = _write_profile(profiles, text=text, name="directory-read-auditlog-read.yaml")
    with pytest.raises(ManifestError, match="secret"):
        load_profile(path)


@pytest.mark.parametrize("value", [
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",                 # base64 key material
    "q8Z~Vm3sQx" + "A" * 30,                            # a client secret
    "0123456789ABCDEF0123456789ABCDEF01234567",         # a thumbprint inlined
    "CLW_PROFILE_X_" + "A" * 30,                        # 30+ base64 chars inside a name
])
@pytest.mark.parametrize("key", ["client_id_env", "certificate_path_env", "thumbprint_env"])
def test_profile_with_secret_looking_credential_value_rejected(dirs, key, value):
    _, profiles = dirs
    doc = _profile()
    doc["credential"][key] = value
    with pytest.raises(ManifestError, match="secret") as info:
        load_profile(_write_profile(profiles, doc))
    _no_leak(info.value, value)


# --- the manifest cannot shape requests or bypass the registry --------------

@pytest.mark.parametrize("entry", [
    "GET /users", "/users", "https://graph.microsoft.com/v1.0/users", "users.list_with_sign_in_activity?$expand=x",
    "USERS.LIST_WITH_SIGN_IN_ACTIVITY", " users.list_with_sign_in_activity", "users.*", "*",
])
def test_allowed_entries_must_be_exact_registry_names(dirs, entry):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(allowed=[entry]))


@pytest.mark.parametrize("entry", [
    {"op": "users.list_with_sign_in_activity", "path": "/users/{user_id}/memberOf"},
    {"users.list_with_sign_in_activity": {"select": ["manager"]}},
    ["users.list_with_sign_in_activity"],
    1,
    None,
])
def test_allowed_entries_must_be_plain_strings(dirs, entry):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(allowed=[entry]))


@pytest.mark.parametrize("key", [
    "operations", "paths", "path_template", "method", "select_allowlist", "top_max", "graph_base", "api_version",
    "headers", "scopes", "credential", "expected_permissions", "tenant_id",
])
def test_request_shaping_keys_rejected(dirs, key):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(**{key: "x"}))


def test_loading_does_not_change_the_registry_or_the_built_request(dirs):
    before = dict(operations.REGISTRY)
    built = operations.build_request(operations.get("users.list_with_sign_in_activity"), {"select": ["id"]})
    _load(dirs)
    load_manifest(DORMANT)
    assert dict(operations.REGISTRY) == before
    assert all(operations.REGISTRY[k] is v for k, v in before.items())
    assert operations.build_request(operations.get("users.list_with_sign_in_activity"), {"select": ["id"]}) == built


def test_allowed_names_resolve_to_registered_read_executable_ops():
    for name in load_manifest(DORMANT).allowed:
        spec = operations.get(name)
        assert spec.kind == "read" and spec.executable


def test_allowed_read_operation_that_is_not_executable_rejected(dirs, monkeypatch):
    import dataclasses
    from types import MappingProxyType

    read = operations.get("users.list_with_sign_in_activity")
    disabled = dataclasses.replace(read, name="users.list_disabled", executable=False)
    monkeypatch.setattr(operations, "REGISTRY", MappingProxyType({**operations.REGISTRY, disabled.name: disabled}))
    with pytest.raises(ManifestError, match="non-executable"):
        _load(dirs, _manifest(allowed=["users.list_disabled"]))


def test_unregistered_prohibited_entry_rejected(dirs):
    # A typo in prohibited would otherwise look like a prohibition that is not one.
    with pytest.raises(ManifestError, match="not a registered operation"):
        _load(dirs, _manifest(prohibited=["users.updat"]))


@pytest.mark.parametrize("field", ["allowed", "prohibited"])
def test_duplicate_entries_rejected(dirs, field):
    doc = _manifest()
    doc[field] = doc[field] + doc[field][:1]
    with pytest.raises(ManifestError, match="duplicate"):
        _load(dirs, doc)


def test_empty_allowed_rejected(dirs):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(allowed=[]))


def test_empty_prohibited_is_allowed(dirs):
    assert _load(dirs, _manifest(prohibited=[])).prohibited == ()


def test_approval_required_true_rejected_in_phase1(dirs):
    # No approval workflow exists in Phase 1: accepting the flag would run
    # the task without the approval it asks for.
    with pytest.raises(ManifestError, match="approval"):
        _load(dirs, _manifest(approval_required=True))


@pytest.mark.parametrize("value", ["false", 0, None])
def test_approval_required_must_be_a_bool(dirs, value):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(approval_required=value))


# --- manifest fields --------------------------------------------------------

@pytest.mark.parametrize("change", [
    {"schema_version": 2}, {"schema_version": "1"}, {"schema_version": _DROP},
    {"id": "Dormant"}, {"id": "../x"}, {"id": "a" * 65}, {"id": ""}, {"id": 1}, {"id": _DROP},
    {"version": 0}, {"version": "1"}, {"version": True},
    {"name": ""}, {"name": "x" * 101}, {"name": "a\nb"},
    {"purpose": ""}, {"purpose": "x" * 501}, {"purpose": "a\x00b"},
    {"permission_profile": "../profiles/directory-read-auditlog-read"},
    {"permission_profile": "/etc/passwd"}, {"permission_profile": "directory-read-auditlog-read.yaml"},
    {"permission_profile": "Directory-Read-AuditLog-Read"}, {"permission_profile": _DROP},
    {"allowed": "users.list_with_sign_in_activity"}, {"allowed": _DROP}, {"prohibited": _DROP},
    {"approval_required": _DROP}, {"timeout_seconds": _DROP}, {"mode": _DROP},
])
def test_bad_manifest_fields_rejected(dirs, change):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(**change))


@pytest.mark.parametrize("params", [
    {"inactive_days": {"type": "string", "minimum": 30, "maximum": 365, "default": 90}},
    {"inactive_days": {"type": "integer", "minimum": 400, "maximum": 365, "default": 400}},
    {"inactive_days": {"type": "integer", "minimum": 30, "maximum": 365, "default": 10}},
    {"inactive_days": {"type": "integer", "minimum": 30, "maximum": 365, "default": 366}},
    {"inactive_days": {"type": "integer", "minimum": 30, "maximum": 365, "default": "90"}},
    {"inactive_days": {"type": "integer", "minimum": 30, "maximum": 365, "default": 90, "pattern": ".*"}},
    {"inactive_days": {"type": "integer", "minimum": 30}},
    {"Inactive-Days": {"type": "integer", "minimum": 30, "maximum": 365, "default": 90}},
    {"inactive_days": 90},
    ["inactive_days"],
])
def test_bad_param_schemas_rejected(dirs, params):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(params=params))


def test_param_without_default_loads(dirs):
    m = _load(dirs, _manifest(params={"inactive_days": {"type": "integer", "minimum": 30, "maximum": 365}}))
    assert m.params["inactive_days"].default is None


def test_params_may_be_omitted(dirs):
    assert dict(_load(dirs, _manifest(params=_DROP)).params) == {}


# --- YAML strictness --------------------------------------------------------

def test_duplicate_yaml_keys_rejected(dirs):
    # PyYAML keeps the last duplicate silently; a reviewer could read the first.
    text = DORMANT.read_text(encoding="utf-8") + "allowed:\n  - users.list_with_sign_in_activity\n"
    with pytest.raises(ManifestError, match="duplicate key"):
        _load(dirs, text=text)


def test_yaml_aliases_rejected(dirs):
    text = DORMANT.read_text(encoding="utf-8").replace(
        "prohibited:\n", "x_anchor: &a [users.delete]\nprohibited:\n") + "y: *a\n"
    with pytest.raises(ManifestError, match="alias"):
        _load(dirs, text=text)


@pytest.mark.parametrize("text", ["", "null\n", "- a\n- b\n", "just a string\n", "{a: 1\n", "a: [\n", "\tid: x\n"])
def test_not_a_mapping_or_invalid_yaml_rejected(dirs, text):
    with pytest.raises(ManifestError):
        _load(dirs, text=text)


def test_oversized_file_rejected(dirs):
    text = DORMANT.read_text(encoding="utf-8") + "#" + "x" * (64 * 1024) + "\n"
    with pytest.raises(ManifestError, match="too large"):
        _load(dirs, text=text)


def test_non_utf8_rejected(dirs):
    tmp, profiles = dirs
    _write_profile(profiles)
    path = tmp / "manifest.yaml"
    path.write_bytes(DORMANT.read_bytes() + b"# \xff\xfe\n")
    with pytest.raises(ManifestError):
        load_manifest(path, profiles_dir=profiles)


def test_missing_manifest_file_rejected(tmp_path):
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "absent.yaml", profiles_dir=tmp_path)


def test_errors_never_echo_values(dirs):
    cases = [
        _manifest(name=SENTINEL * 20),
        _manifest(mode=SENTINEL),
        _manifest(allowed=[SENTINEL]),
        _manifest(timeout_seconds=SENTINEL),
        _manifest(params={"inactive_days": {"type": SENTINEL}}),
    ]
    for doc in cases:
        with pytest.raises(ManifestError) as info:
            _load(dirs, doc)
        _no_leak(info.value, SENTINEL)
    text = DORMANT.read_text(encoding="utf-8") + f"x: [{SENTINEL}\n"
    with pytest.raises(ManifestError) as info:
        _load(dirs, text=text)
    _no_leak(info.value, SENTINEL)


# --- profile fields ---------------------------------------------------------

@pytest.mark.parametrize("change", [
    {"id": "../x"}, {"id": "Directory"}, {"id": _DROP},
    {"version": 0}, {"version": "1"},
    {"mode": "app-only"}, {"mode": _DROP},
    {"expected_permissions": []}, {"expected_permissions": "User.Read.All"},
    {"expected_permissions": ["User.Read.All", "User.Read.All"]},
    {"expected_permissions": ["user.read.all"]}, {"expected_permissions": ["User Read All"]},
    {"expected_permissions": ["User.Read.All", ".default"]},
    {"expected_permissions": ["https://graph.microsoft.com/.default"]},
    {"credential": _DROP}, {"credential": {"client_id_env": "CLW_PROFILE_X"}},
    {"client_secret": "x"}, {"tenant_id": "x"},
])
def test_bad_profile_fields_rejected(dirs, change):
    _, profiles = dirs
    doc = _profile(**change)
    with pytest.raises(ManifestError):
        load_profile(_write_profile(profiles, doc, name="directory-read-auditlog-read.yaml"))


@pytest.mark.parametrize("perm", ["User.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
                                  "User.Write.All", "Application.ReadWrite.OwnedBy"])
def test_profile_with_write_permission_rejected_in_phase1(dirs, perm):
    _, profiles = dirs
    doc = _profile(expected_permissions=["User.Read.All", perm])
    with pytest.raises(ManifestError, match="write"):
        load_profile(_write_profile(profiles, doc))


@pytest.mark.parametrize("name", ["clw_profile_x", "PATH", "HOME", "CLW_RUN_TOKEN", "CLW_PROFILE_", "CLW_PROFILE_X Y",
                                  "CLW_PROFILE_X=1", "$CLW_PROFILE_X", "", 1, None])
def test_credential_entries_must_be_profile_env_names(dirs, name):
    _, profiles = dirs
    doc = _profile()
    doc["credential"]["thumbprint_env"] = name
    with pytest.raises(ManifestError):
        load_profile(_write_profile(profiles, doc))


def test_extra_credential_key_rejected(dirs):
    _, profiles = dirs
    doc = _profile()
    doc["credential"]["private_key"] = "CLW_PROFILE_X_KEY"
    with pytest.raises(ManifestError):
        load_profile(_write_profile(profiles, doc))


def test_profile_file_name_must_match_its_id(dirs):
    _, profiles = dirs
    path = _write_profile(profiles, name="other-profile.yaml")
    with pytest.raises(ManifestError, match="file name"):
        load_profile(path)


@pytest.mark.parametrize("profile_id", ["../x", "a/b", "a\\b", "", "A", ".", "x.yaml", 1, None])
def test_load_profile_by_id_refuses_unsafe_ids(dirs, profile_id):
    _, profiles = dirs
    with pytest.raises(ManifestError):
        load_profile_by_id(profile_id, profiles_dir=profiles)  # type: ignore[arg-type]


def test_load_profile_by_id_refuses_a_symlink_out_of_the_directory(dirs):
    tmp, profiles = dirs
    outside = tmp / "outside"
    outside.mkdir()
    target = _write_profile(outside)
    link = profiles / target.name
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks not permitted here")
    with pytest.raises(ManifestError):
        load_profile_by_id(PROFILE_DOC["id"], profiles_dir=profiles)


def test_manifest_profile_is_the_one_in_profiles_dir(dirs):
    m = _load(dirs, profile=_profile(version=7))
    assert m.profile.version == 7


def test_param_minimum_above_maximum_rejected_without_default(dirs):
    with pytest.raises(ManifestError):
        _load(dirs, _manifest(params={"inactive_days": {"type": "integer", "minimum": 400, "maximum": 365}}))


@pytest.mark.parametrize("line", ["name: !!python/str Dormant", "name: !!python/unicode Dormant"])
def test_python_tags_that_full_loader_accepts_are_refused(dirs, line):
    text = DORMANT.read_text(encoding="utf-8").replace("name: Dormant Account Investigation", line)
    assert text != DORMANT.read_text(encoding="utf-8")
    with pytest.raises(ManifestError):
        _load(dirs, text=text)


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", "", "42\n"])
def test_profile_that_is_not_a_mapping_rejected(dirs, text):
    _, profiles = dirs
    with pytest.raises(ManifestError):
        load_profile(_write_profile(profiles, text=text, name="directory-read-auditlog-read.yaml"))


@pytest.mark.parametrize("profile_id", ["DIRECTORY-READ-AUDITLOG-READ", "Directory-Read-AuditLog-Read"])
def test_load_profile_by_id_is_case_sensitive_even_on_case_insensitive_filesystems(dirs, profile_id):
    _, profiles = dirs
    _write_profile(profiles)
    with pytest.raises(ManifestError):
        load_profile_by_id(profile_id, profiles_dir=profiles)
