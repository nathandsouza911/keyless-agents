"""Import-boundary checks (architecture.md §3, §4.1).

These are hygiene checks on trusted code, NOT a security boundary (SD-008).
The enforcing boundaries are the broker policy and the sandbox; this test
only keeps the code layout from drifting toward them being bypassed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "clw"
TASK_SDK = REPO / "task_sdk" / "clw_task_sdk"
TASKS = REPO / "tasks"

FORBIDDEN_IN_TASKS = ("clw", "msal", "subprocess", "socket")
ALLOWED_TASK_ENV_KEYS = frozenset({"CLW_RUN_TOKEN", "CLW_BROKER_URL"})
API_MAY_IMPORT_FROM_BROKER = frozenset(
    # facade.rules: validating a script manifest at approval (SD-043); pure, no transport or credentials.
    # capability: issue_run_token, to mint an agent session's capability (SD-049); no credential or transport.
    # proposals: the canonical request, to re-check a proposal's binding on its page (SD-054); pure.
    {"clw.broker.manifest", "clw.broker.operations", "clw.broker.profiles", "clw.broker.facade.rules",
     "clw.broker.capability", "clw.broker.proposals"}
)
# Only these broker modules may import msal / name the Graph host.
MSAL_IMPORTERS = frozenset({"clw.broker.credentials"})
GRAPH_HOST_OWNERS = frozenset({"clw.broker.transport", "clw.broker.pagination",
                               # SD-051: the quick start's fake Graph (impersonates the host on an internal
                               # network) and its setup (issues the fake's certificate); neither sends to it.
                               "clw.demo.fake_graph", "clw.demo.setup"})
GRAPH_HOST = "graph.microsoft.com"


def _module_name(path: Path, root: Path, package: str) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = [p for p in rel.parts if p != "__init__"]
    return ".".join([package, *parts])


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _env_violations(tree: ast.AST) -> list[str]:
    """Env reads must be literal keys from ALLOWED_TASK_ENV_KEYS."""
    problems: list[str] = []

    def is_os_environ(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )

    for node in ast.walk(tree):
        key_node = None
        if isinstance(node, ast.Subscript) and is_os_environ(node.value):
            key_node = node.slice
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get" and is_os_environ(node.func.value):
                key_node = node.args[0] if node.args else None
            elif (
                node.func.attr == "getenv"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                key_node = node.args[0] if node.args else None
            else:
                continue
        elif is_os_environ(node):
            # Bare os.environ (iteration, copy, items()) is caught by the
            # parent check below; skip the attribute node itself.
            continue
        else:
            continue
        if not (isinstance(key_node, ast.Constant) and key_node.value in ALLOWED_TASK_ENV_KEYS):
            problems.append(ast.unparse(node))

    # Any use of os.environ other than a literal-key read (e.g. dict(os.environ)).
    allowed_parents: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and is_os_environ(node.value):
            allowed_parents.add(id(node.value))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and is_os_environ(node.func.value)
        ):
            allowed_parents.add(id(node.func.value))
    for node in ast.walk(tree):
        if is_os_environ(node) and id(node) not in allowed_parents:
            problems.append("os.environ (non-literal use)")
    return problems


def check_task_module(source: str) -> list[str]:
    tree = ast.parse(source)
    problems = [
        f"forbidden import {name}"
        for name in sorted(_imports(tree))
        if name.split(".")[0] in FORBIDDEN_IN_TASKS
    ]
    problems += [f"env access {expr}" for expr in _env_violations(tree)]
    return problems


def _py_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


# ---------------------------------------------------------------- checker self-tests
# The checker itself must be shown to catch violations; otherwise a passing
# run over real code proves nothing.


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess",
        "from socket import create_connection",
        "import msal",
        "from clw.broker import credentials",
        "import clw",
        "import os\nos.environ['CLW_PROFILE_DIRREAD_CLIENT_ID']",
        "import os\nos.environ.get('HOME')",
        "import os\nos.getenv('AZURE_CLIENT_SECRET')",
        "import os\nk = 'CLW_RUN_TOKEN'\nos.environ[k]",
        "import os\nsecrets = dict(os.environ)",
    ],
)
def test_checker_flags_violations(source):
    assert check_task_module(source), source


@pytest.mark.parametrize(
    "source",
    [
        "import httpx\nimport json",
        "import os\nos.environ['CLW_RUN_TOKEN']",
        "import os\nos.environ.get('CLW_BROKER_URL')",
        "import os\nos.getenv('CLW_RUN_TOKEN')",
    ],
)
def test_checker_allows_permitted_code(source):
    assert check_task_module(source) == []


# ---------------------------------------------------------------- real tree checks


def test_layout_exists():
    for pkg in (SRC, TASK_SDK, TASKS):
        assert (pkg / "__init__.py").is_file(), f"missing package {pkg}"


def test_task_code_has_no_forbidden_imports_or_env_access():
    problems = {}
    for path in _py_files(TASK_SDK) + _py_files(TASKS):
        found = check_task_module(path.read_text(encoding="utf-8"))
        if found:
            problems[str(path.relative_to(REPO))] = found
    assert problems == {}


def test_api_imports_only_catalog_modules_from_broker():
    bad = {}
    api = SRC / "api"
    for path in _py_files(api) if api.exists() else []:
        names = _imports(ast.parse(path.read_text(encoding="utf-8")))
        broker = {
            n for n in names
            if n.startswith("clw.broker") and n != "clw.broker"
            and not any(n == a or n.startswith(a + ".") for a in API_MAY_IMPORT_FROM_BROKER)
        }
        if broker:
            bad[str(path.relative_to(REPO))] = sorted(broker)
    assert bad == {}


def test_only_credentials_module_imports_msal():
    bad = []
    for path in _py_files(SRC):
        mod = _module_name(path, SRC, "clw")
        names = _imports(ast.parse(path.read_text(encoding="utf-8")))
        if any(n.split(".")[0] == "msal" for n in names) and mod not in MSAL_IMPORTERS:
            bad.append(mod)
    assert bad == []


def test_only_transport_names_graph_host():
    bad = []
    for path in _py_files(SRC):
        mod = _module_name(path, SRC, "clw")
        if GRAPH_HOST in path.read_text(encoding="utf-8") and mod not in GRAPH_HOST_OWNERS:
            bad.append(mod)
    assert bad == []
