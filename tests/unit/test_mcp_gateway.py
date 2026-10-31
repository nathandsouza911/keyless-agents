"""The MCP gateway (v0.1; SD-052): the agent-facing endpoint is credential-less.

It may not import the database, the credential provider, the transport or
msal, and it reaches the broker only at the URL it is configured with.
These are hygiene checks on trusted code (SD-008); the enforcing boundary is
that the gateway holds nothing worth stealing and the broker decides.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

GATEWAY = Path(__file__).resolve().parents[2] / "src" / "clw" / "mcp_gateway"
FORBIDDEN = ("clw.db", "clw.broker", "clw.auth", "clw.audit", "clw.crypto", "msal", "sqlalchemy", "asyncpg", "redis",
             "docker", "subprocess")


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


@pytest.mark.parametrize("path", sorted(GATEWAY.glob("*.py")), ids=lambda p: p.name)
def test_the_gateway_imports_nothing_that_holds_or_reaches_a_credential(path):
    bad = {name for name in _imports(path) for prefix in FORBIDDEN if name == prefix or name.startswith(prefix + ".")}
    assert not bad


def test_the_gateway_never_names_the_graph_host():
    for path in GATEWAY.glob("*.py"):
        assert "graph.microsoft.com" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("url", ["", "broker:8080", "ftp://broker", "http://broker:8080/v1", "http://broker/",
                                 "http://user@broker:8080"])
def test_a_malformed_broker_url_stops_the_gateway(monkeypatch, url):
    from clw.mcp_gateway.app import broker_url

    monkeypatch.setenv("CLW_MCP_BROKER_URL", url)
    with pytest.raises(RuntimeError):
        broker_url()


def test_a_well_formed_broker_url_is_accepted(monkeypatch):
    from clw.mcp_gateway.app import broker_url

    monkeypatch.setenv("CLW_MCP_BROKER_URL", "http://broker:8080")
    assert broker_url() == "http://broker:8080"
