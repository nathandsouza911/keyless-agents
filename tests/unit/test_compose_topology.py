"""docker-compose.yml keeps the facade's network separation (SD-041): only the
credential-less proxy carries the graph.microsoft.com alias, on a network the
broker is not on."""

from __future__ import annotations

from pathlib import Path

import yaml

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]


def _networks(service: str) -> dict:
    networks = SERVICES[service].get("networks", {})
    return {name: {} for name in networks} if isinstance(networks, list) else {k: v or {} for k, v in networks.items()}


def test_only_the_proxy_holds_the_graph_alias_and_only_on_scriptnet():
    holders = [(svc, net) for svc in SERVICES for net, cfg in _networks(svc).items()
               if "graph.microsoft.com" in (cfg.get("aliases") or [])]
    assert holders == [("facade-proxy", "scriptnet")]


def test_the_broker_is_on_no_network_that_carries_the_alias():
    assert "scriptnet" not in _networks("broker") and "facadenet" in _networks("broker")


def test_the_proxy_reaches_only_scriptnet_and_facadenet():
    assert set(_networks("facade-proxy")) == {"scriptnet", "facadenet"}


def test_the_proxy_holds_no_credential_and_no_docker_socket():
    proxy = SERVICES["facade-proxy"]
    assert set(proxy.get("environment", {})) == {"CLW_FACADE_BROKER_URL"}
    mounts = proxy.get("volumes", [])
    assert all(m.endswith((":/run/secrets/facade/leaf.crt:ro", ":/run/secrets/facade/leaf.key:ro")) for m in mounts)
    assert proxy["read_only"] is True and proxy["cap_drop"] == ["ALL"]


def test_the_task_networks_are_internal():
    networks = COMPOSE["networks"]
    assert all(networks[n].get("internal") is True for n in ("tasknet", "scriptnet", "facadenet"))


def test_the_proxy_image_carries_no_profiles_tasks_or_secrets():
    dockerfile = (Path(__file__).resolve().parents[2] / "docker" / "facade-proxy.Dockerfile").read_text(encoding="utf-8")
    copies = [line for line in dockerfile.splitlines() if line.strip().upper().startswith(("COPY", "ADD"))]
    assert not any(word in line for line in copies for word in ("profiles", "tasks", "secrets", ".pem", ".key"))


# --- The MCP gateway (v0.1; SD-052) -----------------------------------------
# The agent-facing MCP endpoint holds no credential, no database access and no
# Graph route of its own: it reaches only the broker, over mcpnet (internal).
# Docker publishes ports only from a non-internal network, so its published
# port is on mcpfront, a network no other service joins.

def test_the_gateway_reaches_only_mcpnet_and_mcpfront():
    assert set(_networks("mcp-gateway")) == {"mcpnet", "mcpfront"}
    assert COMPOSE["networks"]["mcpnet"].get("internal") is True


def test_only_the_gateway_and_the_broker_are_on_mcpnet_and_only_the_gateway_on_mcpfront():
    assert {svc for svc in SERVICES if "mcpnet" in _networks(svc)} == {"mcp-gateway", "broker"}
    assert {svc for svc in SERVICES if "mcpfront" in _networks(svc)} == {"mcp-gateway"}


def test_the_gateway_holds_no_credential_volume_or_socket():
    gateway = SERVICES["mcp-gateway"]
    assert set(gateway.get("environment", {})) == {"CLW_MCP_BROKER_URL", "CLW_MCP_PUBLIC_URL"}
    assert not gateway.get("volumes")
    assert gateway["read_only"] is True and gateway["cap_drop"] == ["ALL"]
    assert gateway["security_opt"] == ["no-new-privileges:true"]


def test_the_gateway_publishes_on_loopback_only():
    assert all(str(port).startswith("127.0.0.1:") for port in SERVICES["mcp-gateway"]["ports"])


def test_the_gateway_image_carries_no_profiles_tasks_or_secrets():
    dockerfile = (Path(__file__).resolve().parents[2] / "docker" / "mcp-gateway.Dockerfile").read_text(encoding="utf-8")
    copies = [line for line in dockerfile.splitlines() if line.strip().upper().startswith(("COPY", "ADD"))]
    assert not any(word in line for line in copies for word in ("profiles", "tasks", "secrets", ".pem", ".key"))
    assert "USER " in dockerfile
