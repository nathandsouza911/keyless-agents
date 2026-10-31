"""quickstart/compose.yml keeps the quick start isolated and in demo mode (SD-051)."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "quickstart" / "compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]


def _networks(service: str) -> set[str]:
    networks = SERVICES[service].get("networks", [])
    return set(networks if isinstance(networks, list) else networks)


def test_only_the_api_and_the_gateway_publish_ports_and_only_on_loopback():
    published = {name: s["ports"] for name, s in SERVICES.items() if s.get("ports")}
    assert set(published) == {"api", "mcp-gateway"}
    assert all(p.startswith("127.0.0.1:") for ports in published.values() for p in ports)


def test_every_shared_network_is_internal_and_the_front_networks_are_single_service():
    networks = COMPOSE["networks"]
    assert all(networks[n].get("internal") is True for n in ("backend", "graphnet", "mcpnet"))
    assert {s for s in SERVICES if "uifront" in _networks(s)} == {"api"}
    assert {s for s in SERVICES if "mcpfront" in _networks(s)} == {"mcp-gateway"}


def test_only_the_fake_graph_holds_the_graph_host_name_and_only_the_broker_can_reach_it():
    holders = [(name, net) for name, s in SERVICES.items() if isinstance(s.get("networks"), dict)
               for net, cfg in s["networks"].items() if "graph.microsoft.com" in ((cfg or {}).get("aliases") or [])]
    assert holders == [("fake-graph", "graphnet")]
    assert {s for s in SERVICES if "graphnet" in _networks(s)} == {"fake-graph", "broker"}


def test_the_broker_runs_the_demo_factory_with_no_real_credentials():
    broker = SERVICES["broker"]
    assert "clw.demo.broker:create_demo_broker_app" in broker["command"]
    assert not [k for k in broker["environment"] if k.startswith(("CLW_PROFILE_", "MICROSOFT_"))]


def test_the_api_runs_in_demo_mode_never_production_and_without_real_sign_in():
    env = SERVICES["api"]["environment"]
    assert env["CLW_DEMO_MODE"] == "true" and env["ENVIRONMENT"] != "production"
    assert not [k for k in env if k.startswith(("MICROSOFT_", "OIDC_", "CLW_PROFILE_"))]


def test_the_long_running_services_are_hardened():
    for name in ("broker", "api", "mcp-gateway"):
        s = SERVICES[name]
        assert s["read_only"] is True and s["cap_drop"] == ["ALL"] and s["security_opt"] == ["no-new-privileges:true"]


def test_the_gateway_reaches_only_the_broker():
    assert _networks("mcp-gateway") == {"mcpnet", "mcpfront"}
    assert {s for s in SERVICES if "mcpnet" in _networks(s)} == {"mcp-gateway", "broker"}


def test_the_agent_config_reads_the_capability_from_the_environment():
    config = json.loads((ROOT / "quickstart" / ".mcp.json").read_text(encoding="utf-8"))
    server = config["mcpServers"]["cloud-locksmith"]
    assert server["url"] == "http://127.0.0.1:8090/mcp"
    assert server["headers"] == {"Authorization": "Bearer ${CLW_MCP_CAPABILITY}"}
