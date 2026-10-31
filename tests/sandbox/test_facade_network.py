"""The facade's network separation, by attempt on a real Docker daemon (SD-041).

The shape of docker-compose.yml (checked statically by
tests/unit/test_compose_topology.py), with throwaway networks:

  scriptnet  internal   a script's task container; the proxy (alias graph.microsoft.com)
  facadenet  internal   the proxy; the broker
  egress     bridge     the broker

Docker's DNS answers a container's lookup from every network it is attached
to, so this checks every reachability property the design relies on:

  - the task resolves graph.microsoft.com to the proxy;
  - the broker never does (its own Graph lookups must reach Microsoft);
  - the proxy has no egress: no external name resolves, no outside address
    is reachable;
  - the task cannot reach the broker except through the proxy: the broker's
    name does not resolve and its address is unreachable from scriptnet.

The task container is set up as the runner sets it up (SD-044): the proxy's
address comes from the runner's lookup (DockerBackend.peer_address) into its
hosts file, and it alone takes the runtime under test (CLW_TASK_RUNTIME). The
proxy and the broker are compose services, under Docker's default runtime.
"""

from __future__ import annotations

import uuid

import pytest

from clw.runner.backend import DockerBackend
from tests.sandbox_support import RUNTIME

pytestmark = pytest.mark.sandbox

IMAGE = "python:3.11-slim"


def _py(code: str) -> list[str]:
    return ["python", "-c", code]


RESOLVE_GRAPH = _py("import socket\ntry: print(socket.gethostbyname('graph.microsoft.com'))\n"
                    "except OSError: print('unresolved')")


def _reach(host: str, port: int) -> list[str]:
    return _py("import socket\ns=socket.socket(); s.settimeout(3)\n"
               f"try:\n    s.connect(({host!r}, {port})); print('reached')\nexcept OSError as e: print('blocked', type(e).__name__)")


def _resolve(name: str) -> list[str]:
    return _py(f"import socket\ntry: print(socket.gethostbyname({name!r}))\nexcept OSError: print('unresolved')")


@pytest.fixture(scope="module")
def topology(client):
    suffix = uuid.uuid4().hex[:8]
    networks, containers = [], []
    try:
        client.images.get(IMAGE)
    except Exception:  # noqa: BLE001 - not present (a fresh CI runner): create() does not pull
        client.images.pull(IMAGE)
    try:
        scriptnet = client.networks.create(f"clw_net_scriptnet_{suffix}", internal=True)
        facadenet = client.networks.create(f"clw_net_facadenet_{suffix}", internal=True)
        egress = client.networks.create(f"clw_net_egress_{suffix}")
        networks += [scriptnet, facadenet, egress]

        def start(name, command, first, *more, aliases=None, **options):
            box = client.containers.create(IMAGE, command, name=f"{name}-{suffix}", network=first.name, **options)
            containers.append(box)
            if aliases:
                first.disconnect(box)
                first.connect(box, aliases=aliases)
            for net in more:
                net.connect(box)
            box.start()
            box.reload()
            return box

        proxy = start("clw-net-proxy", ["sleep", "300"], scriptnet, facadenet, aliases=["graph.microsoft.com"])
        broker = start("clw-net-broker", ["python", "-m", "http.server", "8080"], facadenet, egress)
        peer = DockerBackend(client).peer_address(scriptnet.name, "graph.microsoft.com")
        assert peer is not None
        task = start("clw-net-task", ["sleep", "300"], scriptnet, extra_hosts={"graph.microsoft.com": peer},
                     **({"runtime": RUNTIME} if RUNTIME else {}))
        yield {"proxy": proxy, "broker": broker, "task": task, "facadenet": facadenet.name,
               "broker_name": f"clw-net-broker-{suffix}"}
    finally:
        for box in containers:
            try:
                box.remove(force=True)
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        for net in networks:
            try:
                net.remove()
            except Exception:  # noqa: BLE001
                pass


def _run(box, command) -> str:
    code, output = box.exec_run(command)
    return output.decode().strip()


def _ips(box) -> set[str]:
    return {cfg["IPAddress"] for cfg in box.attrs["NetworkSettings"]["Networks"].values()}


def test_the_task_resolves_graph_to_the_proxy(topology):
    assert _run(topology["task"], RESOLVE_GRAPH) in _ips(topology["proxy"])


def test_the_broker_never_resolves_graph_to_the_proxy(topology):
    assert _run(topology["broker"], RESOLVE_GRAPH) not in _ips(topology["proxy"])


@pytest.mark.parametrize("command", [_resolve("example.com"), _reach("1.1.1.1", 443), _reach("8.8.8.8", 53)])
def test_the_proxy_has_no_egress(topology, command):
    outcome = _run(topology["proxy"], command)
    assert outcome == "unresolved" or outcome.startswith("blocked"), outcome


def test_the_task_cannot_resolve_the_broker(topology):
    assert _run(topology["task"], _resolve(topology["broker_name"])) == "unresolved"


def test_the_task_cannot_reach_the_brokers_address(topology):
    broker_ip = topology["broker"].attrs["NetworkSettings"]["Networks"][topology["facadenet"]]["IPAddress"]
    assert _run(topology["task"], _reach(broker_ip, 8080)).startswith("blocked")


def test_the_proxy_can_reach_the_broker(topology):
    # The control: the only way from the task's side to the broker exists.
    assert _run(topology["proxy"], _reach(topology["broker_name"], 8080)) == "reached"
