"""The task container's configuration (Task 14; SD-008; threat-model §7.1).

sandbox_container_kwargs() is pure: it turns a run, its token, the run's
manifest and the runner's own configuration into keyword arguments for the
Docker SDK's containers.run(). Nothing in it comes from a caller other than
the run row, and from the row only the task id (which selects the manifest
and the module) and the params (validated against the manifest and
rendered as integers):

  command   python -m tasks.<task>.task --<param> <int> ...  (the module
            follows from the task id; argument names from the manifest)
  env       exactly CLW_RUN_TOKEN and CLW_BROKER_URL
  network   clw_tasknet only (internal: true; the broker is the only peer)
  root fs   read-only; /tmp is a 16 MiB noexec tmpfs
  user      10001:10001, all capabilities dropped, no-new-privileges
  limits    256 MiB memory (no swap), 0.5 CPU, 64 PIDs and RLIMIT_NPROC 64
and no volumes, mounts, devices, privileges, port bindings or Docker socket.
The image, broker URL and network are the runner's configuration, never
the run's.

script_container_kwargs() is the script-run variant (SD-044): the same
hardening, with

  command   /clw/bootstrap.ps1 <script_sha256> <bootstrap_sha256> (the
            image's entry point); the script itself arrives on stdin
  env       exactly CLW_RUN_TOKEN and CLW_BROKER_URL (the runner's
            CLW_SCRIPT_BROKER_URL: the Graph host's https URL, which is the
            facade on the script network)
  network   clw_scriptnet only (internal: true; its only peer is the facade
            proxy, which holds the Graph host's name there)
  user      10006:10006
  limits    512 MiB memory (no swap), 1 CPU, 64 PIDs and RLIMIT_NPROC 64

Both take the runner's container runtime (CLW_TASK_RUNTIME, for example
runsc for gVisor); without one, Docker's default.

Both also take `peer`: the address of the one container the task may reach
(the broker on clw_tasknet, the facade proxy on clw_scriptnet), which the
runner looks up at launch. It goes into the container's hosts file under
the host name of the configured broker URL, so the name resolves without
Docker's network DNS, which gVisor's network stack cannot reach (Kali,
2026-10-26; SD-044). Other names still do not resolve.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from clw.broker.manifest import TaskManifest

TASK_NETWORK = "clw_tasknet"
TASK_USER = "10001:10001"
TASK_ENV_KEYS = frozenset({"CLW_RUN_TOKEN", "CLW_BROKER_URL"})
MAX_RESULT_BYTES = 5 * 1024 * 1024
SCRIPT_NETWORK = "clw_scriptnet"
SCRIPT_USER = "10006:10006"
MAX_SCRIPT_OUTPUT_BYTES = 1024 * 1024
SCRIPT_TIMEOUT_SECONDS = 600  # script manifests carry no timeout; this is the runner's
BOOTSTRAP = Path(__file__).resolve().parents[3] / "task_pwsh" / "bootstrap.ps1"
# Under gVisor the container's threads live inside the sandbox, so Docker's
# PID limit does not bound them; RLIMIT_NPROC does (Kali, 2026-10-26: stopped
# at 63 threads). Under runc it counts that user's processes on the host: one
# container per user at a time (each container kind has its own uid).
NPROC_ULIMIT = {"Name": "nproc", "Soft": 64, "Hard": 64}
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_BROKER_URL = re.compile(r"https?://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?\Z")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]{1,128})?(?:@sha256:[0-9a-f]{64})?\Z")
_TASK_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class InvalidRunParams(ValueError):
    """The run's params do not satisfy its manifest. The message has no values."""


def _check_runtime(runtime: object) -> None:
    if runtime is not None and not (isinstance(runtime, str) and _RUNTIME.match(runtime)):
        raise ValueError("container runtime must be a plain name")


@dataclass(frozen=True, slots=True)
class SandboxConfig:
    image: str
    broker_url: str
    runtime: str | None = None

    def __post_init__(self) -> None:
        if not (isinstance(self.image, str) and _IMAGE.match(self.image)):
            raise ValueError("task image must be a plain image reference")
        if not (isinstance(self.broker_url, str) and _BROKER_URL.match(self.broker_url)):
            raise ValueError("broker URL must be http(s)://host[:port] with nothing else")
        _check_runtime(self.runtime)


@dataclass(frozen=True, slots=True)
class ScriptSandboxConfig:
    image: str
    broker_url: str   # the Graph host's https URL: the facade, as the script sees it
    runtime: str | None = None

    def __post_init__(self) -> None:
        if not (isinstance(self.image, str) and _IMAGE.match(self.image)):
            raise ValueError("script image must be a plain image reference")
        if not (isinstance(self.broker_url, str) and self.broker_url.startswith("https://")
                and _BROKER_URL.match(self.broker_url)):
            raise ValueError("script broker URL must be https://host[:port] with nothing else")
        _check_runtime(self.runtime)


def peer_host(broker_url: str) -> str:
    """The host name in a validated broker URL (http(s)://host[:port])."""
    return urlsplit(broker_url).hostname


def _hosts(broker_url: str, peer: object) -> dict[str, str]:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        raise ValueError("peer must be an IP address") from None
    return {peer_host(broker_url): str(address)}


def bootstrap_sha256(path: Path = BOOTSTRAP) -> str:
    """The digest of the bootstrap the image must run (recorded in RUN_STARTED;
    the bootstrap refuses to run if its own file differs)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def task_module(task_id: str) -> str:
    if not (isinstance(task_id, str) and _TASK_ID.match(task_id)):
        raise ValueError("task id is not a plain name")
    return task_id.replace("-", "_")


def task_arguments(manifest: TaskManifest, params: object) -> list[str]:
    """`--name value` for every manifest param, from the run's params or the
    default. Unknown keys, missing required values, non-integers (bool
    included) and out-of-range values are refused."""
    if not isinstance(params, Mapping):
        raise InvalidRunParams("params must be an object")
    unknown = set(params) - set(manifest.params)
    if unknown:
        raise InvalidRunParams(f"unknown params: {len(unknown)}")
    argv: list[str] = []
    for name, spec in manifest.params.items():
        value = params.get(name, spec.default)
        if type(value) is not int:
            raise InvalidRunParams(f"param {name} must be an integer")
        if not spec.minimum <= value <= spec.maximum:
            raise InvalidRunParams(f"param {name} is out of range")
        argv += [f"--{name.replace('_', '-')}", str(value)]
    return argv


def sandbox_container_kwargs(run: object, token: str, *, manifest: TaskManifest, config: SandboxConfig,
                             peer: str) -> dict:
    task_id = getattr(run, "task_id", None)
    if task_id != manifest.id:
        raise ValueError("the manifest is not the run's")
    if not (isinstance(token, str) and _TOKEN.match(token)):
        raise ValueError("run token has the wrong shape")
    run_id = str(getattr(run, "id"))
    command = ["python", "-m", f"tasks.{task_module(task_id)}.task", *task_arguments(manifest, run.params)]
    return {
        "image": config.image,
        "command": command,
        "environment": {"CLW_RUN_TOKEN": token, "CLW_BROKER_URL": config.broker_url},
        "network": TASK_NETWORK,
        "extra_hosts": _hosts(config.broker_url, peer),
        "name": f"clw-task-{run_id}",
        "labels": {"clw.run_id": run_id, "clw.task_id": task_id},
        "detach": True,
        "read_only": True,
        "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
        "user": TASK_USER,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "pids_limit": 64,
        "ulimits": [NPROC_ULIMIT],
        "mem_limit": "256m",
        "memswap_limit": "256m",
        "nano_cpus": 500_000_000,
        "log_config": {"type": "json-file", "config": {"max-size": "8m", "max-file": "1"}},
        **({"runtime": config.runtime} if config.runtime else {}),
    }


def script_container_kwargs(run: object, token: str, *, script_sha256: str, bootstrap: str,
                            config: ScriptSandboxConfig, peer: str) -> dict:
    if getattr(run, "kind", None) != "script":
        raise ValueError("not a script run")
    if not (isinstance(token, str) and _TOKEN.match(token)):
        raise ValueError("run token has the wrong shape")
    for digest in (script_sha256, bootstrap):
        if not (isinstance(digest, str) and _HEX64.match(digest)):
            raise ValueError("digest has the wrong shape")
    run_id = str(getattr(run, "id"))
    return {
        "image": config.image,
        "command": [script_sha256, bootstrap],
        "stdin_open": True,   # the script arrives on stdin, once (DockerBackend.start)
        "environment": {"CLW_RUN_TOKEN": token, "CLW_BROKER_URL": config.broker_url},
        "network": SCRIPT_NETWORK,
        "extra_hosts": _hosts(config.broker_url, peer),
        "name": f"clw-task-{run_id}",
        "labels": {"clw.run_id": run_id, "clw.task_id": "script"},
        "detach": True,
        "read_only": True,
        "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
        "user": SCRIPT_USER,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "pids_limit": 64,
        "ulimits": [NPROC_ULIMIT],
        "mem_limit": "512m",
        "memswap_limit": "512m",
        "nano_cpus": 1_000_000_000,
        "log_config": {"type": "json-file", "config": {"max-size": "2m", "max-file": "1"}},
        **({"runtime": config.runtime} if config.runtime else {}),
    }
