"""Escape-attempt probe (Task 15; test-only, never shipped).

This task runs INSIDE the sandbox container and deliberately tries to do the
things the sandbox must prevent, then prints one JSON report line so the
sandbox tests can assert every attempt failed. It is the opposite of a real
task: it is built only into the test image `clw-task-probe` (docker/
task-probe.Dockerfile), never into the shipped `clw-task` image, and it lives
under tests/fixtures/, so the import-boundary check (which scans task_sdk/
and tasks/ in the source tree) never sees it. That is why it may import
socket and subprocess, which a real task may not.

Modes:
  --attempts        run every escape attempt and print `CLW_PROBE <json>`
  --sleep-seconds N sleep N seconds (for the timeout test; it is killed first)

Each attempt is wrapped so one failure cannot abort the report; the outcome
of every attempt, success or failure, is recorded as data.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

# Variable names that would carry a secret if the sandbox ever leaked one.
SECRET_ENV = (
    "CLW_PROFILE_DIRREAD_CLIENT_ID", "CLW_PROFILE_DIRREAD_CERT_PATH", "CLW_PROFILE_DIRREAD_CERT_THUMBPRINT",
    "DATABASE_URL", "CLW_BROKER_DATABASE_URL", "CLW_RUNNER_DATABASE_URL", "CLW_SESSION_SIGNING_KEY",
    "CLW_FERNET_KEYS", "AZURE_CLIENT_SECRET", "MICROSOFT_CLIENT_SECRET",
)
# Files that exist only inside the broker, never the task container.
SECRET_PATHS = (
    "/run/secrets/profiles/directory-read-auditlog-read.pem",
    "/run/secrets", "/srv/profiles", "/var/run/docker.sock",
)


def _try(fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - every outcome is recorded as data
        return {"error": type(exc).__name__, "detail": str(exc)[:200],
                "errno": getattr(exc, "errno", None)}


def _broker_endpoint() -> tuple[str, int]:
    parts = urlsplit(os.environ.get("CLW_BROKER_URL", ""))
    return parts.hostname or "broker", parts.port or 8080


def _tcp(host: str, port: int, timeout: float = 5.0) -> dict:
    def go():
        with socket.create_connection((host, port), timeout=timeout):
            return {"connected": True}
    return _try(go)


def _dns(host: str) -> dict:
    def go():
        return {"resolved": True, "addrinfo": str(socket.getaddrinfo(host, 443)[0][4])}
    return _try(go)


def _curl(url: str) -> dict:
    def go():
        proc = subprocess.run(["curl", "-sS", "--max-time", "5", url],
                              capture_output=True, text=True, timeout=15)
        return {"available": True, "exit_code": proc.returncode, "stderr": proc.stderr[:200]}
    return _try(go)


def _rootfs_write() -> dict:
    def go():
        # In a directory the task user owns (task-probe.Dockerfile), so only a
        # read-only root can refuse it: EROFS, never a permission error.
        path = "/probe-owned/clw_probe_rootfs_test"
        with open(path, "w") as handle:
            handle.write("x")
        os.unlink(path)
        return {"wrote": True}  # should never happen
    result = _try(go)
    if isinstance(result, dict) and result.get("errno") == errno.EROFS:
        result["is_erofs"] = True
    return result


def _tmp_write() -> dict:
    def go():
        with open("/tmp/clw_probe_tmp", "w") as handle:
            handle.write("x")
        return {"writable": True}
    return _try(go)


def _tmp_noexec() -> dict:
    # /tmp is a noexec tmpfs: a script written there cannot be executed.
    def go():
        path = "/tmp/clw_probe_exec.sh"
        with open(path, "w") as handle:
            handle.write("#!/bin/sh\necho ran\n")
        os.chmod(path, 0o755)
        proc = subprocess.run([path], capture_output=True, text=True, timeout=5)
        return {"executed": True, "exit_code": proc.returncode}  # should not happen
    return _try(go)


def _raw_socket() -> dict:
    # A raw socket needs CAP_NET_RAW, which cap_drop=[ALL] removes. (A low-port
    # bind is NOT a reliable capability probe: many runtimes set
    # net.ipv4.ip_unprivileged_port_start=0, so binding port 80 needs no
    # capability. Raw sockets always require CAP_NET_RAW.)
    def go():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.close()
        return {"created": True}  # should never happen with caps dropped
    return _try(go)


def _setuid_root() -> dict:
    # Becoming root needs CAP_SETUID; without it, and with no-new-privileges,
    # a non-root task cannot escalate.
    def go():
        os.setuid(0)
        return {"became_root": True, "uid": os.getuid()}  # should never happen
    return _try(go)


def _proc_scan() -> dict:
    pids, cmdlines = [], []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pids.append(int(name))
        try:
            with open(f"/proc/{name}/cmdline", "rb") as handle:
                cmdlines.append(handle.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip())
        except OSError:
            pass
    joined = " ".join(cmdlines).lower()
    broker_markers = ("uvicorn", "clw.broker", "create_production_app", "postgres", "redis-server")
    return {"pid_count": len(pids), "cmdlines": cmdlines[:20],
            "broker_seen": any(marker in joined for marker in broker_markers)}


def _pids_limit(target: int = 300) -> dict:
    stop = threading.Event()
    threads: list[threading.Thread] = []
    started, error = 0, None
    try:
        for _ in range(target):
            thread = threading.Thread(target=stop.wait)
            thread.start()
            threads.append(thread)
            started += 1
    except RuntimeError as exc:
        error = str(exc)[:120]
    finally:
        stop.set()
        for thread in threads:
            thread.join()
    return {"threads_started": started, "target": target, "hit_limit": started < target, "error": error}


def run_attempts() -> dict:
    broker_host, broker_port = _broker_endpoint()
    present_secrets = [name for name in SECRET_ENV if name in os.environ]
    found_paths = [path for path in SECRET_PATHS if os.path.exists(path)]
    run_secrets = {}
    if os.path.isdir("/run/secrets"):
        run_secrets = _try(lambda: {"entries": os.listdir("/run/secrets")})
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "connect": {
            "broker": _tcp(broker_host, broker_port),
            "graph_dns": _dns("graph.microsoft.com"),
            "graph_tcp": _tcp("graph.microsoft.com", 443),
            "raw_ip": _tcp("1.1.1.1", 443),
        },
        "env": {"keys": sorted(os.environ), "secrets_present": present_secrets},
        "secrets": {"paths_found": found_paths, "run_secrets": run_secrets},
        "proc": _proc_scan(),
        "subprocess_curl": {"graph": _curl("https://graph.microsoft.com/v1.0/users"),
                            "raw_ip": _curl("https://1.1.1.1/")},
        "rootfs": _rootfs_write(),
        "tmp": _tmp_write(),
        "tmp_noexec": _tmp_noexec(),
        "cap_net_raw": _raw_socket(),
        "setuid_root": _setuid_root(),
        "pids": _pids_limit(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--attempts", action="store_true")
    parser.add_argument("--sleep-seconds", type=int, default=None)
    args, _ = parser.parse_known_args(argv)
    if args.sleep_seconds is not None:
        time.sleep(args.sleep_seconds)
        print("CLW_PROBE " + json.dumps({"slept": args.sleep_seconds}))
        return 0
    if args.attempts:
        print("CLW_PROBE " + json.dumps(run_attempts()), flush=True)
        return 0
    print("escape_probe: pass --attempts or --sleep-seconds N", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
