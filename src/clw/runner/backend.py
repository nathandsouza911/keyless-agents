"""Where task containers run (Task 14).

The launcher talks to a ContainerBackend only; DockerBackend is the real
one. Its calls block, so the launcher runs them in worker threads. The
sandbox tests that exercise it against a Docker daemon are Task 15; the
runner tests use deterministic fakes of this interface.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Protocol


class TaskProcess(Protocol):
    def stdout(self) -> Iterator[bytes]:
        """The task's stdout as it is written; ends when the task exits or is killed."""

    def wait(self) -> int:
        """Block until the task has exited; its exit code."""

    def kill(self) -> None: ...

    def remove(self) -> None: ...


class ContainerBackend(Protocol):
    def start(self, kwargs: dict, stdin: bytes | None = None) -> TaskProcess:
        """Start the container; with `stdin`, those bytes are its whole stdin
        (then end of file), written before this returns."""

    def kill_run(self, run_id: str) -> None:
        """Kill and remove any container left for the run (for the reconciler)."""

    def peer_address(self, network: str, name: str) -> str | None:
        """The address on `network` of the one container known there as `name`;
        None if there is none, or more than one (SD-044)."""

    def analyse(self, kwargs: dict, script: bytes, timeout: float, max_output: int) -> tuple[int, bytes]:
        """Run the analyser container on `script`: (exit code, stdout). TimeoutError if it overruns."""


class _DockerProcess:  # pragma: no cover - needs a Docker daemon (Task 15)
    def __init__(self, container) -> None:
        self._container = container

    def stdout(self) -> Iterator[bytes]:
        return self._container.logs(stdout=True, stderr=False, stream=True, follow=True)

    def wait(self) -> int:
        return int(self._container.wait()["StatusCode"])

    def kill(self) -> None:
        self._container.kill()

    def remove(self) -> None:
        self._container.remove(force=True)


class DockerBackend:  # pragma: no cover - needs a Docker daemon (Task 15)
    def __init__(self, client=None) -> None:
        import docker

        self._client = client or docker.from_env()

    def start(self, kwargs: dict, stdin: bytes | None = None) -> TaskProcess:
        if stdin is None:
            return _DockerProcess(self._client.containers.run(**kwargs))
        container = self._start_with_stdin(kwargs, stdin)
        return _DockerProcess(container)

    def kill_run(self, run_id: str) -> None:
        for container in self._client.containers.list(all=True, filters={"label": f"clw.run_id={run_id}"}):
            container.remove(force=True)

    def peer_address(self, network: str, name: str) -> str | None:
        found = set()
        for container_id, attached in (self._client.networks.get(network).attrs.get("Containers") or {}).items():
            settings = self._client.containers.get(container_id).attrs["NetworkSettings"]["Networks"].get(network) or {}
            names = set(settings.get("Aliases") or ()) | set(settings.get("DNSNames") or ())
            if name in names and attached.get("IPv4Address"):
                found.add(attached["IPv4Address"].split("/")[0])
        return found.pop() if len(found) == 1 else None

    def _start_with_stdin(self, kwargs: dict, data: bytes):
        """Create and start the container with `data` as its whole stdin.
        Nothing is mounted, so a read-only root stays read-only. On failure the
        container is removed and the error raised."""
        # Not detached, with stdin_open: docker-py then sets StdinOnce, so the
        # end of the attached stream is the end of the container's stdin.
        options = {k: v for k, v in kwargs.items() if k != "detach"}
        container = self._client.containers.create(**options)
        try:
            stdin = container.attach_socket(params={"stdin": 1, "stream": 1})
            container.start()
            raw = getattr(stdin, "_sock", stdin)
            try:
                raw.sendall(data)
            finally:
                # On a Unix socket, closing the file wrapper leaves the socket
                # open (the HTTP response still holds it), so half-close it.
                try:
                    raw.shutdown(socket.SHUT_WR)
                except (AttributeError, OSError):
                    pass  # a Windows named pipe has no half-close; closing it ends the stream
                stdin.close()
        except BaseException:
            container.remove(force=True)
            raise
        return container

    def analyse(self, kwargs: dict, script: bytes, timeout: float, max_output: int) -> tuple[int, bytes]:
        """Run the analyser container (SD-043): the script is written to its
        stdin; stdout only, at most `max_output` bytes; killed after `timeout`
        (TimeoutError)."""
        container = self._start_with_stdin(kwargs, script)
        try:
            try:
                status = container.wait(timeout=timeout)
            except Exception as exc:  # requests' ReadTimeout and friends: the analyser overran
                container.kill()
                raise TimeoutError("analysis timed out") from exc
            stdout = container.logs(stdout=True, stderr=False)[: max_output + 1]
            return int(status["StatusCode"]), stdout
        finally:
            container.remove(force=True)
