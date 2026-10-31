"""Per-app runtime wiring and request-parameter validation (Task 16).

The API holds no Graph credentials and builds no Graph request. It needs
only a database session factory, the fail-closed audit writer and the task
catalog; these are set on ``app.state`` by ``create_app`` and read here, so
a test can build an app on its own database and writer without monkeypatching
module globals.

``normalized_params`` validates a run's parameters against its manifest the
same way the runner's ``task_arguments`` does (declared names only; a plain
int, never bool, within the manifest's bounds; the default filled in), and
returns the complete, canonical parameter object stored on the run. The
runner re-validates with ``task_arguments`` when it claims the run, so this
is a fail-fast check for the caller, not the only gate.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.writer import AuditWriter
from clw.broker.manifest import TaskManifest


class ParamsInvalid(ValueError):
    """A run's params do not satisfy its manifest. The message names no value."""


def get_sessionmaker(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.sessionmaker


def get_writer(request: Request) -> AuditWriter:
    return request.app.state.writer


def get_catalog(request: Request) -> Mapping[str, TaskManifest]:
    return request.app.state.catalog


def get_agent_catalog(request: Request) -> Mapping[str, TaskManifest]:
    return request.app.state.agent_catalog


def normalized_params(manifest: TaskManifest, params: Mapping[str, object]) -> dict[str, int]:
    """The run's complete integer params, or ParamsInvalid. Mirrors
    clw.runner.sandbox_spec.task_arguments without building argv."""
    if not isinstance(params, Mapping):
        raise ParamsInvalid("params must be an object")
    unknown = set(params) - set(manifest.params)
    if unknown:
        raise ParamsInvalid(f"unknown params: {len(unknown)}")
    out: dict[str, int] = {}
    for name, spec in manifest.params.items():
        value = params.get(name, spec.default)
        if type(value) is not int:
            raise ParamsInvalid(f"param {name} must be an integer")
        if not spec.minimum <= value <= spec.maximum:
            raise ParamsInvalid(f"param {name} is out of range")
        out[name] = value
    return out
