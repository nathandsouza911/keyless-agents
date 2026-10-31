"""The API's task catalog (Task 16).

Every tasks/<dir>/manifest.yaml, keyed by manifest id, loaded through the
strict manifest loader (clw.broker.manifest, one of the three broker modules
the API may import). A manifest that fails to load stops the API (fail
closed), as it stops the broker and the runner. The API uses the catalog
only to show the task list and the manifest view and to bind a new run to
the task's manifest and profile; it never builds or sends a Graph request.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from clw.broker.manifest import TaskManifest, load_manifest

TASKS_DIR = Path(__file__).resolve().parents[3] / "tasks"
# Agent profiles (SD-049): what an AI agent's session may call, chosen by a
# person when the session starts. Same manifest format and loader.
AGENT_PROFILES_DIR = Path(__file__).resolve().parents[3] / "agent_profiles"


def load_api_catalog(tasks_dir: Path = TASKS_DIR) -> Mapping[str, TaskManifest]:
    catalog: dict[str, TaskManifest] = {}
    for path in sorted(Path(tasks_dir).glob("*/manifest.yaml")):
        manifest = load_manifest(path)
        if manifest.id in catalog:
            raise RuntimeError(f"duplicate task id in {path.parent.name}")
        catalog[manifest.id] = manifest
    return MappingProxyType(catalog)


def load_agent_catalog(agent_dir: Path = AGENT_PROFILES_DIR) -> Mapping[str, TaskManifest]:
    return load_api_catalog(agent_dir)
