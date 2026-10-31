"""The runner's task catalog (Task 14).

Every tasks/<dir>/manifest.yaml, keyed by manifest id. A task is runnable
only if its directory is the module its id names (dormant-account-investigation
→ tasks/dormant_account_investigation) and holds task.py, so the command
the runner builds always names a task that exists in the image. Anything
else stops the runner (fail closed), as for the broker's catalog.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from clw.broker.manifest import TaskManifest, load_manifest
from clw.runner.sandbox_spec import task_module

TASKS_DIR = Path(__file__).resolve().parents[3] / "tasks"


def load_task_catalog(tasks_dir: Path = TASKS_DIR) -> Mapping[str, TaskManifest]:
    catalog: dict[str, TaskManifest] = {}
    for path in sorted(Path(tasks_dir).glob("*/manifest.yaml")):
        manifest = load_manifest(path)
        if path.parent.name != task_module(manifest.id) or not (path.parent / "task.py").is_file():
            raise RuntimeError(f"task {path.parent.name}: directory must be the module its id names, with task.py")
        if manifest.id in catalog:
            raise RuntimeError(f"duplicate task id in {path.parent.name}")
        catalog[manifest.id] = manifest
    return MappingProxyType(catalog)
