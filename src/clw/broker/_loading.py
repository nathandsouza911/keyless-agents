"""Strict YAML reading shared by the manifest and profile loaders (Task 8).

safe_load semantics (no Python tags), plus: a size cap, UTF-8 only, no
duplicate keys (PyYAML would keep the last one silently, so a reviewer
could read a different value from the one loaded), no aliases, string keys
only, and a mapping at the top. Errors name the file, a line or a field
location, never a value from the file.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

MAX_FILE_BYTES = 64 * 1024

M = TypeVar("M", bound=BaseModel)


class ManifestError(Exception):
    """A manifest or profile that must not be used. The message never
    contains a value from the file."""


class _Refused(Exception):
    pass


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            raise _Refused(f"YAML alias at line {self.peek_event().start_mark.line + 1} is not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):  # type: ignore[no-untyped-def]
        seen: set[str] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise _Refused(f"non-string key at line {key_node.start_mark.line + 1}")
            if key in seen:
                raise _Refused(f"duplicate key at line {key_node.start_mark.line + 1}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


@dataclass(frozen=True, slots=True)
class LoadedYaml:
    data: dict
    sha256: str  # of the raw bytes, lowercase hex


def read_yaml(path: Path) -> LoadedYaml:
    name = path.name
    problem = None
    raw = b""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        problem = "cannot be read"
    if problem is None and len(raw) > MAX_FILE_BYTES:
        problem = f"is too large (limit {MAX_FILE_BYTES} bytes)"
    data = None
    if problem is None:
        try:
            data = yaml.load(raw.decode("utf-8"), Loader=_StrictLoader)  # noqa: S506 (SafeLoader subclass)
        except UnicodeDecodeError:
            problem = "is not UTF-8"
        except _Refused as exc:
            problem = str(exc)
        except yaml.MarkedYAMLError as exc:
            mark = exc.problem_mark or exc.context_mark
            problem = "is not valid YAML" + (f" (line {mark.line + 1})" if mark else "")
        except yaml.YAMLError:
            problem = "is not valid YAML"
    if problem is None and not isinstance(data, dict):
        problem = "must be a YAML mapping"
    if problem is not None:
        # Raised outside the except blocks so the YAML error (which quotes the
        # file) is not attached as __context__.
        raise ManifestError(f"{name}: {problem}")
    return LoadedYaml(data=data, sha256=hashlib.sha256(raw).hexdigest())  # type: ignore[arg-type]


def validate(model: type[M], data: object, name: str) -> M:
    """model_validate, with errors reduced to field locations and error types."""
    problems = None
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'} ({err['type']})" for err in exc.errors()[:10]
        )
    raise ManifestError(f"{name}: invalid {problems}")
