"""Task result validation (Task 14; SD-014, SD-034).

A task reports its result as its whole stdout: exactly one line,
`CLW_RESULT <json>\\n`, as clw_task_sdk.result.emit_result writes it. The
runner accepts it only from a task that exited 0, and only if:

  - stdout is at most MAX_RESULT_BYTES (5 MiB; the supervisor stops reading
    and kills the task beyond that: result_too_large);
  - it is exactly that one line: no other output before or after it
    (unexpected_output), not empty (result_missing), not two result lines
    (result_duplicate);
  - the JSON is ASCII (the SDK escapes everything else), one object, with no
    duplicate keys, no NaN or infinity, and in the audit's canonical domain:
    no floats, integers within +/-(2**53 - 1), no NUL, at most 16 levels deep
    (result_malformed). These are the values that survive the JSONB round
    trip exactly, so the stored result re-hashes to result_sha256.

result_sha256 is clw.audit.chain.result_sha256: SHA-256 of the canonical
JSON of the parsed object, the same function verify_run_result applies to
the stored `runs.result`.

A script run (SD-044) reports differently: its stdout is the script's own
output (untrusted text, at most MAX_SCRIPT_OUTPUT_BYTES), followed by the
bootstrap's last line `CLW_SCRIPT_EXIT <code>`. parse_script_output stores

  {"kind": "script_output", "script_exit_code": <code>, "output": <text>}

with the text decoded as UTF-8 (undecodable bytes and NUL become U+FFFD,
since neither survives JSONB). The script's exit code is the script's
outcome, not the run's: the run completed. Without the closing line (the
bootstrap did not finish) there is no result: result_missing. A bootstrap
refusal (exit 70, `CLW_BOOTSTRAP_FAILED <reason>`) is BootstrapRefused.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from clw.audit.canonical import CanonicalizationError, canonical_json
from clw.audit.chain import result_sha256
from clw.runner.sandbox_spec import MAX_RESULT_BYTES, MAX_SCRIPT_OUTPUT_BYTES

RESULT_PREFIX = b"CLW_RESULT "
BOOTSTRAP_EXIT_CODE = 70
BOOTSTRAP_REASONS = frozenset({"usage", "bootstrap_mismatch", "script_too_large", "script_digest_mismatch",
                               "no_capability", "connect_failed"})
_SCRIPT_EXIT = re.compile(rb"CLW_SCRIPT_EXIT (0|-?[1-9][0-9]{0,9})\Z")
_BOOTSTRAP_FAILED = re.compile(rb"CLW_BOOTSTRAP_FAILED ([a-z_]{1,32})\n\Z")


class ResultRejected(Exception):
    """The task's output is not an acceptable result. The message is the reason only."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class TaskResult:
    value: dict
    sha256: str


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def parse_result(stdout: bytes) -> TaskResult:
    if not isinstance(stdout, bytes):
        raise ResultRejected("result_malformed")
    if len(stdout) > MAX_RESULT_BYTES:
        raise ResultRejected("result_too_large")
    if not stdout:
        raise ResultRejected("result_missing")
    lines = stdout.split(b"\n")
    if lines[-1] != b"":
        raise ResultRejected("unexpected_output")  # not newline-terminated
    lines = lines[:-1]
    results = [line for line in lines if line.startswith(RESULT_PREFIX)]
    if len(results) > 1:
        raise ResultRejected("result_duplicate")
    if not results:
        raise ResultRejected("result_missing")
    if len(lines) != 1:
        raise ResultRejected("unexpected_output")
    body = results[0][len(RESULT_PREFIX):]
    if b"\r" in body:
        raise ResultRejected("result_malformed")
    try:
        # Non-ASCII fails the decode; NaN, infinity and every other float fail
        # canonical_json, which accepts only the values that re-hash exactly.
        value = json.loads(body.decode("ascii"), object_pairs_hook=_no_duplicates)
        if not isinstance(value, dict):
            raise ValueError("not an object")
        canonical_json(value)
    except (ValueError, CanonicalizationError, RecursionError):
        raise ResultRejected("result_malformed") from None
    return TaskResult(value=value, sha256=result_sha256(value))


class BootstrapRefused(Exception):
    """The bootstrap refused to run the script. `reason` is one of BOOTSTRAP_REASONS."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def bootstrap_refusal(exit_code: int | None, stdout: bytes) -> str | None:
    """The bootstrap's reason, when this is exactly its refusal; else None."""
    if exit_code != BOOTSTRAP_EXIT_CODE or not isinstance(stdout, bytes):
        return None
    m = _BOOTSTRAP_FAILED.match(stdout)
    reason = m.group(1).decode("ascii") if m else None
    return reason if reason in BOOTSTRAP_REASONS else None


def parse_script_output(stdout: bytes) -> TaskResult:
    if not isinstance(stdout, bytes):
        raise ResultRejected("result_malformed")
    if len(stdout) > MAX_SCRIPT_OUTPUT_BYTES:
        raise ResultRejected("result_too_large")
    if not stdout.endswith(b"\n"):
        raise ResultRejected("result_missing")  # the bootstrap did not finish
    body, _, last = stdout[:-1].rpartition(b"\n")
    m = _SCRIPT_EXIT.match(last)
    if m is None:
        raise ResultRejected("result_missing")
    text = body.decode("utf-8", errors="replace").replace("\x00", "�")
    if body:
        text += "\n"
    value = {"kind": "script_output", "script_exit_code": int(m.group(1)), "output": text}
    try:
        canonical_json(value)
    except (CanonicalizationError, RecursionError):  # pragma: no cover - text and a bounded int always are
        raise ResultRejected("result_malformed") from None
    return TaskResult(value=value, sha256=result_sha256(value))
