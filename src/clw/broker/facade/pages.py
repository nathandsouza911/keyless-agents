"""Facade pagination: Graph's nextLinks are validated and kept by the broker (SD-041).

A script never sees Graph's own continuation. For each page Graph returns
with an `@odata.nextLink`:

  - `next_target` accepts the link only if it is the Graph origin plus the approved request's version and path (the path compared without
    case, as Graph may return its own casing), and its query, percent-decoded,
    is exactly the approved options with their approved values (in any order)
    plus one $skiptoken. It returns the broker's own continuation target: the
    approved target plus "&$skiptoken=" (or "?") and the token percent-encoded.
    That is the form the audit chain binds to the approved target (SD-039).
    Any other link stops paging (fail closed).
  - `PageHandles.issue` stores that target under a random handle bound to the
    run and the approved target, usable once, until the run's deadline. The
    response the script gets carries
    <Graph origin>/<version>/<path>?$skiptoken=clw_<handle>.
  - `PageHandles.take` gives a handle back only to the run it was issued for,
    once, before it expires. Unknown, used, expired or foreign handles are
    refused alike.

Handles live in this broker process's memory: if the broker restarts, a
script's next page is refused and the script sees an ordinary Graph error.
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote, unquote

from clw.audit.events import MAX_REQUEST_TARGET_BYTES, target_matches_template
from clw.broker.pagination import GRAPH_ORIGIN, MAX_NEXT_LINK_CHARS, SKIPTOKEN

HANDLE_PREFIX = "clw_"
MAX_HANDLES_PER_RUN = 10_000
_VERSIONS = ("/v1.0", "/beta")


@dataclass(frozen=True, slots=True)
class Continuation:
    run_id: str
    approved_target: str        # the decision's target (no $skiptoken)
    upstream_target: str        # approved target + the broker's $skiptoken continuation
    template: str
    entry_id: str
    headers: tuple[tuple[str, str], ...]
    expires_at: datetime


def _split(target: str) -> tuple[str, str]:
    path, _, query = target.partition("?")
    return path, query


def _pairs(query: str) -> list[tuple[str, str]] | None:
    pairs = []
    for part in query.split("&") if query else []:
        name, sep, value = part.partition("=")
        if not sep:
            return None
        try:
            pairs.append((unquote(name, errors="strict"), unquote(value, errors="strict")))
        except UnicodeDecodeError:
            return None
    return pairs


def next_target(next_link: object, *, approved_target: str, template: str) -> str | None:
    """The broker's continuation target for Graph's nextLink, or None."""
    if not isinstance(next_link, str) or len(next_link) > MAX_NEXT_LINK_CHARS or not next_link.isascii():
        return None
    approved_path, approved_query = _split(approved_target)
    if not next_link.lower().startswith((GRAPH_ORIGIN + approved_path + "?").lower()):
        return None
    pairs = _pairs(next_link[len(GRAPH_ORIGIN) + len(approved_path) + 1:])
    expected = _pairs(approved_query)
    if pairs is None or expected is None:
        return None
    names = [name.lower() for name, _ in pairs]
    if len(set(names)) != len(names) or set(names) != {name for name, _ in expected} | {SKIPTOKEN}:
        return None
    values = {name.lower(): value for name, value in pairs}
    if any(values[name] != value for name, value in expected):
        return None
    token = values[SKIPTOKEN]
    if not token or not all(0x21 <= ord(c) <= 0x7e for c in token):
        return None
    target = f"{approved_target}{'&' if approved_query else '?'}{SKIPTOKEN}={quote(token, safe='')}"
    if len(target.encode()) > MAX_REQUEST_TARGET_BYTES or not target_matches_template(target, template,
                                                                                       versions=_VERSIONS):
        return None
    return target


def rewrite_next_link(body: bytes, *, approved_target: str, handle: str | None) -> bytes:
    """The response body with @odata.nextLink replaced by the facade's handle URL (or removed)."""
    document = json.loads(body)
    if handle is None:
        document.pop("@odata.nextLink", None)
    else:
        path, _ = _split(approved_target)
        document["@odata.nextLink"] = f"{GRAPH_ORIGIN}{path}?{SKIPTOKEN}={handle}"
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class PageHandles:
    def __init__(self) -> None:
        self._handles: dict[str, Continuation] = {}
        self._per_run: dict[str, int] = {}
        self._lock = threading.Lock()

    def issue(self, continuation: Continuation) -> str | None:
        """A new handle, or None if the run already holds too many (paging then stops)."""
        with self._lock:
            if self._per_run.get(continuation.run_id, 0) >= MAX_HANDLES_PER_RUN:
                return None
            handle = HANDLE_PREFIX + secrets.token_urlsafe(24)
            self._handles[handle] = continuation
            self._per_run[continuation.run_id] = self._per_run.get(continuation.run_id, 0) + 1
            return handle

    def take(self, handle: object, *, run_id: str, now: datetime) -> Continuation | None:
        if not isinstance(handle, str) or not handle.startswith(HANDLE_PREFIX):
            return None
        with self._lock:
            continuation = self._handles.get(handle)
            if continuation is None or continuation.run_id != run_id:
                return None  # a foreign handle stays where it is: its own run may still use it
            del self._handles[handle]
        return continuation if now < continuation.expires_at else None

    def drop_run(self, run_id: str) -> None:
        with self._lock:
            for handle in [h for h, c in self._handles.items() if c.run_id == run_id]:
                del self._handles[handle]
            self._per_run.pop(run_id, None)
