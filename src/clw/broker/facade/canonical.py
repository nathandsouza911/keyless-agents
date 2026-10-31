"""Canonical form of a Graph-shaped request from a script run (SD-041).

A script's request reaches the broker as raw text: the method, the request
target exactly as sent (path and query, before any decoding), the request
headers and the body's length. `canonicalize` turns that into a
`FacadeRequest` the policy can evaluate, or refuses it. Nothing here
authorizes anything; it only makes the request unambiguous.

Refused (deny, `reason`):
  method_not_allowed     any method but GET (Phase 1 is read-only)
  body_not_allowed       a GET with a body
  malformed_target       not "/..." , a fragment, control or space characters,
                         an encoded slash or backslash, a "%" left after one
                         decoding (double encoding), an empty, "." or ".."
                         segment (so no "//", no trailing "/"), or too long
  version_not_allowed    not /v1.0 or /beta
  batch_not_allowed      $batch anywhere in the path
  alias_not_allowed      /me (meaningless for app-only access)
  function_not_allowed   a segment with "(" or ")", or "delta" (function calls,
                         delta queries)
  unknown_query_option   a $-word that is not an OData system option this
                         facade knows (it could change the scope of the request)
  unknown_query_parameter any other parameter, garbled ones included
                         ("$<TAB>op"): refused, never silently dropped (D1,
                         owner decision 2026-10-25)
  duplicate_query_option the same option twice
  malformed_query        an undecodable or non-printable option value
A refusal for a parameter carries its name (sanitized: printable, bounded),
never its value, so the script's error and the audit can say which one.

Canonical form: segments lowercased (Graph path segments are not case
sensitive), options keyed by lowercase name, $select items trimmed,
lowercased and de-duplicated, other values trimmed. `target()` renders the
upstream request target: options in a fixed (sorted) order, values
percent-encoded into the audit chain's request-target character set.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import quote, unquote

KNOWN_OPTIONS = frozenset({
    "$select", "$filter", "$top", "$skip", "$count", "$orderby", "$expand", "$search", "$format",
    "$apply", "$compute", "$deltatoken", "$skiptoken",
})
VERSIONS = ("v1.0", "beta")
MAX_TARGET_CHARS = 4096
# Forwarded upstream, by lowercase name, with the only value accepted.
FORWARDED_HEADERS = {"consistencylevel": ("ConsistencyLevel", "eventual")}

_ODATA_WORD = re.compile(r"\$[A-Za-z]+\Z")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_ENCODED_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)
_PRINTABLE = re.compile(r"[\x20-\x7e]*\Z")
# Characters left unencoded in rendered values: all fall inside the audit
# chain's request-target set ([A-Za-z0-9$=&,._~:'()*+%-]); "&", "=", "+",
# space and the rest are percent-encoded.
_VALUE_SAFE = "$,._~:'()*-"
_SEGMENT_SAFE = "$._~-"

REASONS = frozenset({
    "method_not_allowed", "body_not_allowed", "malformed_target", "version_not_allowed", "batch_not_allowed",
    "alias_not_allowed", "function_not_allowed", "unknown_query_option", "unknown_query_parameter",
    "duplicate_query_option", "malformed_query",
})


@dataclass(frozen=True, slots=True)
class Refused:
    reason: str
    parameter: str | None = None  # the sanitized name of the parameter refused, if one was

    def __post_init__(self) -> None:
        if self.reason not in REASONS:
            raise ValueError("unknown canonicalization reason")


@dataclass(frozen=True, slots=True)
class FacadeRequest:
    method: str
    version: str                              # "v1.0" | "beta"
    segments: tuple[str, ...]                 # after the version; decoded, lowercased
    options: tuple[tuple[str, str], ...]      # known options, sorted by name
    headers: tuple[tuple[str, str], ...]      # forwarded upstream (canonical name, value)

    @property
    def path(self) -> str:
        return "/" + "/".join(self.segments)

    def option(self, name: str) -> str | None:
        return dict(self.options).get(name)

    def target(self, *, without: frozenset[str] = frozenset()) -> str:
        """The upstream request target, e.g. /beta/users?$count=true&$select=id,displayname."""
        path = "/" + self.version + "".join("/" + quote(s, safe=_SEGMENT_SAFE) for s in self.segments)
        query = "&".join(f"{name}={quote(value, safe=_VALUE_SAFE)}" for name, value in self.options
                         if name not in without)
        return path + (f"?{query}" if query else "")


def sanitize_name(name: str) -> str:
    """A parameter's name as shown and recorded: printable, bounded, never the value."""
    shown = "".join(c if 0x21 <= ord(c) <= 0x7e else f"\\x{ord(c):02x}" for c in name)
    return shown[:64]


def _segments(path: str) -> tuple[str, ...] | Refused:
    if not path.startswith("/") or _ENCODED_SEPARATOR.search(path) or "\\" in path:
        return Refused("malformed_target")
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeDecodeError:
        return Refused("malformed_target")
    if "%" in decoded or _CONTROL_OR_SPACE.search(decoded) or not decoded.isascii():
        return Refused("malformed_target")
    parts = decoded.split("/")[1:]
    if any(p in ("", ".", "..") for p in parts):
        return Refused("malformed_target")
    return tuple(p.lower() for p in parts)


def _options(query: str) -> list[tuple[str, str]] | Refused:
    kept: dict[str, str] = {}
    if not query:
        return []
    for part in query.split("&"):
        if part == "":
            continue
        raw_name, _, raw_value = part.partition("=")
        try:
            name = unquote(raw_name, errors="strict")
            value = unquote(raw_value, errors="strict")
        except UnicodeDecodeError:
            return Refused("malformed_query")
        key = name.lower()
        if key in KNOWN_OPTIONS:
            if key in kept:
                return Refused("duplicate_query_option", sanitize_name(name))
            if not _PRINTABLE.match(value):
                return Refused("malformed_query")
            kept[key] = value.strip()
        elif _ODATA_WORD.match(name):
            return Refused("unknown_query_option", sanitize_name(name))
        else:
            return Refused("unknown_query_parameter", sanitize_name(name))
    if "$select" in kept:
        items: list[str] = []
        for item in (i.strip().lower() for i in kept["$select"].split(",")):
            if item and item not in items:
                items.append(item)
        kept["$select"] = ",".join(items)
    for flag in ("$count",):
        if flag in kept:
            kept[flag] = kept[flag].lower()
    return sorted(kept.items())


def canonicalize(method: object, raw_target: object, headers: Mapping[str, str], body_length: int) -> FacadeRequest | Refused:
    if method != "GET":
        return Refused("method_not_allowed")
    if body_length:
        return Refused("body_not_allowed")
    if not isinstance(raw_target, str) or not 0 < len(raw_target) <= MAX_TARGET_CHARS or "#" in raw_target:
        return Refused("malformed_target")
    if _CONTROL_OR_SPACE.search(raw_target) or not raw_target.isascii():
        return Refused("malformed_target")
    path, _, query = raw_target.partition("?")
    segments = _segments(path)
    if isinstance(segments, Refused):
        return segments
    if not segments or segments[0] not in VERSIONS:
        return Refused("version_not_allowed")
    version, rest = segments[0], segments[1:]
    if not rest:
        return Refused("malformed_target")
    if any("$batch" in s for s in rest):
        return Refused("batch_not_allowed")
    if rest[0] == "me":
        return Refused("alias_not_allowed")
    if any("(" in s or ")" in s or s == "delta" or s.startswith("microsoft.graph.") for s in rest):
        return Refused("function_not_allowed")
    parsed = _options(query)
    if isinstance(parsed, Refused):
        return parsed
    options = parsed
    forwarded = []
    for name, value in headers.items():
        allowed = FORWARDED_HEADERS.get(name.lower())
        if allowed and value.strip().lower() == allowed[1]:
            forwarded.append(allowed)
    return FacadeRequest(method="GET", version=version, segments=rest, options=tuple(options),
                         headers=tuple(sorted(set(forwarded))))
