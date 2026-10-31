"""Facade policy: a canonical request against a run's approved script manifest (SD-041).

`evaluate` allows a request only if an entry of the manifest allows all of
it: the version, the path (literals exactly, each placeholder a lowercase
GUID) and every query option and forwarded header. Denials, first matching
entry's reason (or not_in_manifest when no entry's path matches):

  not_in_manifest             no entry has this version and path
  select_required             no $select where the entry requires one
  select_not_allowed          a $select property outside the entry's list
  filter_not_allowed          $filter on an entry without filters
  filter_property_not_allowed a $filter naming a property outside its list
                              (or one the parser cannot read)
  top_not_allowed / top_out_of_bounds
  count_not_allowed, orderby_not_allowed, search_not_allowed
  expand_not_allowed          always (Phase 1)
  option_not_allowed          $skip, $format, $apply, $compute, $deltatoken
  consistency_level_not_allowed
  continuation_not_expected   a $skiptoken on a first request (continuations
                              come only from the broker's own page handles)

An allowed decision carries the entry, the audit path template (the entry's,
lowercased to match the canonical path) and the upstream target: the
canonical target without $skiptoken.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from clw.broker.facade.canonical import FacadeRequest
from clw.broker.facade.rules import Entry, ScriptManifest

_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_NEVER = ("$skip", "$format", "$apply", "$compute", "$deltatoken")

# $filter grammar words that are not property names.
_FILTER_WORDS = frozenset({
    "eq", "ne", "gt", "ge", "lt", "le", "and", "or", "not", "has", "in", "add", "sub", "mul", "div", "mod",
    "true", "false", "null", "any", "all", "startswith", "endswith", "contains", "length", "tolower", "toupper",
    "trim", "concat", "indexof", "substring", "year", "month", "day", "hour", "minute", "second", "date", "time",
    "now", "cast", "isof",
})
_STRING = re.compile(r"'(?:[^']|'')*'")
_DATETIME = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:T[0-9:.]+(?:Z|[+-]\d{2}:\d{2})?)?")
_GUID_LITERAL = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_$][A-Za-z0-9_]*)*(?=\s*(\(|:)?)")
_TOP = re.compile(r"[1-9][0-9]{0,2}\Z")


@dataclass(frozen=True, slots=True)
class FacadeDecision:
    allowed: bool
    reason: str
    entry: Entry | None = None
    path_template: str | None = None
    target: str | None = None


def filter_properties(expression: str) -> set[str] | None:
    """The property names a $filter expression refers to (lowercased; first path
    part of `a/b`), or None if it cannot be read. Literals, operators, functions
    and lambda variables are not properties."""
    text = _GUID_LITERAL.sub(" ", _DATETIME.sub(" ", _STRING.sub(" ", expression)))
    if "'" in text:
        return None  # an unterminated string literal
    lambda_vars = {m.group(1).lower() for m in re.finditer(r"\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", text)}
    names: set[str] = set()
    for match in _TOKEN.finditer(text):
        token, follower = match.group(0), match.group(1)
        parts = token.split("/")
        head = parts[0].lower()
        if follower == "(" and len(parts) > 1:
            # "collection/any(" or "collection/all(": a lambda over the property `head`.
            # Any other path followed by "(" is not something this reader understands.
            if parts[-1].lower() not in ("any", "all"):
                return None
        elif follower == "(" or follower == ":" or head in _FILTER_WORDS:
            continue
        if head in lambda_vars:
            continue
        names.add(head)
    return names


def _path_matches(entry: Entry, request: FacadeRequest) -> bool:
    if request.version not in entry.versions or len(entry.segments) != len(request.segments):
        return False
    for want, got in zip(entry.segments, request.segments):
        if want.startswith("{"):
            if not _GUID.match(got):
                return False
        elif want != got:
            return False
    return True


def _options_problem(entry: Entry, request: FacadeRequest) -> str | None:
    options = dict(request.options)
    if "$skiptoken" in options:
        return "continuation_not_expected"
    if "$expand" in options:
        return "expand_not_allowed"
    if any(name in options for name in _NEVER):
        return "option_not_allowed"
    select = options.get("$select")
    if select is None:
        if entry.select_required:
            return "select_required"
    elif not select or not set(select.split(",")) <= entry.select:
        return "select_not_allowed"
    expression = options.get("$filter")
    if expression is not None:
        if not entry.filter_allowed:
            return "filter_not_allowed"
        if entry.filter_properties is not None:
            names = filter_properties(expression)
            if names is None or not names <= entry.filter_properties:
                return "filter_property_not_allowed"
    if "$top" in options:
        if entry.top is None:
            return "top_not_allowed"
        if not _TOP.match(options["$top"]) or int(options["$top"]) > entry.top:
            return "top_out_of_bounds"
    if "$count" in options and (not entry.count or options["$count"] not in ("true", "false")):
        return "count_not_allowed"
    if "$orderby" in options and not entry.orderby:
        return "orderby_not_allowed"
    if "$search" in options and not entry.search:
        return "search_not_allowed"
    if any(name == "ConsistencyLevel" for name, _ in request.headers) and not entry.consistency_level:
        return "consistency_level_not_allowed"
    return None


def evaluate(manifest: ScriptManifest, request: FacadeRequest) -> FacadeDecision:
    first_problem: str | None = None
    for entry in manifest.entries:
        if not _path_matches(entry, request):
            continue
        problem = _options_problem(entry, request)
        if problem is None:
            return FacadeDecision(True, "allowed", entry, "/" + "/".join(entry.segments), request.target())
        first_problem = first_problem or problem
    return FacadeDecision(False, first_problem or "not_in_manifest")
