"""Two-stage, deny-by-default policy (Task 9, SD-003).

Stage 1, `authorize_operation`, in this order:
  unknown_operation  the name is not a plain str naming a registered operation
  prohibited         it is in the manifest's `prohibited`
  not_in_manifest    it is not in the manifest's `allowed`
  not_executable     it is a write, or a read marked not executable
  invalid_params     the registry refuses the parameters
and on success the request built by the registry (clw.broker.operations).

Stage 2, `authorize_request`, checks the BUILT request against RULES: one
rule per executable read, taken from the registry when this module is
imported, so a registry entry replaced later cannot widen it. A request
passes only if, for an operation the manifest allows and does not prohibit,
the method and declared template equal the rule's, the path fully matches
the template compiled to a case-sensitive regex (each placeholder a
lowercase GUID), and the query is exactly the normalized form the registry
emits ($select sorted and unique, then $top, then the registry's own fixed
parameters as captured here (SD-053), nothing else) with values the
operation's params model accepts. Otherwise: request_pattern_mismatch.

`evaluate` is the only entry point the broker uses. It allows only when
both stages allow, and then checks for itself that the request belongs to
the named operation: the name is allowed and not prohibited, the request
matches that operation's rule, and it equals what the registry builds from
the same parameters. So a replacement engine (SD-003 leaves room for OPA)
can deny more but cannot allow an operation the manifest does not, or
change the request. Any exception or malformed engine result is
policy_error, with no detail kept: messages could quote parameters.

Nothing here relies on the manifest loader's checks (overlap, writes in
`allowed`, unregistered names): each is made again at decision time.
This module decides; it does not record the decision (Task 12).
"""

from __future__ import annotations

import re
import string
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Protocol, get_args

from pydantic import BaseModel, ValidationError

from clw.broker import operations
from clw.broker.manifest import TaskManifest
from clw.broker.operations import BuiltRequest, InvalidParams, NotExecutable, OperationSpec

Reason = Literal[
    "allowed", "unknown_operation", "not_in_manifest", "prohibited",
    "not_executable", "invalid_params", "request_pattern_mismatch", "policy_error",
]
_REASONS = frozenset(get_args(Reason))

_GUID_GROUP = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# Params-model field -> query name, in the order the registry emits them.
_QUERY_ORDER = (("select", "$select"), ("top", "$top"))
_TOP = re.compile(r"[1-9][0-9]*\Z")


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: Reason

    def __post_init__(self) -> None:
        if (
            type(self.allowed) is not bool
            or self.reason not in _REASONS
            or self.allowed != (self.reason == "allowed")
        ):
            raise ValueError("inconsistent decision")


ALLOWED = Decision(True, "allowed")
_POLICY_ERROR = Decision(False, "policy_error")


class PolicyEngine(Protocol):
    def authorize_operation(
        self, manifest: TaskManifest, op_name: str, params: Mapping[str, object]
    ) -> tuple[Decision, BuiltRequest | None]: ...

    def authorize_request(self, manifest: TaskManifest, request: BuiltRequest) -> Decision: ...


@dataclass(frozen=True, slots=True)
class Rule:
    method: str
    path_template: str
    path: re.Pattern[str]
    query_names: tuple[str, ...]  # permitted, in emitted order
    params_model: type[BaseModel]
    fixed_query: tuple[tuple[str, str], ...] = ()  # the registry's own, captured at import (SD-053)


def _rule_for(spec: OperationSpec) -> Rule:
    parts = []
    placeholders = []
    for literal, field, _, _ in string.Formatter().parse(spec.path_template):
        parts.append(re.escape(literal))
        if field is not None:
            parts.append(f"(?P<{field}>{_GUID_GROUP})")
            placeholders.append(field)
    query_fields = set(spec.params_model.model_fields) - set(placeholders)
    if not query_fields <= {field for field, _ in _QUERY_ORDER}:
        raise RuntimeError(f"no stage 2 rule for the parameters of {spec.name}")
    return Rule(
        method=spec.method,
        path_template=spec.path_template,
        path=re.compile("".join(parts)),
        query_names=tuple(name for field, name in _QUERY_ORDER if field in query_fields),
        params_model=spec.params_model,
        fixed_query=tuple(spec.fixed_query),
    )


RULES: Mapping[str, Rule] = MappingProxyType({
    name: _rule_for(spec)
    for name, spec in operations.REGISTRY.items()
    if spec.kind == "read" and spec.executable
})


def _require_manifest(manifest: object) -> TaskManifest:
    if not (
        isinstance(manifest, TaskManifest)
        and all(
            type(names) is tuple and all(type(n) is str for n in names)
            for names in (manifest.allowed, manifest.prohibited)
        )
    ):
        raise TypeError("not a TaskManifest")
    return manifest


def _query_params(rule: Rule, query: object) -> dict[str, object] | None:
    """The params the query encodes, or None unless it is in normalized form."""
    if type(query) is not tuple or not all(
        type(item) is tuple and len(item) == 2 and all(type(x) is str for x in item) for item in query
    ):
        return None
    # The registry's fixed parameters close the query, exactly as captured; the rest is the caller's.
    fixed = len(rule.fixed_query)
    if fixed:
        if query[-fixed:] != rule.fixed_query:
            return None
        query = query[:-fixed]
    # Permitted names only, each at most once, in emitted order.
    names = [name for name, _ in query]
    if names != [name for name in rule.query_names if name in names]:
        return None
    values = dict(query)
    params: dict[str, object] = {}
    if "$select" in values:
        items = values["$select"].split(",")
        if items != sorted(set(items)):
            return None
        params["select"] = items
    if "$top" in values:
        if not _TOP.match(values["$top"]):
            return None
        params["top"] = int(values["$top"])
    return params


def _matches(rule: Rule, request: BuiltRequest) -> bool:
    if not all(type(v) is str for v in (request.method, request.path_template, request.path)):
        return False
    if request.method != rule.method or request.path_template != rule.path_template:
        return False
    match = rule.path.fullmatch(request.path)
    params = _query_params(rule, request.query) if match else None
    if params is None:
        return False
    try:
        rule.params_model.model_validate({**params, **match.groupdict()})
    except ValidationError:
        return False
    return True


class AllowlistPolicyEngine:
    def authorize_operation(
        self, manifest: TaskManifest, op_name: str, params: Mapping[str, object]
    ) -> tuple[Decision, BuiltRequest | None]:
        manifest = _require_manifest(manifest)
        if type(op_name) is not str or op_name not in operations.REGISTRY:
            return Decision(False, "unknown_operation"), None
        spec = operations.get(op_name)
        if op_name in manifest.prohibited:
            return Decision(False, "prohibited"), None
        if op_name not in manifest.allowed:
            return Decision(False, "not_in_manifest"), None
        if spec.kind != "read" or not spec.executable:
            return Decision(False, "not_executable"), None
        try:
            built = operations.build_request(spec, params)
        except (ValidationError, InvalidParams):
            return Decision(False, "invalid_params"), None
        except NotExecutable:
            return Decision(False, "not_executable"), None
        return ALLOWED, built

    def authorize_request(self, manifest: TaskManifest, request: BuiltRequest) -> Decision:
        manifest = _require_manifest(manifest)
        if type(request) is BuiltRequest:
            for name in manifest.allowed:
                rule = RULES.get(name)
                if name not in manifest.prohibited and rule is not None and _matches(rule, request):
                    return ALLOWED
        return Decision(False, "request_pattern_mismatch")


def _belongs_to(manifest: TaskManifest, op_name: object, params: Mapping[str, object], built: BuiltRequest) -> bool:
    """Checked by evaluate itself, whatever the engine said."""
    manifest = _require_manifest(manifest)
    if type(op_name) is not str or op_name in manifest.prohibited or op_name not in manifest.allowed:
        return False
    rule = RULES.get(op_name)
    if rule is None or not _matches(rule, built):
        return False
    return built == operations.build_request(operations.get(op_name), params)


def evaluate(
    engine: PolicyEngine, manifest: TaskManifest, op_name: str, params: Mapping[str, object]
) -> tuple[Decision, BuiltRequest | None]:
    """Both stages. Returns (ALLOWED, request) or (a denial, None); never raises."""
    try:
        result = engine.authorize_operation(manifest, op_name, params)
        if type(result) is not tuple or len(result) != 2 or type(result[0]) is not Decision:
            return _POLICY_ERROR, None
        decision, built = result
        if not decision.allowed:
            return decision, None
        if type(built) is not BuiltRequest:
            return _POLICY_ERROR, None
        second = engine.authorize_request(manifest, built)
        if type(second) is not Decision:
            return _POLICY_ERROR, None
        if not second.allowed:
            return second, None
        if not _belongs_to(manifest, op_name, params, built):
            return _POLICY_ERROR, None
        return ALLOWED, built
    except Exception:  # noqa: BLE001 - an exception never means allow; detail is dropped
        return _POLICY_ERROR, None
