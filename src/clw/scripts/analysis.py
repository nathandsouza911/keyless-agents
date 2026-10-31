"""From the offline analyser's output to a proposed manifest and a summary (SD-043).

The analyser (task_pwsh/analyse.ps1, run by the runner in a container with no
network) parses a script and never executes it. Its stdout is exactly one
line, `CLW_ANALYSIS <json>`. This module:

  parse_analysis   accepts that line only: one line, at most 1 MiB, a JSON
                   object with exactly the analyser's keys
  propose          a script manifest document (clw.broker.facade.rules) with
                   one GET entry per Graph collection the script reads, the
                   properties it selects, the filter properties it names, and
                   the options it uses. Writes are never proposed.
  summarize        plain English, for the analyst and the approver: what it
                   reads, what it tries to change (and that it will be
                   blocked), its risk flags and what could not be resolved

Both are deterministic templates over the analysis. The analysis explains;
it does not enforce: the facade enforces the approved manifest at run time,
and anything the analysis missed is denied there unless the manifest allows it.
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote

from clw.broker.facade.policy import filter_properties

PREFIX = b"CLW_ANALYSIS "
MAX_OUTPUT_BYTES = 1024 * 1024
KEYS = frozenset({"version", "parse_errors", "commands", "graph_calls", "unresolved", "risks"})
DEFAULT_PROFILE = "directory-read-auditlog-read"

_GRAPH = re.compile(r"(?:https://graph\.microsoft\.com)?/(v1\.0|beta)(/[^?#]*)(?:\?([^#]*))?\Z", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"\{([A-Za-z][A-Za-z0-9-]*)\}")
_PROPERTY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}\Z")
_WRITE_METHODS = frozenset({"POST", "PATCH", "PUT", "DELETE"})
UNREAD = "<computed>"  # a filter the script builds at run time: present, but its properties are unknown

RISK_TEXT = {
    "dynamic_code": "runs code built at run time (Invoke-Expression)",
    "compiled_code": "compiles code (Add-Type)",
    "native_process": "starts other programs (Start-Process)",
    "background_job": "starts background jobs",
    "interactive_prompt": "asks for input (Read-Host); there is no one to answer in the sandbox",
    "removed_in_sdk_v2": "uses Select-MgProfile, which Graph PowerShell SDK v2 removed; the script will fail there",
    "module_install": "tries to install modules; the sandbox has no PowerShell Gallery",
    "module_not_preinstalled": "imports a module that is not installed in the sandbox",
    "opens_files": "tries to open files (Invoke-Item)",
    "file_write": "writes files; only output on the screen is kept as the run's result",
    "credential_access": "reads or asks for credentials",
    "dynamic_command": "calls a command whose name is computed",
    "module_qualified_call": "calls a cmdlet by its module-qualified name (bypasses Cloud Locksmith's Connect-MgGraph)",
    "other_service": "connects to a service other than Microsoft Graph",
    "non_graph_web_call": "calls a web address that is not Microsoft Graph; the sandbox has no network",
    "string_built_url": "builds a Graph address from variables",
    "encoded_command": "uses an encoded command",
    "environment_read": "reads environment variables",
}


class AnalysisRefused(ValueError):
    """The analyser's output is not a usable analysis. The message is the reason only."""


def parse_analysis(stdout: bytes) -> dict:
    if not isinstance(stdout, bytes) or len(stdout) > MAX_OUTPUT_BYTES:
        raise AnalysisRefused("analysis_too_large")
    lines = stdout.rstrip(b"\r\n").split(b"\n")
    if len(lines) != 1 or not lines[0].startswith(PREFIX):
        raise AnalysisRefused("analysis_malformed")
    try:
        document = json.loads(lines[0][len(PREFIX):].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise AnalysisRefused("analysis_malformed") from None
    if not isinstance(document, dict) or set(document) != KEYS:
        raise AnalysisRefused("analysis_malformed")
    for key in KEYS - {"version"}:
        if not isinstance(document[key], list) or not all(isinstance(i, dict) for i in document[key]):
            raise AnalysisRefused("analysis_malformed")
    return document


def _template(path: str) -> str | None:
    """A facade path template from a Graph path: {user-id} -> {user_id}; None if unsupported."""
    path = _PLACEHOLDER.sub(lambda m: "{" + m.group(1).lower().replace("-", "_") + "}", path.rstrip("/"))
    segments = path.split("/")[1:]
    if not segments or any(s == "" or "(" in s or ")" in s or s.lower() == "$batch" for s in segments):
        return None
    return path


def _options(query: str | None) -> dict[str, str]:
    out = {}
    for part in (query or "").split("&"):
        name, _, value = part.partition("=")
        if name:
            out[unquote(name).strip().lower()] = unquote(value).strip()
    return out


def _properties(value) -> list[str]:
    items = value if isinstance(value, list) else str(value).split(",") if isinstance(value, str) else []
    return [i.strip() for i in items if isinstance(i, str) and _PROPERTY.match(i.strip())]


def _slug(method: str, template: str) -> str:
    words = re.sub(r"[^a-z0-9]+", "-", template.lower().replace("{", "").replace("}", "")).strip("-")
    return f"{method.lower()}-{words}"[:64].strip("-")


def _read(call: dict) -> dict | None:
    """What one GET call reads: version, template, properties, filter, top, count, consistency."""
    uri = call.get("uri")
    if not isinstance(uri, str):
        return None
    match = _GRAPH.match(uri)
    if match:  # a literal URI (Invoke-MgGraphRequest, Invoke-RestMethod)
        version, path, query = match.group(1).lower(), match.group(2), match.group(3)
        options = _options(query)
        top = options.get("$top")
        return {"version": version, "template": _template(path), "select": _properties(options.get("$select", "")),
                "filter": options.get("$filter"), "top": int(top) if top and top.isdigit() else None,
                "count": options.get("$count") == "true", "consistency": options.get("$count") == "true"}
    if not uri.startswith("/"):
        return None
    parameters = call.get("parameters") if isinstance(call.get("parameters"), dict) else {}
    version = "beta" if str(call.get("api_version", "")).lower() == "beta" else "v1.0"
    top = parameters.get("Top")
    counted = "CountVariable" in parameters or parameters.get("ConsistencyLevel") is not None
    return {"version": version, "template": _template(uri),
            "select": _properties(parameters.get("Property") or parameters.get("Select") or ""),
            "filter": (parameters["Filter"] if isinstance(parameters["Filter"], str) else UNREAD)
            if "Filter" in parameters else None,
            "top": int(top) if isinstance(top, str) and top.isdigit() else None,
            "count": counted, "consistency": counted}


def propose(analysis: dict, *, profile: str = DEFAULT_PROFILE) -> dict:
    entries: dict[str, dict] = {}
    for call in analysis["graph_calls"]:
        if str(call.get("method", "")).upper() != "GET":
            continue
        read = _read(call)
        if read is None or read["template"] is None:
            continue
        entry = entries.setdefault(read["template"], {
            "id": _slug("get", read["template"]), "method": "GET", "versions": [], "path": read["template"],
            "select": [], "select_required": True, "filter": {"allowed": False, "properties": []},
            "top": None, "count": False, "consistency_level": False, "_unknown_filter": False,
            "_no_select": False})
        if read["version"] not in entry["versions"]:
            entry["versions"].append(read["version"])
        for prop in read["select"]:
            # The facade compares $select case-insensitively: Id and id are one property.
            if prop.casefold() not in {p.casefold() for p in entry["select"]}:
                entry["select"].append(prop)
        if not read["select"]:
            entry["_no_select"] = True
        expression = read["filter"]
        if expression is not None:
            entry["filter"]["allowed"] = True
            names = filter_properties(expression) if expression != UNREAD else None
            if names is None:
                entry["_unknown_filter"] = True
            else:
                entry["filter"]["properties"] = sorted(set(entry["filter"]["properties"]) | names)
        if read["top"]:
            entry["top"] = max(entry["top"] or 0, min(read["top"], 999))
        entry["count"] = entry["count"] or read["count"]
        entry["consistency_level"] = entry["consistency_level"] or read["consistency"]

    proposed = []
    for entry in entries.values():
        if entry.pop("_no_select") and not entry["select"]:
            entry["select_required"] = False  # the script names no properties: the approver must decide
        if entry.pop("_unknown_filter") or not entry["filter"]["allowed"]:
            entry["filter"] = {"allowed": False} if not entry["filter"]["allowed"] else {"allowed": True, "properties": []}
        if entry["top"] is None:
            del entry["top"]
        proposed.append(entry)
    return {"schema_version": 1, "profile": profile, "entries": proposed}


def summarize(analysis: dict, proposed: dict) -> dict:
    reads = []
    for e in proposed["entries"]:
        line = f"Reads {e['path']} ({' and '.join(e['versions'])})"
        if e["select"]:
            line += ": " + ", ".join(e["select"])
        else:
            line += ": no properties chosen, so Graph's default set (choose the properties before approving)"
        if e["filter"]["allowed"]:
            props = e["filter"].get("properties") or []
            line += f"; filters on {', '.join(props)}" if props else "; uses a filter that could not be read"
        if e.get("count"):
            line += "; counts results"
        reads.append(line + ".")
    blocked = [f"Tries to change data: {str(c.get('method', '')).upper()} {c.get('uri')} ({c.get('source')}, line "
               f"{c.get('line')}). This will be blocked."
               for c in analysis["graph_calls"] if str(c.get("method", "")).upper() in _WRITE_METHODS]
    risks = sorted({f"Line {r.get('line')}: {RISK_TEXT.get(str(r.get('kind')), str(r.get('kind')))}."
                    for r in analysis["risks"]})
    unknown = [f"Line {u.get('line')}: {u.get('reason')} ({u.get('command')}). Denied unless the manifest allows it."
               for u in analysis["unresolved"]]
    if analysis["parse_errors"]:
        risks.insert(0, f"The script does not parse ({len(analysis['parse_errors'])} error(s)); it will fail to run.")
    return {"reads": reads, "blocked": blocked, "risks": risks, "unknown": unknown}
