"""Role holders and app permissions, from the broker's filtered results (v0.1; SD-053).

Pure functions over what the broker returned: no request is made here. Both
reports say what they do not cover, so an agent cannot present a partial
view as the whole picture.
"""

from __future__ import annotations

from collections.abc import Mapping

ROLE_SCOPE_NOTE = ("Active role assignments only. PIM-eligible assignments (activated on demand) are not "
                   "included, so someone not listed here may still be able to become an administrator.")
APP_SCOPE_NOTE = ("Microsoft Graph application permissions only: what apps can do on their own, without a "
                  "signed-in user. Delegated permissions users have consented to, and permissions to other APIs, "
                  "are not included. 'highImpact' is a heuristic list of permissions that can change the tenant, "
                  "escalate privilege or read everyone's data; it is not exhaustive, so review every permission.")

# Built-in roles Microsoft documents as privileged, matched by name only when the role is built in,
# so a custom role cannot borrow the label.
PRIVILEGED_BUILT_IN_ROLES = frozenset({
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Security Administrator", "Application Administrator", "Cloud Application Administrator",
    "User Administrator", "Authentication Administrator", "Conditional Access Administrator",
    "Exchange Administrator", "SharePoint Administrator", "Hybrid Identity Administrator",
    "Intune Administrator", "Helpdesk Administrator", "Authentication Policy Administrator",
    "Partner Tier2 Support", "Directory Writers",
})
MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Microsoft Graph application permissions only (review F8, 2026-10-31): writes that change the tenant or let an
# app escalate, and reads of everyone's mail, files and chats. Not exhaustive; the output says so.
_HIGH_IMPACT_EXACT = frozenset({
    "Mail.Send", "Mail.ReadWrite", "Mail.Read", "Mail.ReadBasic.All", "Sites.FullControl.All", "Sites.Read.All",
    "Files.Read.All", "Chat.Read.All", "ChannelMessage.Read.All", "Notes.Read.All",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All", "Application.ReadWrite.OwnedBy", "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup", "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory", "UserAuthenticationMethod.ReadWrite.All",
})
_HIGH_IMPACT_PREFIXES = ("Policy.ReadWrite.",)
_PRINCIPAL_KINDS = {"#microsoft.graph.user": "user", "#microsoft.graph.group": "group",
                    "#microsoft.graph.servicePrincipal": "app"}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def role_holders(definitions: list, assignments: list) -> dict:
    """Each role with at least one active holder, privileged built-in roles first."""
    names: dict[str, Mapping] = {d["id"]: d for d in definitions if isinstance(d, Mapping) and isinstance(d.get("id"), str)}
    roles: dict[str, dict] = {}
    for assignment in assignments:
        if not isinstance(assignment, Mapping):
            continue
        role_id = _text(assignment.get("roleDefinitionId")) or "unknown"
        definition = names.get(role_id, {})
        name = _text(definition.get("displayName")) or f"(unknown role {role_id})"
        built_in = definition.get("isBuiltIn") is True
        role = roles.setdefault(role_id, {
            "role": name, "builtIn": built_in, "privileged": built_in and name in PRIVILEGED_BUILT_IN_ROLES,
            "holders": []})
        principal = assignment.get("principal") if isinstance(assignment.get("principal"), Mapping) else {}
        scope = _text(assignment.get("directoryScopeId"))
        role["holders"].append({
            "displayName": _text(principal.get("displayName")),
            "userPrincipalName": _text(principal.get("userPrincipalName")),
            "type": _PRINCIPAL_KINDS.get(_text(principal.get("@odata.type")) or "", "other"),
            "id": _text(principal.get("id")) or _text(assignment.get("principalId")),
            "scope": "whole tenant" if scope == "/" else scope,
        })
    ordered = sorted(roles.values(), key=lambda r: (not r["privileged"], r["role"]))
    for role in ordered:
        role["holders"].sort(key=lambda h: (str(h["userPrincipalName"] or h["displayName"] or ""), str(h["id"])))
    return {"scope": ROLE_SCOPE_NOTE, "roles": ordered,
            "counts": {"roles_with_holders": len(ordered), "assignments": sum(len(r["holders"]) for r in ordered),
                       "privileged_assignments": sum(len(r["holders"]) for r in ordered if r["privileged"])}}


def graph_service_principal(service_principals: list) -> Mapping | None:
    for sp in service_principals:
        if isinstance(sp, Mapping) and sp.get("appId") == MICROSOFT_GRAPH_APP_ID and isinstance(sp.get("id"), str):
            return sp
    return None


def high_impact(permission: str) -> bool:
    return (permission in _HIGH_IMPACT_EXACT or permission.startswith(_HIGH_IMPACT_PREFIXES)
            or permission.endswith((".ReadWrite.All", ".ReadWrite.Directory")))


def app_permissions(graph_sp: Mapping, assignments: list) -> dict:
    """Each app holding Microsoft Graph application permissions, with high-impact ones first."""
    roles = graph_sp.get("appRoles") if isinstance(graph_sp.get("appRoles"), list) else []
    values = {r["id"]: r.get("value") for r in roles if isinstance(r, Mapping) and isinstance(r.get("id"), str)}
    apps: dict[str, dict] = {}
    for assignment in assignments:
        if not isinstance(assignment, Mapping):
            continue
        principal = _text(assignment.get("principalId")) or "unknown"
        app = apps.setdefault(principal, {
            "app": _text(assignment.get("principalDisplayName")), "id": principal,
            "type": _text(assignment.get("principalType")), "permissions": [], "highImpact": []})
        role_id = _text(assignment.get("appRoleId")) or ""
        permission = _text(values.get(role_id)) or f"(unknown permission {role_id})"
        app["permissions"].append({"permission": permission, "granted": _text(assignment.get("createdDateTime"))})
        if high_impact(permission):
            app["highImpact"].append(permission)
    ordered = sorted(apps.values(), key=lambda a: (not a["highImpact"], str(a["app"] or ""), a["id"]))
    for app in ordered:
        app["permissions"].sort(key=lambda p: p["permission"])
        app["highImpact"].sort()
    return {"scope": APP_SCOPE_NOTE, "apps": ordered,
            "counts": {"apps": len(ordered), "apps_with_high_impact": sum(1 for a in ordered if a["highImpact"])}}
