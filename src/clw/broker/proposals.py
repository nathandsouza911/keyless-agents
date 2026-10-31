"""Change proposals (v0.1, SD-054): what an agent may ask for, and how it is bound and shown.

v0.1 has one kind of proposal: disable a user (users.update, accountEnabled
false). A proposal is never executed here. It binds to the target's object id
through the canonical request and its SHA-256; the target's name, UPN and
accountEnabled are a display snapshot from the broker's own lookup, with the
time it was taken. Everything the agent wrote (its reason) and everything the
tenant holds (the display name) is untrusted text: stored and returned as
data, never interpreted.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime

from clw.audit.canonical import canonical_json
from clw.common.timeutil import to_rfc3339_utc

ACTION = "disable_user"
# At most this many proposals per session: a flood would bury real ones in the list (review F3, 2026-10-31).
MAX_PER_SESSION = 20
OPERATION = "users.update"
LOOKUP = "users.get_identity"
MAX_REASON = 500
MAX_TEXT = 512
_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")
_BODY_KEYS = {"action", "user_id", "reason"}
NOT_FOUND_WARNING = ("No user with this ID was found. It may not exist, or it may be another kind of object "
                     "(a group or an app). Check the ID before acting on this proposal.")


@dataclass(frozen=True, slots=True)
class Asked:
    user_id: str  # lowercase GUID
    reason: str


@dataclass(frozen=True, slots=True)
class Snapshot:
    status: str  # found | not_found
    display_name: str | None = None
    upn: str | None = None
    account_enabled: bool | None = None


def parse(raw: bytes | None) -> Asked | None:
    """Strictly {"action": "disable_user", "user_id": GUID, "reason": 1-500 chars}, else None."""
    if raw is None or len(raw) > 4096:
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(body, dict) or set(body) != _BODY_KEYS or body.get("action") != ACTION:
        return None
    user_id, reason = body.get("user_id"), body.get("reason")
    if not (isinstance(user_id, str) and _GUID.match(user_id)):
        return None
    if not (isinstance(reason, str) and 1 <= len(reason) <= MAX_REASON and "\x00" not in reason):
        return None
    return Asked(user_id=user_id.lower(), reason=reason)


def canonical_request(user_id: str) -> tuple[dict, str]:
    """The exact request a later, approved execution would send, and its SHA-256 (the binding)."""
    request = {"method": "PATCH", "path": f"/v1.0/users/{user_id}", "body": {"accountEnabled": False}}
    return request, hashlib.sha256(canonical_json(request)).hexdigest()


def _clip(value: object) -> str | None:
    return value[:MAX_TEXT] if isinstance(value, str) else None


def snapshot(items: object) -> Snapshot:
    """The lookup's one user, or not_found: no object, or an object that is not a user."""
    if not (isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict)):
        return Snapshot("not_found")
    user = items[0]
    kind = user.get("@odata.type")
    if kind is not None and kind != "#microsoft.graph.user":
        return Snapshot("not_found")
    enabled = user.get("accountEnabled")
    return Snapshot("found", _clip(user.get("displayName")), _clip(user.get("userPrincipalName")),
                    enabled if isinstance(enabled, bool) else None)


def answer(proposal_id: uuid.UUID, asked: Asked, digest: str, snap: Snapshot, looked_up_at: datetime) -> dict:
    """What the agent is told. It says plainly that nothing was executed."""
    target: dict = {"id": asked.user_id, "lookup": snap.status, "looked_up_at": to_rfc3339_utc(looked_up_at)}
    if snap.status == "found":
        target |= {"displayName": snap.display_name, "userPrincipalName": snap.upn,
                   "accountEnabled": snap.account_enabled}
    else:
        target["warning"] = NOT_FOUND_WARNING
    return {
        "status": "proposed", "executed": False, "proposal_id": str(proposal_id),
        "explanation": ("Cloud Locksmith does not execute changes requested by an agent. This proposal was filed "
                        "so a person can see it in Cloud Locksmith's proposal list. This version cannot approve, "
                        "reject or execute proposals, and nobody can approve one in Cloud Locksmith: there is no "
                        "approval step yet. If the change is wanted, a person makes it themselves in the Microsoft "
                        "Entra admin center. Nothing was changed in Microsoft 365."),
        "effect": {"operation": OPERATION, "object_type": "user", "count": 1, "object_ids": [asked.user_id],
                   "change": {"accountEnabled": False}},
        "target": target, "request_sha256": digest,
    }
