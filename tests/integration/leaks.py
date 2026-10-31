"""Identity-leak scanning for the dev-tenant tests (owner note on A1, 2026-10-25).

The dev tenant contains real people. The only place their identities may be
stored is a run's result (`runs.result`), which the tests redact (SD-037).
`find_leaks` reports where identifying strings appear and how often, and
never the strings themselves, so a failure cannot leak what it found.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

_MIN_NAME_CHARS = 8
# Display names made only of these words are placeholders ("Test User", "Admin
# Account"), not a person: they would match ordinary prose such as "non-test user".
# Such an account's id and user principal name are still scanned.
_GENERIC_WORDS = frozenset({"test", "user", "users", "admin", "administrator", "account", "service", "guest",
                            "demo", "sample", "default", "new", "temp", "shared", "mailbox", "room", "the", "a"})


def identities(users: Iterable[Mapping[str, object]], *, exclude_ids: set[str]) -> set[str]:
    """Lowercase identifying strings of every user whose id is not in `exclude_ids`.

    Ids and user principal names are always included (they are unique). A display
    name is included only when it is distinctive: two words or more, or at least
    eight characters, and not made only of generic placeholder words. A one-word
    short name ("Admin") or a placeholder ("Test User") would match unrelated text.
    """
    found: set[str] = set()
    for user in users:
        user_id = str(user.get("id") or "").lower()
        if not user_id or user_id in exclude_ids:
            continue
        found.add(user_id)
        upn = user.get("userPrincipalName")
        if isinstance(upn, str) and upn:
            found.add(upn.lower())
        name = user.get("displayName")
        words = name.lower().split() if isinstance(name, str) else []
        distinctive = len(words) >= 2 or len(name or "") >= _MIN_NAME_CHARS
        if words and distinctive and not set(words) <= _GENERIC_WORDS:
            found.add(name.lower())
    return found


def find_leaks(needles: set[str], places: Mapping[str, str]) -> dict[str, int]:
    """{place: number of hits} for every place holding any needle (case-insensitive)."""
    if not needles:
        return {}
    pattern = re.compile("|".join(re.escape(n) for n in sorted(needles, key=len, reverse=True)))
    hits = {place: len(pattern.findall(text.lower())) for place, text in places.items()}
    return {place: count for place, count in hits.items() if count}


def describe(leaks: dict[str, int]) -> str:
    """A failure message naming places and counts only."""
    return "tenant identities found in: " + ", ".join(f"{place} ({count})" for place, count in sorted(leaks.items()))
