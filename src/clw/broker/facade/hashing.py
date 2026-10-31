"""Keyed hashing of free-text query values in the audit chain (SD-042).

The chain records each facade request's exact target, because the verifier
binds a request to its approval by that target (SD-039). The values of
`$filter` and `$search` are free text a script chooses and can name a person,
and the chain is permanent (redaction, SD-037, cannot reach it). So the
chain records those two values as

    clwhash.<key_id>.<HMAC-SHA256(tenant key, "<option>\\0<value>") in hex>

and every other part of the target as is. Graph always receives the real
target; only the audit form is hashed. The decision and its requests are
hashed with the same key, so RR-5's exact comparison still holds (the
broker's $skiptoken continuation is appended after, and is not hashed).

Keys: one 32-byte key per tenant in `audit_value_keys`, created by the broker
on first use, cached in this process. An operator holding the owner role can
test a candidate value against a recorded hash (`clw audit-hash-value`).
Deleting the tenant's key makes its hashes impossible to tie to values.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from urllib.parse import unquote

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

HASHED_OPTIONS = frozenset({"$filter", "$search"})
PREFIX = "clwhash"


@dataclass(frozen=True, slots=True)
class ValueKey:
    key_id: str
    key: bytes = field(repr=False)


def value_digest(key: ValueKey, option: str, value: str) -> str:
    mac = hmac.new(key.key, f"{option}\0{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{PREFIX}.{key.key_id}.{mac}"


def audit_target(target: str, key: ValueKey) -> str:
    """`target` with the values of HASHED_OPTIONS replaced by their keyed digests."""
    path, sep, query = target.partition("?")
    if not sep:
        return target
    parts = []
    for part in query.split("&"):
        name, eq, raw = part.partition("=")
        option = unquote(name).lower()
        parts.append(f"{name}={value_digest(key, option, unquote(raw))}" if eq and option in HASHED_OPTIONS else part)
    return f"{path}?{'&'.join(parts)}"


class ValueKeys:
    """The tenant's key, created on first use (broker role: SELECT, INSERT only)."""

    def __init__(self) -> None:
        self._cache: dict[str, ValueKey] = {}

    async def get(self, sessionmaker: async_sessionmaker[AsyncSession], tenant_id: str) -> ValueKey:
        cached = self._cache.get(tenant_id)
        if cached is not None:
            return cached
        async with sessionmaker() as session:
            async with session.begin():
                await session.execute(text(
                    "INSERT INTO audit_value_keys (tenant_id, key_id, key) VALUES (:t, :i, :k) "
                    "ON CONFLICT (tenant_id) DO NOTHING"),
                    {"t": tenant_id, "i": secrets.token_hex(4), "k": secrets.token_bytes(32)})
                row = (await session.execute(text(
                    "SELECT key_id, key FROM audit_value_keys WHERE tenant_id = :t"), {"t": tenant_id})).one()
        key = ValueKey(key_id=row[0], key=bytes(row[1]))
        self._cache[tenant_id] = key
        return key

    def forget(self, tenant_id: str) -> None:
        self._cache.pop(tenant_id, None)


async def digest_for(sessionmaker: async_sessionmaker[AsyncSession], tenant_id: str, option: str, value: str) -> str | None:
    """The digest a recorded value would have under the tenant's current key (None: no key)."""
    async with sessionmaker() as session:
        row = (await session.execute(text("SELECT key_id, key FROM audit_value_keys WHERE tenant_id = :t"),
                                     {"t": tenant_id})).first()
    return None if row is None else value_digest(ValueKey(row[0], bytes(row[1])), option.lower(), value)
