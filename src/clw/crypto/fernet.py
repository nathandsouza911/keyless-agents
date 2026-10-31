"""Application-layer encryption for recoverable secrets at rest (SD-013).

Fernet (AES-128-CBC with HMAC-SHA256) over an ordered key list: the first key
encrypts, every key decrypts. This gives confidentiality and integrity of
stored values only; it is not the audit chain's hashing or the checkpoint
signatures.

ENCRYPTION_KEYS holds comma-separated Fernet keys, newest first. Generate one
with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Failures are closed and carry no detail: a bad key list raises KeyConfigError
(never a default or generated key), and anything that does not authenticate
under a configured key raises DecryptionError (never unverified plaintext).
Neither message contains key material, ciphertext or plaintext, and neither
chains the underlying exception.
"""

from __future__ import annotations

import base64
import re
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from clw.common.config import get_settings

# 32 bytes as canonical URL-safe base64. urlsafe_b64decode alone is lenient: it
# accepts the standard alphabet and ignores the two unused bits of the last
# character, so one key could be spelled several ways and dodge the
# duplicate check.
_KEY_SHAPE = re.compile(r"[A-Za-z0-9_-]{43}=")


class KeyConfigError(Exception):
    """ENCRYPTION_KEYS is missing or malformed."""


class DecryptionError(Exception):
    """A value could not be authenticated and decrypted under any configured key."""

    def __init__(self) -> None:
        super().__init__("decryption failed")


def _parse_key(entry: str, position: int) -> bytes:
    raw = base64.urlsafe_b64decode(entry) if _KEY_SHAPE.fullmatch(entry) else b""
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode() != entry:
        raise KeyConfigError(
            f"ENCRYPTION_KEYS entry {position} is not a canonical URL-safe base64 32-byte Fernet key"
        )
    return raw


class KeyRing:
    """Ordered Fernet keys. Build with from_string; repr shows the key count only."""

    __slots__ = ("_fernet", "_count")

    def __init__(self, keys: list[bytes]) -> None:
        self._fernet = MultiFernet([Fernet(base64.urlsafe_b64encode(k)) for k in keys])
        self._count = len(keys)

    @classmethod
    def from_string(cls, raw: str | None) -> KeyRing:
        """Parse ENCRYPTION_KEYS. Entries are trimmed; a blank entry is an error, not skipped."""
        if not isinstance(raw, str):
            raise KeyConfigError("ENCRYPTION_KEYS is not set")
        if not raw.strip():
            raise KeyConfigError("ENCRYPTION_KEYS is empty")
        keys: list[bytes] = []
        for position, entry in enumerate(raw.split(","), start=1):
            entry = entry.strip()
            if not entry:
                raise KeyConfigError(f"ENCRYPTION_KEYS entry {position} is blank")
            key = _parse_key(entry, position)
            if key in keys:
                raise KeyConfigError(f"ENCRYPTION_KEYS entry {position} duplicates an earlier key")
            keys.append(key)
        return cls(keys)

    def __repr__(self) -> str:
        return f"KeyRing(keys={self._count})"

    def encrypt_str(self, plaintext: str) -> str:
        """Encrypt under the first key. Returns an opaque ASCII token."""
        if not isinstance(plaintext, str):
            raise TypeError("encrypt_str requires a str argument")
        data = _utf8_encode(plaintext)
        if data is None:
            raise ValueError("plaintext is not encodable as UTF-8")
        return self._fernet.encrypt(data).decode("ascii")

    def decrypt_str(self, ciphertext: str) -> str:
        """Authenticate and decrypt a token from encrypt_str, or raise DecryptionError."""
        # Failures are detected inside helpers and raised here, outside any
        # except block, so the error has no __context__ holding the input.
        text = _utf8_decode(self._open(ciphertext))
        if text is None:
            raise DecryptionError()
        return text

    def rotate(self, ciphertext: str) -> str:
        """Re-encrypt a token under the first key, so older keys can be retired."""
        return self.encrypt_str(self.decrypt_str(ciphertext))

    def _open(self, ciphertext: object) -> bytes | None:
        if not isinstance(ciphertext, str) or not ciphertext.isascii():
            return None
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii"))
        except (InvalidToken, TypeError, ValueError):
            return None


def _utf8_encode(text: str) -> bytes | None:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates; the error would quote the text
        return None


def _utf8_decode(data: bytes | None) -> str | None:
    if data is None:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:  # authentic, but not something encrypt_str wrote
        return None


@lru_cache(maxsize=1)
def get_keyring() -> KeyRing:
    """The configured key ring. Raises KeyConfigError if ENCRYPTION_KEYS is missing or bad.

    Call once at startup in any process that needs it, so a bad key list
    stops the process before it serves requests. Failures are not cached.
    """
    value = get_settings().ENCRYPTION_KEYS
    return KeyRing.from_string(None if value is None else value.get_secret_value())


def encrypt_str(plaintext: str) -> str:
    return get_keyring().encrypt_str(plaintext)


def decrypt_str(ciphertext: str) -> str:
    return get_keyring().decrypt_str(ciphertext)
