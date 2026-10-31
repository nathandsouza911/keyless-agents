"""Fernet encryption at rest (SD-013).

Keys are generated at runtime; no real key is ever written to the repo.
"""

from __future__ import annotations

import ast
import base64
import logging
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from clw.common.config import Settings
from clw.crypto import fernet as crypto
from clw.crypto.fernet import DecryptionError, KeyConfigError, KeyRing

CRYPTO_SRC = Path(__file__).resolve().parents[2] / "src" / "clw" / "crypto"
PG = "postgresql+asyncpg://u:p@127.0.0.1:5433/clw"
SECRET = "refresh-token-value-é"


def _key() -> str:
    return Fernet.generate_key().decode()


def _ring(*keys: str) -> KeyRing:
    return KeyRing.from_string(",".join(keys))


def _decoded(token: str) -> bytes:
    return base64.urlsafe_b64decode(token.encode())


def _encoded(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


# ---------------------------------------------------------------- round trip


def test_round_trip():
    ring = _ring(_key())
    token = ring.encrypt_str(SECRET)
    assert token != SECRET and SECRET not in token
    assert ring.decrypt_str(token) == SECRET


def test_round_trip_empty_string():
    ring = _ring(_key())
    assert ring.decrypt_str(ring.encrypt_str("")) == ""


def test_encryption_is_randomised():
    ring = _ring(_key())
    assert ring.encrypt_str(SECRET) != ring.encrypt_str(SECRET)


@pytest.mark.parametrize("value", [None, b"bytes", 42])
def test_encrypt_rejects_non_str(value):
    with pytest.raises(TypeError):
        _ring(_key()).encrypt_str(value)


def test_encrypt_rejects_unencodable_text_without_echoing_it():
    secret = "token-\ud800-value"
    with pytest.raises(ValueError) as info:
        _ring(_key()).encrypt_str(secret)
    # Exactly ValueError: UnicodeEncodeError (a subclass) keeps the text in .object.
    assert type(info.value) is ValueError
    assert secret not in str(info.value) and "token-" not in str(info.value)
    assert info.value.__context__ is None


# ---------------------------------------------------------------- integrity


def test_tampered_ciphertext_fails_closed():
    ring = _ring(_key())
    raw = bytearray(_decoded(ring.encrypt_str(SECRET)))
    raw[-40] ^= 0x01  # inside the ciphertext, covered by the HMAC
    with pytest.raises(DecryptionError):
        ring.decrypt_str(_encoded(bytes(raw)))


def test_tampered_hmac_fails_closed():
    ring = _ring(_key())
    raw = bytearray(_decoded(ring.encrypt_str(SECRET)))
    raw[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        ring.decrypt_str(_encoded(bytes(raw)))


def test_truncated_ciphertext_fails_closed():
    ring = _ring(_key())
    token = ring.encrypt_str(SECRET)
    with pytest.raises(DecryptionError):
        ring.decrypt_str(token[:-8])


def test_wrong_key_fails_closed():
    token = _ring(_key()).encrypt_str(SECRET)
    with pytest.raises(DecryptionError):
        _ring(_key()).decrypt_str(token)


def test_unsupported_token_version_fails_closed():
    ring = _ring(_key())
    raw = bytearray(_decoded(ring.encrypt_str(SECRET)))
    assert raw[0] == 0x80
    raw[0] = 0x81
    with pytest.raises(DecryptionError):
        ring.decrypt_str(_encoded(bytes(raw)))


def test_valid_token_with_non_utf8_plaintext_fails_closed():
    # Authentic under our key but not something encrypt_str could produce:
    # never hand back bytes we cannot represent as the str contract promises.
    key = _key()
    token = Fernet(key.encode()).encrypt(b"\xff\xfe\xfd").decode()
    with pytest.raises(DecryptionError):
        _ring(key).decrypt_str(token)


@pytest.mark.parametrize(
    "value",
    [None, 42, b"bytes", [], "", "not-a-token", "ééé", "gAAAAA", _encoded(b"\x80" + b"\x00" * 80)],
)
def test_garbage_input_raises_decryption_error(value):
    with pytest.raises(DecryptionError):
        _ring(_key()).decrypt_str(value)


def test_decryption_error_is_not_an_http_exception():
    from fastapi import HTTPException

    assert not issubclass(DecryptionError, HTTPException)
    with pytest.raises(DecryptionError) as info:
        _ring(_key()).decrypt_str("garbage")
    assert not isinstance(info.value, HTTPException)


# ---------------------------------------------------------------- rotation


def test_old_ciphertext_decrypts_after_rotation():
    old, new = _key(), _key()
    token = _ring(old).encrypt_str(SECRET)
    assert _ring(new, old).decrypt_str(token) == SECRET


def test_new_encryption_uses_first_key():
    old, new = _key(), _key()
    token = _ring(new, old).encrypt_str(SECRET)
    assert Fernet(new.encode()).decrypt(token.encode()).decode() == SECRET
    with pytest.raises(Exception):
        Fernet(old.encode()).decrypt(token.encode())


def test_rotate_rewraps_under_first_key():
    old, new = _key(), _key()
    token = _ring(old).encrypt_str(SECRET)
    rewrapped = _ring(new, old).rotate(token)
    assert _ring(new).decrypt_str(rewrapped) == SECRET


def test_rotate_fails_closed_on_bad_token():
    with pytest.raises(DecryptionError):
        _ring(_key()).rotate("garbage")


def test_retired_key_ciphertext_fails_closed():
    old, new = _key(), _key()
    token = _ring(old).encrypt_str(SECRET)
    assert _ring(new, old).decrypt_str(token) == SECRET
    with pytest.raises(DecryptionError):
        _ring(new).decrypt_str(token)


def test_legacy_single_key_ciphertext_is_compatible():
    # Legacy crypto.py wrote plain Fernet tokens under one ENCRYPTION_KEY.
    legacy = _key()
    token = Fernet(legacy.encode()).encrypt(SECRET.encode()).decode()
    assert _ring(_key(), legacy).decrypt_str(token) == SECRET


# ---------------------------------------------------------------- key configuration


@pytest.mark.parametrize("raw", [None, "", "   ", "\n"])
def test_missing_or_empty_keys_rejected(raw):
    with pytest.raises(KeyConfigError):
        KeyRing.from_string(raw)


def test_non_str_keys_rejected():
    with pytest.raises(KeyConfigError):
        KeyRing.from_string(Fernet.generate_key())  # bytes, not str


def _non_canonical(key: str) -> str:
    # Same 32 bytes, different spelling: the last data character carries two
    # unused bits that a lenient decoder ignores.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(key[42])
    return key[:42] + alphabet[last ^ 0x01] + "="


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda k: f"{k},,{_key()}", id="blank-middle"),
        pytest.param(lambda k: f"{k},", id="trailing-comma"),
        pytest.param(lambda k: f",{k}", id="leading-comma"),
        pytest.param(lambda k: f"{k}, ,{_key()}", id="whitespace-entry"),
        pytest.param(lambda k: "!" * 43 + "=", id="bad-base64-chars"),
        pytest.param(lambda k: k[:-1], id="missing-padding"),
        pytest.param(lambda k: k + "AAAA", id="too-long"),
        pytest.param(lambda k: _encoded(b"\x00" * 16), id="16-byte-key"),
        pytest.param(lambda k: _encoded(b"\x00" * 48), id="48-byte-key"),
        pytest.param(lambda k: base64.b64encode(b"\xfb" * 32).decode(), id="standard-alphabet"),
        pytest.param(lambda k: _non_canonical(k), id="non-canonical"),
        pytest.param(lambda k: k[:20] + "é" + k[21:], id="non-ascii"),
        pytest.param(lambda k: f"{k};{_key()}", id="wrong-separator"),
        pytest.param(lambda k: f"{k},{k}", id="duplicate"),
        pytest.param(lambda k: f"{k},{_key()},{k}", id="duplicate-later"),
        pytest.param(lambda k: f"{k},{_non_canonical(k)}", id="duplicate-by-bytes"),
    ],
)
def test_malformed_keys_rejected(make):
    key = _key()
    raw = make(key)
    with pytest.raises(KeyConfigError) as info:
        KeyRing.from_string(raw)
    message = str(info.value)
    for part in raw.split(","):
        if part.strip():
            assert part.strip() not in message
    assert info.value.__cause__ is None and info.value.__context__ is None


def test_surrounding_whitespace_is_trimmed():
    a, b = _key(), _key()
    ring = KeyRing.from_string(f" {a} ,\n{b}\n")
    assert Fernet(a.encode()).decrypt(ring.encrypt_str("x").encode()) == b"x"


def test_keyring_repr_hides_keys():
    key = _key()
    ring = _ring(key)
    assert key not in repr(ring) and key not in str(ring)
    assert "1" in repr(ring)  # key count only


# ---------------------------------------------------------------- settings wiring


def test_settings_keys_are_optional_and_secret():
    key = _key()
    assert Settings(_env_file=None, DATABASE_URL=PG).ENCRYPTION_KEYS is None
    settings = Settings(_env_file=None, DATABASE_URL=PG, ENCRYPTION_KEYS=key)
    assert key not in repr(settings)


@pytest.fixture
def env_keys(monkeypatch):
    from clw.common import config

    monkeypatch.setenv("DATABASE_URL", PG)

    def set_keys(value: str | None) -> None:
        if value is None:
            monkeypatch.delenv("ENCRYPTION_KEYS", raising=False)
        else:
            monkeypatch.setenv("ENCRYPTION_KEYS", value)
        config.get_settings.cache_clear()
        crypto.get_keyring.cache_clear()

    yield set_keys
    config.get_settings.cache_clear()
    crypto.get_keyring.cache_clear()


def test_module_functions_use_configured_keys(env_keys):
    old, new = _key(), _key()
    env_keys(old)
    token = crypto.encrypt_str(SECRET)
    env_keys(f"{new},{old}")
    assert crypto.decrypt_str(token) == SECRET
    assert Fernet(new.encode()).decrypt(crypto.encrypt_str(SECRET).encode()).decode() == SECRET
    env_keys(new)
    with pytest.raises(DecryptionError):
        crypto.decrypt_str(token)


@pytest.mark.parametrize("value", [None, "", "not-a-key"])
def test_module_functions_fail_closed_without_valid_keys(env_keys, value):
    env_keys(value)
    with pytest.raises(KeyConfigError):
        crypto.get_keyring()
    with pytest.raises(KeyConfigError):
        crypto.encrypt_str(SECRET)
    with pytest.raises(KeyConfigError):
        crypto.decrypt_str("anything")


def test_failed_key_load_is_not_cached(env_keys, monkeypatch):
    from clw.common import config

    env_keys(None)
    with pytest.raises(KeyConfigError):
        crypto.get_keyring()
    key = _key()
    monkeypatch.setenv("ENCRYPTION_KEYS", key)
    config.get_settings.cache_clear()  # keyring cache deliberately not cleared
    assert crypto.decrypt_str(_ring(key).encrypt_str("x")) == "x"


# ---------------------------------------------------------------- no secret leakage


def test_no_secret_material_in_errors_or_logs(caplog):
    caplog.set_level(logging.DEBUG)
    key, other = _key(), _key()
    token = _ring(key).encrypt_str(SECRET)
    raw = bytearray(_decoded(token))
    raw[-1] ^= 0x01
    cases = [
        (_ring(other).decrypt_str, token),
        (_ring(key).decrypt_str, _encoded(bytes(raw))),
        (_ring(key).decrypt_str, Fernet(key.encode()).encrypt(b"\xff" + SECRET.encode()).decode()),
    ]
    for fn, arg in cases:
        with pytest.raises(DecryptionError) as info:
            fn(arg)
        exc = info.value
        text = f"{exc!s} {exc!r} {exc.args!r}"
        for secret in (key, other, token, arg, SECRET):
            assert secret not in text
        # No chained exception carrying the input or the decrypted bytes.
        assert exc.__cause__ is None and exc.__context__ is None
    logged = " ".join(r.getMessage() for r in caplog.records)
    for secret in (key, other, token, SECRET):
        assert secret not in logged


# ---------------------------------------------------------------- layering


def _imported_roots(path: Path) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_crypto_does_not_import_web_framework(tmp_path):
    probe = tmp_path / "probe.py"  # the checker must catch the legacy import
    probe.write_text("from fastapi import HTTPException\nimport starlette.responses\n", encoding="utf-8")
    assert {"fastapi", "starlette"} <= _imported_roots(probe)

    files = sorted(CRYPTO_SRC.glob("*.py"))
    assert files
    for path in files:
        assert not _imported_roots(path) & {"fastapi", "starlette"}, path.name
