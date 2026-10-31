"""Workbench settings.

Only settings that exist in code today live here; each later task adds its
own (session secret in Task 5, encryption keys in Task 3, ...), so no
component is forced to hold secrets it does not use.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_HIDDEN_INPUT = "<hidden>"


def _without_inputs(exc: ValidationError) -> ValidationError:
    """The same errors (setting, type, message) with every input value replaced."""
    line_errors = []
    for error in exc.errors(include_url=False):
        line = {"type": error["type"], "loc": error["loc"], "input": _HIDDEN_INPUT}
        if "ctx" in error:
            line["ctx"] = error["ctx"]
        line_errors.append(line)
    return ValidationError.from_exception_data(exc.title, line_errors, hide_input=True)


class Settings(BaseSettings):
    # Process environment only (compose/container env). No .env parsing: the
    # local .env also carries compose-only variables, and extra="forbid" exists
    # to catch typos in explicitly passed settings.
    # hide_input_in_errors keeps values out of str()/repr() of validation
    # errors; __init__ also strips them from errors()/json(), where pydantic
    # keeps them. This applies to every setting: settings hold credentials.
    model_config = SettingsConfigDict(env_file=None, extra="forbid", hide_input_in_errors=True)

    def __init__(self, **values) -> None:
        sanitized = None
        try:
            super().__init__(**values)
        except ValidationError as exc:
            sanitized = _without_inputs(exc)
        if sanitized is not None:
            # Raised outside the except block: no __context__ holding the original.
            raise sanitized

    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    # SecretStr keeps credentials embedded in the URL out of repr() and logs.
    DATABASE_URL: SecretStr = Field(...)
    # Fernet keys, newest first (SD-013). Optional here so processes that never
    # encrypt do not need them; clw.crypto.fernet validates them and refuses to
    # run without them.
    ENCRYPTION_KEYS: SecretStr | None = None
    # Session signing secret (SD-011). Optional here for the same reason;
    # clw.auth.session_jwt refuses to issue or decode without it.
    SESSION_JWT_SECRET: SecretStr | None = None
    # Revocation and rate-limit store (SD-011). No default host: without it
    # Redis is unavailable, which production treats as fail closed. The scheme
    # is checked in clw.auth.redis, not here: a validator error would echo the
    # URL, password included, in the ValidationError.
    REDIS_URL: SecretStr | None = None
    # Analyst sign-in (SD-029): a sign-in-only app registration (openid,
    # profile; no Graph permissions). Optional here; clw.auth.signin refuses to
    # start or complete a sign-in without them.
    MICROSOFT_CLIENT_ID: str | None = None
    MICROSOFT_CLIENT_SECRET: SecretStr | None = None
    OIDC_REDIRECT_URI: str | None = None
    # Where a completed sign-in lands: a fixed local path, never request input.
    POST_LOGIN_PATH: str = "/"
    # The quick start's fictional tenant on fake Graph (SD-051). clw.demo.check_api refuses it in
    # production and alongside any real sign-in setting.
    CLW_DEMO_MODE: bool = False
    # The MCP gateway's URL, shown to a person starting an agent session (display only).
    CLW_MCP_PUBLIC_URL: str | None = None

    @field_validator("DATABASE_URL")
    @classmethod
    def _require_asyncpg(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith("postgresql+asyncpg://"):
            raise ValueError("DATABASE_URL must use the postgresql+asyncpg:// driver")
        return value

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
