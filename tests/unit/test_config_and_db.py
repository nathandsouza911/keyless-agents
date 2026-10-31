import importlib

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from clw.common.config import Settings

PG = "postgresql+asyncpg://u:p@127.0.0.1:5433/clw"


def test_database_url_is_required(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    "url",
    ["postgresql://u:p@h/db", "sqlite+aiosqlite:///x.db", "postgresql+psycopg://u:p@h/db"],
)
def test_database_url_must_be_asyncpg(url):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, DATABASE_URL=url)


def test_environment_is_constrained():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, DATABASE_URL=PG, ENVIRONMENT="prod")
    assert Settings(_env_file=None, DATABASE_URL=PG, ENVIRONMENT="production").is_production


def test_unknown_settings_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, DATABASE_URL=PG, SESSION_SECRET_TYPO="x")


def test_database_url_not_echoed_in_repr():
    assert "u:p@" not in repr(Settings(_env_file=None, DATABASE_URL=PG))


def test_importing_session_module_needs_no_database(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    import clw.db.session as session_module

    importlib.reload(session_module)  # must not build an engine at import


async def test_session_factory_yields_async_session():
    from clw.db.session import build_sessionmaker

    maker = build_sessionmaker(Settings(_env_file=None, DATABASE_URL=PG))
    async with maker() as session:  # no I/O until first query
        assert isinstance(session, AsyncSession)
    await maker.kw["bind"].dispose()


def test_get_settings_reads_process_env_and_ignores_unrelated_vars(monkeypatch, tmp_path):
    from clw.common import config

    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("POSTGRES_USER=clw\nDATABASE_URL=postgresql://wrong\n")
    monkeypatch.setenv("DATABASE_URL", PG)
    monkeypatch.setenv("POSTGRES_USER", "clw")
    config.get_settings.cache_clear()
    try:
        assert config.get_settings().DATABASE_URL.get_secret_value() == PG
    finally:
        config.get_settings.cache_clear()


# ---------------------------------------------------------------- no credentials in validation errors

SENTINEL = "pw-SENTINEL-4c1e9b"


def _all_representations(exc: ValidationError) -> dict[str, str]:
    import traceback

    return {
        "str": str(exc),
        "repr": repr(exc),
        "args": repr(exc.args),
        "errors()": repr(exc.errors()),
        "errors(include_context)": repr(exc.errors(include_url=True, include_context=True, include_input=True)),
        "json()": exc.json(),
        "traceback": "".join(traceback.format_exception(exc)),
        "context": repr(exc.__context__) + repr(exc.__cause__),
    }


def _assert_hidden(exc: ValidationError) -> None:
    leaked = [name for name, text in _all_representations(exc).items() if SENTINEL in text]
    assert leaked == []
    assert exc.__context__ is None and exc.__cause__ is None


@pytest.mark.parametrize(
    "url",
    [f"postgresql://clw:{SENTINEL}@db:5432/clw", f"postgresql+psycopg://clw:{SENTINEL}@db/clw", f"{SENTINEL}"],
)
def test_bad_database_url_error_hides_the_password(url):
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None, DATABASE_URL=url)
    _assert_hidden(info.value)
    # Still enough to debug: which setting, and why.
    (error,) = info.value.errors()
    assert error["loc"] == ("DATABASE_URL",)
    assert "postgresql+asyncpg://" in error["msg"]
    assert "DATABASE_URL" in str(info.value) and "postgresql+asyncpg://" in str(info.value)


def test_bad_database_url_from_environment_hides_the_password(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"postgresql://clw:{SENTINEL}@db/clw")
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None)
    _assert_hidden(info.value)
    assert info.value.errors()[0]["loc"] == ("DATABASE_URL",)


def test_other_settings_errors_hide_values_too():
    # Intentional: every Settings error hides its input (a typo'd key may hold a secret).
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None, DATABASE_URL=PG, SESSION_SECRET_TYPO=SENTINEL, ENVIRONMENT=f"prod-{SENTINEL}")
    _assert_hidden(info.value)
    errors = {e["loc"]: e for e in info.value.errors()}
    assert errors[("SESSION_SECRET_TYPO",)]["type"] == "extra_forbidden"
    assert errors[("ENVIRONMENT",)]["type"] == "literal_error"
    assert "'development', 'test' or 'production'" in errors[("ENVIRONMENT",)]["msg"]
    assert all(e["input"] == "<hidden>" for e in info.value.errors())


def test_missing_database_url_still_reported(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None)
    (error,) = info.value.errors()
    assert (error["loc"], error["type"]) == (("DATABASE_URL",), "missing")
