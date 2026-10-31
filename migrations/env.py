"""Alembic environment (async, asyncpg).

The URL is taken from the alembic config attribute "database_url" when set
programmatically (tests), otherwise from Settings (DATABASE_URL env var).
"""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from clw.db.base import Base
from clw.db import models  # noqa: F401  (register tables on Base.metadata)

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    url = config.attributes.get("database_url")
    if url:
        return url
    from clw.common.config import get_settings

    return get_settings().DATABASE_URL.get_secret_value()


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline migrations are not supported")
asyncio.run(_run_async())
