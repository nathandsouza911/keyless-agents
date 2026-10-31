"""Async database sessions.

Adapted from legacy app/db/session.py: async engine only (the sync engine
is dropped), and the engine is built on demand from Settings instead of at
import time, so importing this module needs no database configuration.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.common.config import Settings, get_settings


def build_sessionmaker(settings: Settings) -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(
        settings.DATABASE_URL.get_secret_value(),
        echo=False,
        pool_pre_ping=True,
    )
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return build_sessionmaker(get_settings())


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session
