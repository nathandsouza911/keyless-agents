"""The api's start-up check (SD-011, SD-027): production refuses to start
without a reachable Redis, which holds session revocation and rate limits."""

from __future__ import annotations

import pytest

from clw.api.main import create_app
from tests.auth_fixtures import auth_env  # noqa: F401 (fixture)


def _app():
    return create_app(sessionmaker=None, writer=None, catalog={}, rate_limited=False)


@pytest.mark.parametrize("redis_url", ["redis://127.0.0.1:1/0", None], ids=["unreachable", "unset"])
async def test_production_refuses_to_start_without_redis(auth_env, redis_url):
    auth_env(environment="production", redis_url=redis_url)
    app = _app()
    with pytest.raises(RuntimeError, match="Redis is required in production"):
        async with app.router.lifespan_context(app):
            pass


@pytest.mark.parametrize("environment", ["development", "test"])
async def test_outside_production_it_starts_without_redis(auth_env, environment):
    auth_env(environment=environment)
    app = _app()
    async with app.router.lifespan_context(app):
        pass
