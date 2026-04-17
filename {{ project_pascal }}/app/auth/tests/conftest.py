"""Pytest fixtures for auth tests."""
import importlib

import pytest_asyncio
import redis.asyncio as redis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.orm import clear_mappers

import auth.forms
import auth.models
import auth.schemas
import auth.utils.auth_backend
import auth.utils.oauth
import auth.views
import djast.urls
import main
from djast.db.models import Base
from djast.settings import settings


@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_cleanup():
    """Flush Redis DBs used by auth tests before and after each test.

    Auth endpoints use DB 1 (``REDIS_URL``) for token blacklisting, OAuth
    state, email cooldowns, and login lockouts. SlowAPI uses DB 2
    (``RATE_LIMIT_REDIS_URL``) for rate-limit counters. Both must be flushed
    to prevent state leakage between tests.
    """
    clients = [
        redis.from_url(url, encoding="utf-8", decode_responses=True)
        for url in (settings.REDIS_URL, settings.RATE_LIMIT_REDIS_URL)
    ]
    for client in clients:
        await client.flushdb()
    try:
        yield
    finally:
        for client in clients:
            await client.flushdb()
            close = getattr(client, "aclose", None)
            if callable(close):
                await close()
            else:
                await client.close()


@pytest_asyncio.fixture(params=["django", "email"])
async def auth_client(request, db_engine, db_session):
    """App + HTTP client parametrized over both auth modes.

    Yields ``(client, mode, db_session)``. Tests that only need two of the
    three can unpack with a leading underscore: ``client, _mode, _db = ...``.
    """
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode

    # Functional tests run with rate limiting off; the rate_limit_client
    # fixture re-enables it for its own tests.
    from djast.rate_limit import limiter
    limiter.enabled = False

    clear_mappers()
    Base.metadata.clear()

    importlib.reload(auth.forms)
    importlib.reload(auth.models)
    importlib.reload(auth.schemas)
    importlib.reload(auth.utils.auth_backend)
    importlib.reload(auth.utils.oauth)
    importlib.reload(auth.views)
    importlib.reload(djast.urls)
    importlib.reload(main)

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app = main.app
    from djast.database import get_async_session
    app.dependency_overrides[get_async_session] = lambda: db_session

    # Use https so Secure cookies (refresh_token) are sent on subsequent
    # requests within the client session.
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://test",
    ) as c:
        yield c, mode, db_session

    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    settings.AUTH_USER_MODEL_TYPE = "django"
    clear_mappers()
    Base.metadata.clear()
    importlib.reload(auth.forms)
    importlib.reload(auth.models)
