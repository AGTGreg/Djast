"""Pytest fixtures for admin tests."""
import pytest_asyncio
import redis.asyncio as redis

from djast.settings import settings


@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_cleanup():
    """Flush Redis DBs used by admin tests before and after each test.

    Admin tests exercise auth endpoints (signup/login) that use DB 1
    (``REDIS_URL``) for blacklisting/lockouts and DB 2
    (``RATE_LIMIT_REDIS_URL``) for SlowAPI counters. Both must be flushed.
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
