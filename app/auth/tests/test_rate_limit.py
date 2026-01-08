import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from djast.settings import settings
import auth.views
import main
import importlib


def _auth_prefix() -> str:
    return f"{settings.APP_PREFIX}/auth"


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create an in-memory SQLite engine for testing."""
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """Create an async session for testing."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    async_session_factory = async_sessionmaker(
        db_engine,
        expire_on_commit=False,
    )
    async with async_session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def rate_limit_client(db_engine, db_session):
    """
    Fixture that sets up the app with rate limiting enabled.
    """
    # Reset settings to defaults
    settings.AUTH_RATE_LIMIT_SIGNUP = "5/minute"
    settings.AUTH_RATE_LIMIT_LOGIN = "5/minute"
    settings.AUTH_RATE_LIMIT_REFRESH = "20/minute"
    settings.AUTH_RATE_LIMIT_CHANGE_PASSWORD = "3/minute"
    settings.AUTH_RATE_LIMIT_REVOKE = "20/minute"
    settings.AUTH_RATE_LIMIT_USER_ME = "100/minute"

    # Reload rate_limit module to get a fresh Limiter instance (clears in-memory state if any)
    import djast.rate_limit
    importlib.reload(djast.rate_limit)

    # Ensure limiter is enabled (on the new instance)
    from djast.rate_limit import limiter
    limiter.enabled = True

    importlib.reload(auth.views)
    importlib.reload(main)

    app = main.app
    from djast.database import get_async_session
    app.dependency_overrides[get_async_session] = lambda: db_session

    # Create tables
    from djast.db.models import Base
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Ensure redis is clean
    import redis.asyncio as redis
    redis_client = redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    await redis_client.flushdb()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
        yield c

    await redis_client.flushdb()
    await redis_client.aclose()
    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def _strong_password() -> str:
    return "StrongPassword123!"


def _new_user_payload(i: int):
    # Minimal valid payload
    return {
        "username": f"user{i}",
        "email": f"user{i}@example.com",
        "password": _strong_password()
    }


@pytest.mark.asyncio
async def test_signup_rate_limit(rate_limit_client):
    """
    Test that signup is rate limited according to AUTH_RATE_LIMIT_SIGNUP (default 5/minute).
    """
    client = rate_limit_client
    limit = int(settings.AUTH_RATE_LIMIT_SIGNUP.split("/")[0])

    # Send VALID payloads to trigger rate limit (invalid ones fail schema validaton before rate limit)
    for i in range(limit):
        payload = _new_user_payload(i)
        resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
        # Should be 201 Created
        assert resp.status_code == 201

    # The next one should fail
    payload = _new_user_payload(limit)
    resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert resp.status_code == 429, f"Should be rate limited after {limit} requests"
    # SlowAPI default detail is "X per Y minute"
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_login_rate_limit(rate_limit_client):
    """
    Test that login is rate limited according to AUTH_RATE_LIMIT_LOGIN (default 5/minute).
    """
    client = rate_limit_client
    limit = int(settings.AUTH_RATE_LIMIT_LOGIN.split("/")[0])

    for _ in range(limit):
        resp = await client.post(f"{_auth_prefix()}/token", data={"username": "foo", "password": "bar"})
        assert resp.status_code != 429

    resp = await client.post(f"{_auth_prefix()}/token", data={"username": "foo", "password": "bar"})
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_refresh_rate_limit(rate_limit_client):
    """
    Test that refresh is rate limited according to AUTH_RATE_LIMIT_REFRESH (default 20/minute).
    """
    client = rate_limit_client
    limit = int(settings.AUTH_RATE_LIMIT_REFRESH.split("/")[0])

    for _ in range(limit):
        resp = await client.post(f"{_auth_prefix()}/refresh")
        assert resp.status_code != 429

    resp = await client.post(f"{_auth_prefix()}/refresh")
    assert resp.status_code == 429
