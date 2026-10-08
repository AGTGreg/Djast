import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

import main
from djast.database import get_async_session
from djast.settings import settings

from auth.tests.helpers import auth_prefix as _auth_prefix


@pytest_asyncio.fixture(scope="function")
async def rate_limit_client(db_session, schema, auth_mode):
    """App + HTTP client with rate limiting enabled.

    Skips under email auth: these tests post ``username``-based login payloads.
    Redis cleanup is handled by the autouse ``redis_cleanup`` fixture.
    """
    if auth_mode != "django":
        pytest.skip("Rate-limit tests post username-based login payloads")

    # The limits themselves are baked into the route decorators at import time
    # (``@limiter.limit(settings.AUTH_RATE_LIMIT_LOGIN)``), so they cannot be
    # changed from here -- reloading the module would only build a second
    # Limiter that the already-built app does not use. Toggling ``enabled`` on
    # the instance the app holds is the part that works.
    from djast.rate_limit import limiter
    limiter.enabled = True

    app = main.app
    app.dependency_overrides[get_async_session] = lambda: db_session

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
        yield c

    app.dependency_overrides.clear()
    await db_session.rollback()


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
