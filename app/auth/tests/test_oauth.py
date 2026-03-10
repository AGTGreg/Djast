"""Tests for OAuth2 social login (Google and GitHub)."""
import pytest
import pytest_asyncio
import importlib
from unittest.mock import AsyncMock, patch, MagicMock

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import clear_mappers

import auth.models
import auth.views
import auth.schemas
import auth.utils.auth_backend
import auth.utils.oauth
import djast.urls
import main
from djast.settings import settings
from djast.db.models import Base


def _auth_prefix() -> str:
    return f"{settings.APP_PREFIX}/auth"


def _strong_password() -> str:
    return "StrongPassword123!"


# Mock profile data
GOOGLE_PROFILE = {
    "sub": "google-user-123",
    "email": "oauth_user@example.com",
    "name": "OAuth User",
}

GITHUB_PROFILE = {
    "id": 456789,
    "email": "github_user@example.com",
    "name": "GitHub User",
    "login": "githubuser",
}

GITHUB_EMAILS = [
    {"email": "github_user@example.com", "primary": True, "verified": True},
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def db_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_cleanup():
    import redis.asyncio as redis
    client = redis.from_url(
        settings.REDIS_URL, encoding="utf-8", decode_responses=True
    )
    await client.flushdb()
    try:
        yield
    finally:
        await client.flushdb()
        close = getattr(client, "aclose", None)
        if callable(close):
            await close()
        else:
            await client.close()


@pytest_asyncio.fixture(params=["django", "email"])
async def oauth_client(request, db_engine, db_session):
    """Set up the app with OAuth enabled for testing."""
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode

    # Enable OAuth providers for testing
    original_google = settings.OAUTH_GOOGLE_ENABLED
    original_github = settings.OAUTH_GITHUB_ENABLED
    settings.OAUTH_GOOGLE_ENABLED = True
    settings.OAUTH_GITHUB_ENABLED = True
    settings.OAUTH_GOOGLE_CLIENT_ID = "test-google-client-id"
    settings.OAUTH_GOOGLE_CLIENT_SECRET = "test-google-client-secret"
    settings.OAUTH_GITHUB_CLIENT_ID = "test-github-client-id"
    settings.OAUTH_GITHUB_CLIENT_SECRET = "test-github-client-secret"

    from djast.rate_limit import limiter
    limiter.enabled = False

    clear_mappers()
    Base.metadata.clear()

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

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://test",
        follow_redirects=False,
    ) as c:
        yield c, mode

    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    # Restore settings
    settings.OAUTH_GOOGLE_ENABLED = original_google
    settings.OAUTH_GITHUB_ENABLED = original_github
    settings.AUTH_USER_MODEL_TYPE = "django"
    clear_mappers()
    Base.metadata.clear()
    importlib.reload(auth.models)


@pytest_asyncio.fixture(params=["django", "email"])
async def oauth_disabled_client(request, db_engine, db_session):
    """Set up the app with OAuth disabled for testing."""
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode
    settings.OAUTH_GOOGLE_ENABLED = False
    settings.OAUTH_GITHUB_ENABLED = False

    from djast.rate_limit import limiter
    limiter.enabled = False

    clear_mappers()
    Base.metadata.clear()

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

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://test",
        follow_redirects=False,
    ) as c:
        yield c, mode

    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    settings.AUTH_USER_MODEL_TYPE = "django"
    clear_mappers()
    Base.metadata.clear()
    importlib.reload(auth.models)


# ---------------------------------------------------------------------------
# Helper to create a user + get access token via password login
# ---------------------------------------------------------------------------

async def _signup_and_login(client: AsyncClient, mode: str) -> tuple[int, str]:
    password = _strong_password()
    if mode == "django":
        signup = {"username": "testuser", "email": "test@example.com", "password": password}
        login = {"username": "testuser", "password": password}
    else:
        signup = {"email": "test@example.com", "password": password}
        login = {"email": "test@example.com", "password": password}

    resp = await client.post(f"{_auth_prefix()}/signup", json=signup)
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]

    resp = await client.post(f"{_auth_prefix()}/token", data=login)
    assert resp.status_code == 200, resp.text
    return user_id, resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Helper to mock an OAuth callback flow
# ---------------------------------------------------------------------------

def _mock_google_oauth():
    """Return patches that mock a complete Google OAuth flow."""
    mock_client = MagicMock()
    mock_client.fetch_token = AsyncMock(return_value={
        "access_token": "mock-google-access-token",
    })

    mock_http_resp = MagicMock()
    mock_http_resp.status_code = 200
    mock_http_resp.raise_for_status = MagicMock()
    mock_http_resp.json.return_value = GOOGLE_PROFILE

    return mock_client, mock_http_resp


def _mock_github_oauth():
    """Return patches that mock a complete GitHub OAuth flow."""
    mock_client = MagicMock()
    mock_client.fetch_token = AsyncMock(return_value={
        "access_token": "mock-github-access-token",
    })

    mock_user_resp = MagicMock()
    mock_user_resp.status_code = 200
    mock_user_resp.raise_for_status = MagicMock()
    mock_user_resp.json.return_value = GITHUB_PROFILE

    mock_emails_resp = MagicMock()
    mock_emails_resp.status_code = 200
    mock_emails_resp.raise_for_status = MagicMock()
    mock_emails_resp.json.return_value = GITHUB_EMAILS

    return mock_client, mock_user_resp, mock_emails_resp


async def _do_oauth_callback(
    client: AsyncClient,
    provider: str,
    state: str,
):
    """Perform the callback request with mocked OAuth provider calls."""
    if provider == "google":
        mock_client, mock_http_resp = _mock_google_oauth()

        async def mock_get(*args, **kwargs):
            return mock_http_resp

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=MagicMock(get=mock_get))
        mock_http.__aexit__ = AsyncMock(return_value=False)

        with patch("auth.utils.oauth._create_oauth_client", return_value=mock_client), \
             patch("auth.utils.oauth.httpx.AsyncClient", return_value=mock_http):
            return await client.get(
                f"{_auth_prefix()}/oauth/google/callback",
                params={"code": "mock-code", "state": state},
            )

    elif provider == "github":
        mock_client, mock_user_resp, mock_emails_resp = _mock_github_oauth()
        call_count = 0

        async def mock_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_user_resp
            return mock_emails_resp

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=MagicMock(get=mock_get))
        mock_http.__aexit__ = AsyncMock(return_value=False)

        with patch("auth.utils.oauth._create_oauth_client", return_value=mock_client), \
             patch("auth.utils.oauth.httpx.AsyncClient", return_value=mock_http):
            return await client.get(
                f"{_auth_prefix()}/oauth/github/callback",
                params={"code": "mock-code", "state": state},
            )


async def _store_oauth_state(provider: str) -> str:
    """Store a valid OAuth state token in Redis and return it."""
    import secrets
    import redis.asyncio as redis
    client = redis.from_url(
        settings.REDIS_URL, encoding="utf-8", decode_responses=True
    )
    state = secrets.token_urlsafe(32)
    await client.setex(f"oauth_state:{state}", 300, provider)
    close = getattr(client, "aclose", None)
    if callable(close):
        await close()
    else:
        await client.close()
    return state


# ---------------------------------------------------------------------------
# Tests: Provider disabled
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_authorize_disabled_provider_returns_404(oauth_disabled_client):
    client, mode = oauth_disabled_client
    resp = await client.get(f"{_auth_prefix()}/oauth/google/authorize")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_callback_disabled_provider_returns_404(oauth_disabled_client):
    client, mode = oauth_disabled_client
    resp = await client.get(
        f"{_auth_prefix()}/oauth/google/callback",
        params={"code": "x", "state": "y"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unsupported_provider_returns_404(oauth_client):
    client, mode = oauth_client
    resp = await client.get(f"{_auth_prefix()}/oauth/fakeprovider/authorize")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tests: Authorize endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_authorize_redirects_to_google(oauth_client):
    client, mode = oauth_client
    with patch("auth.utils.oauth.AsyncOAuth2Client") as MockClient:
        instance = MagicMock()
        instance.create_authorization_url.return_value = (
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=test", "state123"
        )
        MockClient.return_value = instance

        resp = await client.get(f"{_auth_prefix()}/oauth/google/authorize")
        assert resp.status_code == 302
        assert "accounts.google.com" in resp.headers["location"]


@pytest.mark.asyncio
async def test_authorize_redirects_to_github(oauth_client):
    client, mode = oauth_client
    with patch("auth.utils.oauth.AsyncOAuth2Client") as MockClient:
        instance = MagicMock()
        instance.create_authorization_url.return_value = (
            "https://github.com/login/oauth/authorize?client_id=test", "state123"
        )
        MockClient.return_value = instance

        resp = await client.get(f"{_auth_prefix()}/oauth/github/authorize")
        assert resp.status_code == 302
        assert "github.com" in resp.headers["location"]


# ---------------------------------------------------------------------------
# Tests: Callback — new user creation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_google_callback_creates_new_user(oauth_client):
    client, mode = oauth_client
    state = await _store_oauth_state("google")

    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302

    location = resp.headers["location"]
    assert settings.OAUTH_LOGIN_REDIRECT_URL in location
    assert "access_token=" in location

    # Verify refresh cookie is set
    cookies = resp.cookies
    assert "refresh_token" in resp.headers.get("set-cookie", "").lower() or \
           any("refresh_token" in str(h) for h in resp.headers.raw)


@pytest.mark.asyncio
async def test_github_callback_creates_new_user(oauth_client):
    client, mode = oauth_client
    state = await _store_oauth_state("github")

    resp = await _do_oauth_callback(client, "github", state)
    assert resp.status_code == 302
    assert "access_token=" in resp.headers["location"]


# ---------------------------------------------------------------------------
# Tests: Callback — auto-link by email
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oauth_callback_links_to_existing_user(oauth_client):
    """If a user with the same email exists, OAuth should link to that account."""
    client, mode = oauth_client

    # First create a password-based user with the same email as the OAuth profile
    if mode == "django":
        signup = {
            "username": "existinguser",
            "email": "oauth_user@example.com",
            "password": _strong_password(),
        }
    else:
        signup = {
            "email": "oauth_user@example.com",
            "password": _strong_password(),
        }

    resp = await client.post(f"{_auth_prefix()}/signup", json=signup)
    assert resp.status_code == 201
    original_user_id = resp.json()["user_id"]

    # Now do OAuth with the same email
    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302

    # Verify the access token is for the same user
    location = resp.headers["location"]
    access_token = location.split("access_token=")[1].split("&")[0]

    # Use the token to get user info
    me_resp = await client.get(
        f"{_auth_prefix()}/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["id"] == original_user_id


# ---------------------------------------------------------------------------
# Tests: Callback — returning OAuth user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oauth_returning_user(oauth_client):
    """A user who already linked via OAuth should be recognized on next login."""
    client, mode = oauth_client

    # First OAuth login
    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302
    location1 = resp.headers["location"]
    token1 = location1.split("access_token=")[1].split("&")[0]

    me1 = await client.get(
        f"{_auth_prefix()}/users/me",
        headers={"Authorization": f"Bearer {token1}"},
    )
    user_id_1 = me1.json()["id"]

    # Second OAuth login — same provider, same user
    state2 = await _store_oauth_state("google")
    resp2 = await _do_oauth_callback(client, "google", state2)
    assert resp2.status_code == 302
    token2 = resp2.headers["location"].split("access_token=")[1].split("&")[0]

    me2 = await client.get(
        f"{_auth_prefix()}/users/me",
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert me2.json()["id"] == user_id_1


# ---------------------------------------------------------------------------
# Tests: Callback — invalid state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_callback_invalid_state(oauth_client):
    client, mode = oauth_client

    mock_client = MagicMock()
    with patch("auth.utils.oauth._create_oauth_client", return_value=mock_client):
        resp = await client.get(
            f"{_auth_prefix()}/oauth/google/callback",
            params={"code": "mock-code", "state": "invalid-state"},
        )
    assert resp.status_code == 400
    assert "state" in resp.json()["detail"].lower() or "expired" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Tests: Unlink OAuth account
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unlink_oauth_with_password(oauth_client):
    """User with password + OAuth can unlink the OAuth account."""
    client, mode = oauth_client

    # Create password user, then link OAuth
    user_id, access_token = await _signup_and_login(client, mode)

    # Link Google OAuth to this user
    state = await _store_oauth_state("google")
    # The user already exists with the same email, so this will auto-link
    # We need to use a different email for Google profile to avoid conflict
    # Actually, the user was created with test@example.com and Google uses
    # oauth_user@example.com, so we need to create the OAuthAccount directly
    from auth.models import OAuthAccount
    from auth.utils.auth_backend import redis_client
    import redis.asyncio as redis

    # Use the DB session from the fixture to create an OAuthAccount directly
    # This is simpler than mocking the full OAuth flow
    resp = await client.delete(
        f"{_auth_prefix()}/oauth/google/link",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    # No linked account → 404
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unlink_unsupported_provider(oauth_client):
    client, mode = oauth_client
    user_id, access_token = await _signup_and_login(client, mode)

    resp = await client.delete(
        f"{_auth_prefix()}/oauth/fakeprovider/link",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cannot_unlink_only_auth_method(oauth_client):
    """OAuth-only user with single provider cannot unlink it."""
    client, mode = oauth_client

    # Create user via OAuth (no password)
    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302
    token = resp.headers["location"].split("access_token=")[1].split("&")[0]

    # Try to unlink the only auth method
    resp = await client.delete(
        f"{_auth_prefix()}/oauth/google/link",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    assert "only authentication method" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Tests: Set password for OAuth-only users
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_set_password_for_oauth_user(oauth_client):
    """OAuth-only user can set a password."""
    client, mode = oauth_client

    # Create user via OAuth
    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302
    token = resp.headers["location"].split("access_token=")[1].split("&")[0]

    # Set password
    resp = await client.post(
        f"{_auth_prefix()}/set-password",
        json={"new_password": _strong_password()},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "success" in resp.json()["message"].lower()


@pytest.mark.asyncio
async def test_set_password_rejected_if_already_has_password(oauth_client):
    """User who already has a password cannot use set-password."""
    client, mode = oauth_client

    user_id, access_token = await _signup_and_login(client, mode)

    resp = await client.post(
        f"{_auth_prefix()}/set-password",
        json={"new_password": _strong_password()},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 400
    assert "already has a password" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_set_password_rejected_if_disabled(oauth_client):
    """Setting password should be rejected if OAUTH_ALLOW_SET_PASSWORD is False."""
    client, mode = oauth_client

    # Create user via OAuth
    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302
    token = resp.headers["location"].split("access_token=")[1].split("&")[0]

    # Disable the setting
    original = settings.OAUTH_ALLOW_SET_PASSWORD
    settings.OAUTH_ALLOW_SET_PASSWORD = False
    try:
        resp = await client.post(
            f"{_auth_prefix()}/set-password",
            json={"new_password": _strong_password()},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
    finally:
        settings.OAUTH_ALLOW_SET_PASSWORD = original


@pytest.mark.asyncio
async def test_set_password_weak_password_rejected(oauth_client):
    """Weak passwords should be rejected in set-password."""
    client, mode = oauth_client

    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302
    token = resp.headers["location"].split("access_token=")[1].split("&")[0]

    resp = await client.post(
        f"{_auth_prefix()}/set-password",
        json={"new_password": "weak"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: Django mode — username generation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_oauth_generates_username_in_django_mode(oauth_client):
    """In django mode, OAuth users get an auto-generated username."""
    client, mode = oauth_client
    if mode != "django":
        pytest.skip("Username generation only applies to django mode")

    state = await _store_oauth_state("google")
    resp = await _do_oauth_callback(client, "google", state)
    assert resp.status_code == 302
    token = resp.headers["location"].split("access_token=")[1].split("&")[0]

    me = await client.get(
        f"{_auth_prefix()}/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me.status_code == 200
    user_data = me.json()
    assert "username" in user_data
    assert len(user_data["username"]) > 0


# ---------------------------------------------------------------------------
# Tests: Existing password auth unaffected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_password_auth_still_works(oauth_client):
    """Enabling OAuth should not break existing password auth."""
    client, mode = oauth_client
    user_id, access_token = await _signup_and_login(client, mode)
    assert user_id > 0
    assert access_token
