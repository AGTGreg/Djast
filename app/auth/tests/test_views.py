import pytest
import pytest_asyncio
import importlib
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from djast.settings import settings
from djast.db.models import Base
import auth.models
import auth.views
import auth.schemas
import djast.urls
import main


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Create an in-memory SQLite engine for testing."""
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
    async_session_factory = async_sessionmaker(
        db_engine,
        expire_on_commit=False,
    )
    async with async_session_factory() as session:
        yield session


@pytest_asyncio.fixture(params=["django", "email"])
async def auth_client(request, db_engine, db_session):
    """
    Fixture that sets up the app with the specified auth mode.
    Reloads modules and recreates DB tables.
    """
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode

    # Clear metadata to avoid "Table already defined" errors
    Base.metadata.clear()

    # Reload modules to pick up the new setting
    importlib.reload(auth.models)
    importlib.reload(auth.schemas)
    importlib.reload(auth.views)
    importlib.reload(djast.urls)
    importlib.reload(main)

    # Create tables for the new model definitions
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Override dependency
    app = main.app
    from djast.database import get_async_session
    app.dependency_overrides[get_async_session] = lambda: db_session

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, mode

    app.dependency_overrides.clear()

    # Cleanup tables
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    # Restore default state to avoid side effects on other tests
    settings.AUTH_USER_MODEL_TYPE = "django"
    Base.metadata.clear()
    importlib.reload(auth.models)
    importlib.reload(auth.schemas)
    importlib.reload(auth.views)
    importlib.reload(djast.urls)
    importlib.reload(main)


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_and_me(auth_client, db_session):
    """Test login and /users/me/ endpoint for both user types."""
    client, mode = auth_client

    # Import User from the reloaded module
    from auth.models import User

    password = "secure_password"

    if mode == "django":
        username = "testuser"
        email = "test@example.com"
        await User.create_user(db_session, username=username, password=password, email=email)
        # Django mode uses OAuth2PasswordRequestForm which expects 'username'
        login_data = {"username": username, "password": password}
    else:
        email = "test@example.com"
        await User.create_user(db_session, email=email, password=password)
        # Email mode uses OAuth2EmailRequestForm which expects 'email'
        login_data = {"email": email, "password": password}

    # 1. Test Login
    response = await client.post("/api/v1/auth/token", data=login_data)
    assert response.status_code == 200, response.text
    tokens = response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # 2. Test Get Me
    response = await client.get(
        "/api/v1/auth/users/me/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    user_data = response.json()

    if mode == "django":
        assert user_data["username"] == "testuser"
        assert user_data["email"] == "test@example.com"
    else:
        assert user_data["email"] == "test@example.com"
        assert "username" not in user_data

    # 3. Test Refresh Token
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    # Access token might be identical if generated in the same second
    # assert new_tokens["access_token"] != access_token
    assert new_tokens["refresh_token"] != refresh_token

    # 4. Test Logout
    response = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": new_tokens["refresh_token"]}
    )
    assert response.status_code == 200

    # Verify refresh token is invalid
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": new_tokens["refresh_token"]}
    )
    assert response.status_code == 401
