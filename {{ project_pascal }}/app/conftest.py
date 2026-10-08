"""Project-wide pytest fixtures.

Fixtures defined here are auto-discovered by pytest for any test under ``app/``,
so an app's own tests can use ``auth_client`` and ``schema`` without repeating
any setup. See docs/testing.md.

``AUTH_USER_MODEL_TYPE`` is a build-time choice, not a per-test one: the ``User``
model's shape is fixed when ``auth.models`` is imported. The suite therefore runs
under whichever mode the environment sets, and CI runs it once per mode::

    AUTH_USER_MODEL_TYPE=django pytest
    AUTH_USER_MODEL_TYPE=email  pytest

Do not try to switch modes inside a running process. The previous approach --
``clear_mappers()`` + ``Base.metadata.clear()`` + ``importlib.reload()`` -- is
global: it unmaps *every* model in the process, including the application's, and
nothing restores them. See auth/tests/test_model_isolation.py.
"""
import os

import pytest
import pytest_asyncio
import redis.asyncio as redis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import main
from djast.database import get_async_session
from djast.db.models import Base
from djast.settings import settings

# Default: in-memory SQLite, one fresh database per test.
# Point TEST_DATABASE_URL at the compose Postgres to run the suite against the
# backend the template actually deploys:
#   TEST_DATABASE_URL=postgresql+asyncpg://myuser:pw@db:5432/test_db pytest
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:",
)


@pytest.fixture(scope="session")
def auth_mode() -> str:
    """The auth mode this process is running under ("django" or "email")."""
    return settings.AUTH_USER_MODEL_TYPE


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_cleanup():
    """Flush the Redis DBs the app uses, before and after each test.

    Auth endpoints use DB 1 (``REDIS_URL``) for token blacklisting, OAuth state,
    email cooldowns and login lockouts. SlowAPI uses DB 2
    (``RATE_LIMIT_REDIS_URL``) for rate-limit counters. Both must be flushed to
    prevent state leaking between tests.
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


@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_lifecycle():
    """Reconnect the module-level Redis client on the current event loop.

    ``auth.utils.auth_backend.redis_client`` is created once at import.
    ``redis.asyncio`` opens its sockets lazily and binds them to whichever loop
    is running at the time, but pytest-asyncio gives each test its own loop, so
    a pooled connection from a previous test raises when reused. That raise is
    swallowed by ``is_blacklisted``'s ``except``, which then fails closed and
    rejects a perfectly valid token.

    Disconnecting the pool around each test makes the next command reconnect on
    the loop that is actually running.
    """
    from auth.utils import auth_backend
    await auth_backend.redis_client.connection_pool.disconnect()
    try:
        yield
    finally:
        await auth_backend.redis_client.connection_pool.disconnect()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """Async engine for tests, disposed after each test.

    This fixture deliberately does **no** schema management: the ``schema``
    fixture owns that. Do not add ``create_all``/``drop_all`` here -- two
    fixtures both managing the schema will fight, and the failure shows up as a
    foreign-key error in an unrelated test.
    """
    engine = create_async_engine(TEST_DATABASE_URL, echo=False, future=True)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """Async session bound to the test engine."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def schema(db_engine):
    """Create the schema for a test and drop it afterwards.

    Builds the whole of ``Base.metadata``, so an app's own models are created
    too -- anything importable and mapped is included, nothing to register.

    Drops first: ``create_all`` defaults to ``checkfirst=True``, so a table left
    behind by an earlier test would be kept with its old shape rather than
    rebuilt.
    """
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def auth_client(db_session, schema, auth_mode):
    """App + HTTP client for the auth mode this process runs under.

    Yields ``(client, mode, db_session)``. Tests that only need two of the
    three can unpack with a leading underscore: ``client, _mode, _db = ...``.

    Use ``auth.tests.helpers.signup_and_login(client, mode)`` to get a token --
    it builds the right payload for either auth mode.
    """
    # Functional tests run with rate limiting off; the rate_limit_client
    # fixture re-enables it for its own tests.
    from djast.rate_limit import limiter
    limiter.enabled = False

    app = main.app
    app.dependency_overrides[get_async_session] = lambda: db_session

    # Use https so Secure cookies (refresh_token) are sent on subsequent
    # requests within the client session.
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://test",
    ) as c:
        yield c, auth_mode, db_session

    app.dependency_overrides.clear()
    # Release the session before the schema fixture drops the tables. Without
    # this the session sits idle-in-transaction holding locks and DROP TABLE
    # blocks on it forever -- the suite hangs with no traceback.
    await db_session.rollback()
