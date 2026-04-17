"""Project-wide pytest fixtures.

Fixtures defined here are auto-discovered by pytest for any test under ``app/``.
App-specific fixtures (e.g. Redis cleanup for auth tests) live in each
app's ``tests/conftest.py``.
"""
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """In-memory SQLite engine, disposed after each test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """Async session bound to the in-memory engine."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session
