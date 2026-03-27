import importlib
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import clear_mappers

import main
import djast.urls
from djast.db.models import Base
from djast.settings import settings


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
async def health_client(db_engine):
    """Set up the app with a test database for health checks."""
    test_session_factory = async_sessionmaker(
        db_engine, expire_on_commit=False
    )

    clear_mappers()
    Base.metadata.clear()

    importlib.reload(djast.urls)
    importlib.reload(main)

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app = main.app
    from djast.database import get_async_session

    async def _override_session():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_async_session] = _override_session

    with patch("djast.database.async_session_factory", test_session_factory):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://test",
        ) as client:
            yield client

    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    clear_mappers()
    Base.metadata.clear()


@pytest.mark.asyncio
async def test_health_liveness_returns_200(health_client):
    resp = await health_client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_health_ready_all_services_up(health_client):
    with patch("djast.health.aioredis") as mock_redis_mod:
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.aclose = AsyncMock()
        mock_redis_mod.from_url.return_value = mock_client

        resp = await health_client.get("/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["database"] == "ok"
        assert data["redis"] == "ok"


@pytest.mark.asyncio
async def test_health_ready_database_down(health_client):
    with patch("djast.health.aioredis") as mock_redis_mod:
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        mock_client.aclose = AsyncMock()
        mock_redis_mod.from_url.return_value = mock_client

        with patch(
            "djast.database.async_session_factory",
            side_effect=Exception("DB down"),
        ):
            resp = await health_client.get("/health/ready")
            assert resp.status_code == 503
            data = resp.json()
            assert data["database"] == "unavailable"
            assert data["redis"] == "ok"
            assert data["status"] == "unavailable"


@pytest.mark.asyncio
async def test_health_ready_redis_down(health_client):
    with patch("djast.health.aioredis") as mock_redis_mod:
        mock_redis_mod.from_url.side_effect = Exception("Redis down")

        resp = await health_client.get("/health/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["database"] == "ok"
        assert data["redis"] == "unavailable"
        assert data["status"] == "unavailable"


@pytest.mark.asyncio
async def test_health_endpoints_not_under_api_prefix(health_client):
    resp = await health_client.get(f"{settings.APP_PREFIX}/health")
    assert resp.status_code in (404, 405)
