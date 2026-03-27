from __future__ import annotations

import redis.asyncio as aioredis
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from djast.settings import settings

router = APIRouter(tags=["health"])


@router.get("/health")
async def liveness() -> dict[str, str]:
    """Liveness probe — confirms the ASGI app is responding."""
    return {"status": "ok"}


@router.get("/health/ready")
async def readiness() -> JSONResponse:
    """Readiness probe — checks database and Redis connectivity."""
    checks: dict[str, str] = {}

    # Database check
    try:
        from djast.database import async_session_factory
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "unavailable"

    # Redis check
    try:
        client = aioredis.from_url(
            settings.REDIS_URL, decode_responses=True
        )
        try:
            await client.ping()
            checks["redis"] = "ok"
        finally:
            await client.aclose()
    except Exception:
        checks["redis"] = "unavailable"

    all_ok = all(v == "ok" for v in checks.values())
    status = "ok" if all_ok else "unavailable"
    status_code = 200 if all_ok else 503

    return JSONResponse(
        content={"status": status, **checks},
        status_code=status_code,
    )
