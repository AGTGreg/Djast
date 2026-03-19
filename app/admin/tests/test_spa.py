"""Integration tests for admin SPA serving via setup_app() hook."""
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from main import create_app

DIST_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"


@pytest_asyncio.fixture
async def client():
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# SPA serving
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_spa_root(client):
    """GET /admin/ returns the SPA index.html."""
    resp = await client.get("/admin/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_admin_spa_deep_route(client):
    """Client-side routes return index.html (SPA fallback)."""
    resp = await client.get("/admin/auth/user")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_admin_spa_favicon(client):
    """Static files in dist root are served directly."""
    resp = await client.get("/admin/favicon.svg")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_spa_js_asset(client):
    """JS bundles in assets/ are served."""
    js_files = list((DIST_DIR / "assets").glob("*.js"))
    assert js_files, "No JS bundle found in dist/assets/"
    filename = js_files[0].name
    resp = await client.get(f"/admin/assets/{filename}")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_spa_css_asset(client):
    """CSS bundles in assets/ are served."""
    css_files = list((DIST_DIR / "assets").glob("*.css"))
    assert css_files, "No CSS bundle found in dist/assets/"
    filename = css_files[0].name
    resp = await client.get(f"/admin/assets/{filename}")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# API routes unaffected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_api_config_unaffected(client):
    """API routes at APP_PREFIX still work (no interference from SPA mount)."""
    from djast.settings import settings
    resp = await client.get(f"{settings.APP_PREFIX}/admin/config/")
    assert resp.status_code == 200
    assert "auth_type" in resp.json()


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_path_traversal_blocked(client):
    """Percent-encoded path traversal must not leak files outside dist.

    StaticFiles blocks the traversal (path escapes the directory → 404),
    then the SPA fallback returns index.html. The critical check is that
    no sensitive file content is leaked — the response must be the SPA.
    """
    resp = await client.get("/admin/..%2F..%2F..%2Fetc%2Fpasswd")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "passwd" not in resp.text
    assert "root:" not in resp.text
