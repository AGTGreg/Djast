"""Tests for SPAStaticFiles utility."""
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

from djast.utils.staticfiles import SPAStaticFiles


@pytest.fixture
def spa_dist(tmp_path):
    """Create a minimal SPA dist directory."""
    (tmp_path / "index.html").write_text("<html><body>SPA</body></html>")
    (tmp_path / "favicon.svg").write_text("<svg/>")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "app.js").write_text("console.log('app');")
    (assets / "style.css").write_text("body { margin: 0; }")
    return tmp_path


@pytest.fixture
def spa_app(spa_dist):
    """FastAPI app with SPAStaticFiles mounted."""
    app = FastAPI()
    app.mount("/spa", SPAStaticFiles(directory=str(spa_dist), html=True), name="spa")
    return app


@pytest_asyncio.fixture
async def client(spa_app):
    async with AsyncClient(
        transport=ASGITransport(app=spa_app), base_url="https://test"
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spa_root_returns_index_html(client):
    resp = await client.get("/spa/")
    assert resp.status_code == 200
    assert "SPA" in resp.text


@pytest.mark.asyncio
async def test_spa_unknown_path_returns_index_html(client):
    """Client-side routes should fall back to index.html."""
    resp = await client.get("/spa/some/deep/route")
    assert resp.status_code == 200
    assert "SPA" in resp.text


@pytest.mark.asyncio
async def test_spa_serves_real_file(client):
    resp = await client.get("/spa/favicon.svg")
    assert resp.status_code == 200
    assert "<svg/>" in resp.text


@pytest.mark.asyncio
async def test_spa_serves_asset_subdirectory(client):
    resp = await client.get("/spa/assets/app.js")
    assert resp.status_code == 200
    assert "console.log" in resp.text


@pytest.mark.asyncio
async def test_spa_serves_css_asset(client):
    resp = await client.get("/spa/assets/style.css")
    assert resp.status_code == 200
    assert "margin" in resp.text
