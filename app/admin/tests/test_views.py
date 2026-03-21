"""Tests for admin API endpoints."""
from __future__ import annotations

import secrets
import importlib

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import clear_mappers

from djast.db.models import Base
from djast.settings import settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _admin_prefix() -> str:
    return f"{settings.APP_PREFIX}/admin"


def _auth_prefix() -> str:
    return f"{settings.APP_PREFIX}/auth"


def _strong_password(seed: str | None = None) -> str:
    suffix = seed or ""
    return f"StrongPassword123!{suffix}"


def _new_user_payload(mode: str, *, password: str) -> tuple[dict, dict]:
    """Returns (signup_payload, login_form_payload)."""
    unique = secrets.token_hex(6)
    if mode == "django":
        username = f"user_{unique}"
        email = f"{username}@example.com"
        return (
            {"username": username, "email": email, "password": password},
            {"username": username, "password": password},
        )
    email = f"user_{unique}@example.com"
    return (
        {"email": email, "password": password},
        {"email": email, "password": password},
    )


async def _create_admin_user(
    client: AsyncClient, mode: str,
) -> tuple[int, str]:
    """Sign up a user, promote to staff, log in, return (user_id, token)."""
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]

    # Promote to staff via direct DB update
    from auth.models import User
    from djast.database import get_async_session

    # Use the overridden session
    session = client._transport.app.dependency_overrides[get_async_session]()
    user = await User.objects(session).get(id=user_id)
    await user.update(session, is_staff=True, is_superuser=True)

    token_resp = await client.post(
        f"{_auth_prefix()}/token", data=login_form,
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]
    return user_id, access_token


async def _create_regular_user(
    client: AsyncClient, mode: str,
) -> tuple[int, str]:
    """Sign up and log in a non-staff user."""
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]

    token_resp = await client.post(
        f"{_auth_prefix()}/token", data=login_form,
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = token_resp.json()["access_token"]
    return user_id, access_token


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_cleanup():
    import redis.asyncio as redis

    client = redis.from_url(
        settings.REDIS_URL, encoding="utf-8", decode_responses=True,
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
async def admin_client(request, db_engine):
    """Set up app with specified auth mode, return (client, mode)."""
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode

    from djast.rate_limit import limiter
    limiter.enabled = False

    import auth.forms
    import auth.models
    import auth.schemas
    import auth.utils.auth_backend
    import auth.utils.oauth
    import auth.views
    import admin.registry
    import admin.views
    import djast.urls
    import main

    clear_mappers()
    Base.metadata.clear()

    importlib.reload(auth.forms)
    importlib.reload(auth.models)
    importlib.reload(auth.schemas)
    importlib.reload(auth.utils.auth_backend)
    importlib.reload(auth.utils.oauth)
    importlib.reload(auth.views)
    importlib.reload(admin.registry)
    importlib.reload(admin.views)
    importlib.reload(djast.urls)
    importlib.reload(main)

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app = main.app
    from djast.database import get_async_session

    async_session_factory = async_sessionmaker(
        db_engine, expire_on_commit=False,
    )
    session = async_session_factory()
    app.dependency_overrides[get_async_session] = lambda: session

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://test"
    ) as c:
        yield c, mode

    await session.close()
    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    import admin.registry
    import admin.views
    import djast.urls
    import main

    settings.AUTH_USER_MODEL_TYPE = "django"
    clear_mappers()
    Base.metadata.clear()
    importlib.reload(auth.forms)
    importlib.reload(auth.models)
    importlib.reload(admin.registry)
    importlib.reload(admin.views)
    importlib.reload(djast.urls)
    importlib.reload(main)


# ---------------------------------------------------------------------------
# Config endpoint (public)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_config_returns_auth_type(admin_client):
    client, mode = admin_client
    resp = await client.get(f"{_admin_prefix()}/config/")
    assert resp.status_code == 200
    assert resp.json()["auth_type"] == mode


# ---------------------------------------------------------------------------
# Admin login endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_login_staff_user_succeeds(admin_client):
    client, mode = admin_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert resp.status_code == 201
    user_id = resp.json()["user_id"]

    # Promote to staff
    from auth.models import User
    from djast.database import get_async_session

    session = client._transport.app.dependency_overrides[get_async_session]()
    user = await User.objects(session).get(id=user_id)
    await user.update(session, is_staff=True)

    resp = await client.post(f"{_admin_prefix()}/login/", data=login_form)
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_admin_login_non_staff_returns_403(admin_client):
    client, mode = admin_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert resp.status_code == 201

    resp = await client.post(f"{_admin_prefix()}/login/", data=login_form)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required."


@pytest.mark.asyncio
async def test_admin_login_invalid_credentials_returns_401(admin_client):
    client, mode = admin_client
    if mode == "django":
        login_form = {"username": "nonexistent", "password": "Wrong1234!"}
    else:
        login_form = {"email": "nonexistent@example.com", "password": "Wrong1234!"}

    resp = await client.post(f"{_admin_prefix()}/login/", data=login_form)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Auth gates
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_schema_unauthenticated_returns_401(admin_client):
    client, _ = admin_client
    resp = await client.get(f"{_admin_prefix()}/schema/")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_schema_non_staff_returns_403(admin_client):
    client, mode = admin_client
    _, token = await _create_regular_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/schema/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Schema endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_schema_returns_apps(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/schema/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "apps" in data
    assert "Auth" in data["apps"]
    assert "User" in data["apps"]["Auth"]["models"]


@pytest.mark.asyncio
async def test_schema_user_has_password_change(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/schema/",
        headers={"Authorization": f"Bearer {token}"},
    )
    user_model = resp.json()["apps"]["Auth"]["models"]["User"]
    assert user_model["has_password_change"] is True
    field_names = [f["name"] for f in user_model["fields"]]
    assert "password" not in field_names


# ---------------------------------------------------------------------------
# List endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_returns_paginated(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Auth/User/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "count" in data
    assert "results" in data
    assert "page" in data
    assert data["page"] == 1
    # At least the admin user exists
    assert data["count"] >= 1


@pytest.mark.asyncio
async def test_list_search(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Auth/User/?search=nonexistent_xyz",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


@pytest.mark.asyncio
async def test_list_ordering(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Auth/User/?ordering=-id",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1


@pytest.mark.asyncio
async def test_list_ordering_ignores_excluded_fields(admin_client):
    """Ordering by an excluded field (e.g. password) is silently ignored."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Auth/User/?ordering=password",
        headers={"Authorization": f"Bearer {token}"},
    )
    # Should succeed (200) and not crash — password ordering is silently ignored.
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1


@pytest.mark.asyncio
async def test_list_404_for_unknown_model(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Fake/Model/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Detail endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detail_returns_record(admin_client):
    client, mode = admin_client
    user_id, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Auth/User/{user_id}/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == user_id


@pytest.mark.asyncio
async def test_detail_404_for_missing_record(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)
    resp = await client.get(
        f"{_admin_prefix()}/Auth/User/99999/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Create endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_user_record(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    if mode == "django":
        payload = {
            "username": "newuser",
            "email": "new@example.com",
            "password": _strong_password("new"),
        }
    else:
        payload = {
            "email": "new@example.com",
            "password": _strong_password("new"),
        }

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["id"] is not None


@pytest.mark.asyncio
async def test_create_with_weak_password(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    if mode == "django":
        payload = {"username": "weakuser", "password": "weak"}
    else:
        payload = {"email": "weak@example.com", "password": "weak"}

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_user_without_password_returns_422(admin_client):
    """Creating a user model without a password must fail with 422."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    if mode == "django":
        payload = {"username": "nopwuser"}
    else:
        payload = {"email": "nopw@example.com"}

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_user_without_identity_field_returns_422(admin_client):
    """Creating a user without username (django) or email (email mode) must fail."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    # Only password — missing the identity field entirely
    payload = {"password": _strong_password("noid")}

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_user_with_empty_identity_field_returns_422(admin_client):
    """Creating a user with empty string username/email must fail."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    if mode == "django":
        payload = {"username": "", "password": _strong_password("empty")}
    else:
        payload = {"email": "", "password": _strong_password("empty")}

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_user_with_whitespace_identity_field_returns_400(admin_client):
    """Creating a user with whitespace-only username/email must fail."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    if mode == "django":
        payload = {"username": "   ", "password": _strong_password("ws")}
    else:
        payload = {"email": "   ", "password": _strong_password("ws")}

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Update endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_record(admin_client):
    client, mode = admin_client
    user_id, token = await _create_admin_user(client, mode)

    # GET current record to build full payload
    detail = await client.get(
        f"{_admin_prefix()}/Auth/User/{user_id}/",
        headers={"Authorization": f"Bearer {token}"},
    )
    payload = detail.json()
    payload["is_active"] = False

    resp = await client.put(
        f"{_admin_prefix()}/Auth/User/{user_id}/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


@pytest.mark.asyncio
async def test_update_404_for_missing(admin_client):
    client, mode = admin_client
    user_id, token = await _create_admin_user(client, mode)

    # Use a valid payload shape but non-existent record
    detail = await client.get(
        f"{_admin_prefix()}/Auth/User/{user_id}/",
        headers={"Authorization": f"Bearer {token}"},
    )
    payload = detail.json()

    resp = await client.put(
        f"{_admin_prefix()}/Auth/User/99999/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Delete endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delete_record(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    # Create a user to delete
    password = _strong_password("del")
    if mode == "django":
        payload = {"username": "delme", "password": password}
    else:
        payload = {"email": "delme@example.com", "password": password}
    create_resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    record_id = create_resp.json()["id"]

    resp = await client.delete(
        f"{_admin_prefix()}/Auth/User/{record_id}/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_delete_404_for_missing(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    resp = await client.delete(
        f"{_admin_prefix()}/Auth/User/99999/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Bulk delete
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bulk_delete(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    # Create two users to delete
    ids = []
    for i in range(2):
        password = _strong_password(f"bulk{i}")
        if mode == "django":
            payload = {"username": f"bulk{i}", "password": password}
        else:
            payload = {"email": f"bulk{i}@example.com", "password": password}
        r = await client.post(
            f"{_admin_prefix()}/Auth/User/",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        ids.append(r.json()["id"])

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/bulk-delete/",
        json={"ids": ids},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["deleted"] == 2


@pytest.mark.asyncio
async def test_bulk_delete_empty_ids_returns_422(admin_client):
    """Empty ids list is rejected by schema validation."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/bulk-delete/",
        json={"ids": []},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Set password
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_set_password_success(admin_client):
    client, mode = admin_client
    user_id, token = await _create_admin_user(client, mode)

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/{user_id}/set-password/",
        json={"new_password": _strong_password("new")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Password changed successfully."


@pytest.mark.asyncio
async def test_set_password_weak(admin_client):
    client, mode = admin_client
    user_id, token = await _create_admin_user(client, mode)

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/{user_id}/set-password/",
        json={"new_password": "weak"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_set_password_user_not_found(admin_client):
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/99999/set-password/",
        json={"new_password": _strong_password()},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_rejects_invalid_field_type(admin_client):
    """Sending a string where an integer is expected returns 422."""
    client, mode = admin_client
    _, token = await _create_admin_user(client, mode)

    if mode == "django":
        payload = {
            "username": "badtype",
            "password": _strong_password("type"),
            "is_active": "not_a_bool_or_int",
        }
    else:
        payload = {
            "email": "badtype@example.com",
            "password": _strong_password("type"),
            "is_active": "not_a_bool_or_int",
        }

    resp = await client.post(
        f"{_admin_prefix()}/Auth/User/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_update_rejects_invalid_field_type(admin_client):
    """Sending invalid type on PUT returns 422."""
    client, mode = admin_client
    user_id, token = await _create_admin_user(client, mode)

    detail = await client.get(
        f"{_admin_prefix()}/Auth/User/{user_id}/",
        headers={"Authorization": f"Bearer {token}"},
    )
    payload = detail.json()
    payload["is_active"] = "not_a_bool_or_int"

    resp = await client.put(
        f"{_admin_prefix()}/Auth/User/{user_id}/",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422
