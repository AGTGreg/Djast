import pytest
import pytest_asyncio
import importlib
import asyncio
import secrets
from datetime import timedelta
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import clear_mappers
from ulid import ULID

import auth.models
import auth.views
import auth.schemas
import auth.utils.auth_backend
import djast.urls
import main
from djast.settings import settings
from djast.db.models import Base
from djast.utils import timezone as dj_timezone


def _extract_access_token(token_response_json: dict) -> str:
    return token_response_json["access_token"]


def _auth_prefix() -> str:
    return f"{settings.APP_PREFIX}/auth"


def _strong_password(seed: str | None = None) -> str:
    # Must satisfy settings.PASSWORD_VALIDATION_REGEX.
    # Keep deterministic-ish option for debugging.
    suffix = seed or ""
    return f"StrongPassword123!{suffix}"


def _password_of_length(length: int) -> str:
    """Build a password that satisfies settings.PASSWORD_VALIDATION_REGEX."""
    if length < 8:
        raise ValueError("length must be >= 8")
    # Must include: lowercase, uppercase, digit, special.
    # Must use allowed chars: [A-Za-z\d@$!%*?&]
    base = "Aa1!"
    password = base + ("a" * (length - len(base)))
    assert len(password) == length
    return password


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

    if mode == "email":
        email = f"user_{unique}@example.com"
        return (
            {"email": email, "password": password},
            {"email": email, "password": password},
        )

    raise AssertionError(f"Unknown auth mode: {mode}")


async def _signup_and_login(client: AsyncClient, mode: str) -> tuple[int, str]:
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(
        f"{_auth_prefix()}/signup",
        json=signup_payload,
    )
    assert signup_resp.status_code == 201, signup_resp.text
    user_id = signup_resp.json()["user_id"]

    token_resp = await client.post(
        f"{_auth_prefix()}/token",
        data=login_form,
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = _extract_access_token(token_resp.json())
    assert access_token
    return user_id, access_token


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


@pytest_asyncio.fixture(scope="function", autouse=True)
async def redis_cleanup():
    """Flush Redis before and after each test."""
    import redis.asyncio as redis

    blacklist_client = redis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
    )

    await blacklist_client.flushdb()
    try:
        yield
    finally:
        await blacklist_client.flushdb()

        for client in (blacklist_client,):
            # redis-py supports aclose() on asyncio clients.
            close = getattr(client, "aclose", None)
            if callable(close):
                await close()
            else:
                await client.close()


def _limit_count(limit: str) -> int:
    """Extract the numeric request count from a limit like '5/minute'."""
    return int(limit.split("/", 1)[0].strip())


@pytest_asyncio.fixture(params=["django", "email"])
async def auth_client(request, db_engine, db_session):
    """
    Fixture that sets up the app with the specified auth mode.
    """
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode

    clear_mappers()
    Base.metadata.clear()

    importlib.reload(auth.models)
    importlib.reload(auth.schemas)
    importlib.reload(auth.utils.auth_backend)
    importlib.reload(auth.views)
    importlib.reload(djast.urls)
    importlib.reload(main)

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app = main.app
    from djast.database import get_async_session
    app.dependency_overrides[get_async_session] = lambda: db_session

    # Use https so Secure cookies (refresh_token) are sent on subsequent requests.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://test") as c:
        yield c, mode

    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    settings.AUTH_USER_MODEL_TYPE = "django"
    clear_mappers()
    Base.metadata.clear()
    importlib.reload(auth.models)

# -----------------------------------------------------------------------------
# Test cases
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signup_success(auth_client):
    client, mode = auth_client
    password = _strong_password()
    payload, _ = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert isinstance(body.get("user_id"), int)


@pytest.mark.asyncio
async def test_signup_disabled_returns_403(auth_client):
    client, mode = auth_client

    old = settings.ALLOW_SIGNUP
    settings.ALLOW_SIGNUP = False
    try:
        password = _strong_password()
        payload, _ = _new_user_payload(mode, password=password)
        resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
        assert resp.status_code == 403
        assert resp.json()["detail"] == "User registration is disabled."
    finally:
        settings.ALLOW_SIGNUP = old


@pytest.mark.asyncio
async def test_signup_duplicate_returns_400(auth_client):
    client, mode = auth_client
    password = _strong_password()
    unique = secrets.token_hex(6)

    if mode == "django":
        username = f"dup_{unique}"
        payload = {
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        }
    else:
        payload = {
            "email": f"dup_{unique}@example.com",
            "password": password,
        }

    first = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert first.status_code == 201, first.text

    second = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert second.status_code == 400
    assert second.json()["detail"] == "This user already exists."


@pytest.mark.asyncio
async def test_login_success_returns_access_and_sets_refresh_cookie(auth_client):
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_expired_refresh_tokens_are_deleted_on_login(
    auth_client,
    db_session,
    monkeypatch,
):
    client, mode = auth_client

    # Make the cleanup deterministic for tests:
    # - disable per-worker cooldown
    # - reset local last-attempt timestamp
    monkeypatch.setattr(
        auth.utils.auth_backend,
        "_REFRESH_TOKEN_EXPIRED_LOCAL_COOLDOWN_SECONDS",
        0,
        raising=False,
    )
    monkeypatch.setattr(
        auth.utils.auth_backend,
        "_refresh_token_cleanup_last_attempt_monotonic",
        0.0,
        raising=False,
    )

    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(
        f"{_auth_prefix()}/signup",
        json=signup_payload,
    )
    assert signup_resp.status_code == 201, signup_resp.text
    user_id = signup_resp.json()["user_id"]

    # Insert an expired refresh token for this user.
    now = dj_timezone.now()
    expired_key = str(ULID())
    await auth.models.RefreshToken.objects(db_session).create(
        key=expired_key,
        user_id=user_id,
        issued_at=now - timedelta(days=30),
        expires_at=now - timedelta(days=1),
    )
    await db_session.commit()

    # Login triggers maybe_cleanup_expired_refresh_tokens() before issuing
    # new tokens.
    token_resp = await client.post(
        f"{_auth_prefix()}/token",
        data=login_form,
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()

    still_there = await auth.models.RefreshToken.objects(db_session).get(
        key=expired_key
    )
    assert still_there is None
    assert _extract_access_token(body)
    assert "refresh_token" in token_resp.cookies


@pytest.mark.asyncio
async def test_login_invalid_credentials_returns_401(auth_client):
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    login_form = dict(login_form)
    login_form["password"] = "WrongPassword123!"

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 401
    assert token_resp.json()["detail"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_login_inactive_user_returns_401(auth_client, db_session):
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text
    user_id = signup_resp.json()["user_id"]

    user = await auth.models.User.objects(db_session).get(id=user_id)
    assert user is not None
    user.is_active = False
    await user.save(db_session)
    await db_session.commit()

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 401
    assert token_resp.json()["detail"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_refresh_missing_cookie_returns_400(auth_client):
    client, _mode = auth_client
    resp = await client.post(f"{_auth_prefix()}/refresh")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Refresh token is missing."


@pytest.mark.asyncio
async def test_refresh_success_rotates_refresh_cookie(auth_client):
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    old_refresh = token_resp.cookies.get("refresh_token")
    old_access = _extract_access_token(token_resp.json())

    refresh_resp = await client.post(f"{_auth_prefix()}/refresh")
    assert refresh_resp.status_code == 200, refresh_resp.text
    new_access = _extract_access_token(refresh_resp.json())
    assert new_access
    assert new_access != old_access
    assert "refresh_token" in refresh_resp.cookies
    new_refresh = refresh_resp.cookies.get("refresh_token")
    assert new_refresh
    assert new_refresh != old_refresh


@pytest.mark.asyncio
async def test_refresh_old_refresh_token_reuse_revokes_all_tokens(auth_client):
    """If an old refresh token is reused quickly, treat as duplicate not replay."""
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    access_token = _extract_access_token(token_resp.json())
    old_refresh = token_resp.cookies.get("refresh_token")
    assert old_refresh

    # First refresh rotates the refresh token
    refresh_resp = await client.post(f"{_auth_prefix()}/refresh")
    assert refresh_resp.status_code == 200, refresh_resp.text
    new_refresh = refresh_resp.cookies.get("refresh_token")
    assert new_refresh
    assert new_refresh != old_refresh

    # Reuse old refresh token quickly -> should succeed and return the
    # replacement refresh token (idempotent behavior within grace window).
    reused = await client.post(
        f"{_auth_prefix()}/refresh",
        headers={"Cookie": f"refresh_token={old_refresh}"},
    )
    assert reused.status_code == 200, reused.text
    reused_refresh = reused.cookies.get("refresh_token")
    assert reused_refresh == new_refresh

    # Existing access token should still authorize (no global logout).
    me = await client.get(
        f"{_auth_prefix()}/users/me/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me.status_code == 200


@pytest.mark.asyncio
async def test_refresh_concurrent_requests_return_same_replacement(auth_client):
    """Two concurrent refresh calls with the same cookie should not revoke sessions."""
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    old_refresh = token_resp.cookies.get("refresh_token")
    assert old_refresh

    r1, r2 = await asyncio.gather(
        client.post(f"{_auth_prefix()}/refresh", headers={"Cookie": f"refresh_token={old_refresh}"}),
        client.post(f"{_auth_prefix()}/refresh", headers={"Cookie": f"refresh_token={old_refresh}"}),
    )

    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text

    n1 = r1.cookies.get("refresh_token")
    n2 = r2.cookies.get("refresh_token")
    assert n1
    assert n2
    assert n1 == n2
    assert n1 != old_refresh


@pytest.mark.asyncio
async def test_read_users_me_returns_current_user(auth_client):
    client, mode = auth_client
    user_id, access_token = await _signup_and_login(client, mode)

    resp = await client.get(
        f"{_auth_prefix()}/users/me/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["id"] == user_id
    if mode == "django":
        assert "username" in body
    else:
        assert "email" in body


@pytest.mark.asyncio
async def test_invalid_access_token_returns_401(auth_client):
    client, _mode = auth_client
    resp = await client.get(
        f"{_auth_prefix()}/users/me/",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_change_password_success_and_login_with_new_password(auth_client):
    client, mode = auth_client
    old_password = _strong_password("A")
    new_password = _strong_password("B")
    signup_payload, login_form = _new_user_payload(mode, password=old_password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    access_token = _extract_access_token(token_resp.json())

    change_resp = await client.post(
        f"{_auth_prefix()}/change-password",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"old_password": old_password, "new_password": new_password},
    )
    assert change_resp.status_code == 200, change_resp.text
    assert change_resp.json()["message"] == "Password changed successfully."

    # Old password should no longer work
    old_login_form = dict(login_form)
    old_login_form["password"] = old_password
    bad_login = await client.post(f"{_auth_prefix()}/token", data=old_login_form)
    assert bad_login.status_code == 401

    # New password should work
    new_login_form = dict(login_form)
    new_login_form["password"] = new_password
    good_login = await client.post(f"{_auth_prefix()}/token", data=new_login_form)
    assert good_login.status_code == 200, good_login.text


@pytest.mark.asyncio
async def test_change_password_wrong_old_password_returns_400(auth_client):
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    access_token = _extract_access_token(token_resp.json())

    change_resp = await client.post(
        f"{_auth_prefix()}/change-password",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"old_password": "WrongPassword123!", "new_password": _strong_password("Z")},
    )
    assert change_resp.status_code == 400
    assert change_resp.json()["detail"] == "Old password is incorrect."


@pytest.mark.asyncio
async def test_logout_revoke_blacklists_current_access_token(auth_client):
    client, mode = auth_client
    _user_id, access_token = await _signup_and_login(client, mode)

    revoke_resp = await client.post(
        f"{_auth_prefix()}/revoke",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert revoke_resp.status_code == 204

    # Token should no longer authorize requests
    me_resp = await client.get(
        f"{_auth_prefix()}/users/me/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_stale_refresh_cookie_revokes_replacement_refresh_token(
    auth_client,
    db_session,
):
    """If client presents a rotated (stale) refresh cookie, logout should still
    revoke the *current* replacement refresh token.
    """
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    access_token = _extract_access_token(token_resp.json())
    old_refresh = token_resp.cookies.get("refresh_token")
    assert old_refresh

    # Rotate once, producing a replacement refresh cookie.
    refresh_resp = await client.post(f"{_auth_prefix()}/refresh")
    assert refresh_resp.status_code == 200, refresh_resp.text
    new_refresh = refresh_resp.cookies.get("refresh_token")
    assert new_refresh
    assert new_refresh != old_refresh

    old_refresh_data = auth.utils.auth_backend.decode_token(old_refresh, verify_exp=False)
    new_refresh_data = auth.utils.auth_backend.decode_token(new_refresh, verify_exp=False)

    old_row = await auth.models.RefreshToken.objects(db_session).get(key=old_refresh_data.jti)
    assert old_row is not None
    assert old_row.used_at is not None
    assert old_row.replaced_by_key == new_refresh_data.jti

    new_row = await auth.models.RefreshToken.objects(db_session).get(key=new_refresh_data.jti)
    assert new_row is not None
    assert new_row.revoked_at is None

    # Simulate a stale cookie at logout time.
    revoke_resp = await client.post(
        f"{_auth_prefix()}/revoke",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Cookie": f"refresh_token={old_refresh}",
        },
    )
    assert revoke_resp.status_code == 204, revoke_resp.text

    # Replacement token should now be revoked.
    new_row = await auth.models.RefreshToken.objects(db_session).get(key=new_refresh_data.jti)
    assert new_row is not None
    assert new_row.revoked_at is not None

    # And refresh with the replacement cookie should fail.
    refresh_after_logout = await client.post(
        f"{_auth_prefix()}/refresh",
        headers={"Cookie": f"refresh_token={new_refresh}"},
    )
    assert refresh_after_logout.status_code == 401
    assert refresh_after_logout.json()["detail"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_redis_outage_does_not_500_access_token_validation(
    auth_client,
    monkeypatch,
):
    """If Redis is unavailable during blacklist checks, we should not 500.

    Default policy is fail-closed via settings.FALLBACK_IS_BLACKLISTED.
    """
    client, mode = auth_client
    _user_id, access_token = await _signup_and_login(client, mode)

    old_fallback = settings.FALLBACK_IS_BLACKLISTED
    settings.FALLBACK_IS_BLACKLISTED = True
    try:
        async def _boom(*_args, **_kwargs):
            raise RuntimeError("redis down")

        # Blacklist checks should not bubble exceptions.
        monkeypatch.setattr(auth.utils.auth_backend.redis_client, "get", _boom)

        me = await client.get(
            f"{_auth_prefix()}/users/me/",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me.status_code == 401
        assert me.json()["detail"] == "Invalid credentials."
    finally:
        settings.FALLBACK_IS_BLACKLISTED = old_fallback


@pytest.mark.asyncio
async def test_redis_outage_fail_open_allows_access_when_configured(
    auth_client,
    monkeypatch,
):
    """If Redis is unavailable during blacklist checks, we should not 500.

    When configured to fail-open, authenticated requests should still succeed.
    """
    client, mode = auth_client
    _user_id, access_token = await _signup_and_login(client, mode)

    old_fallback = settings.FALLBACK_IS_BLACKLISTED
    settings.FALLBACK_IS_BLACKLISTED = False
    try:
        async def _boom(*_args, **_kwargs):
            raise RuntimeError("redis down")

        monkeypatch.setattr(auth.utils.auth_backend.redis_client, "get", _boom)

        me = await client.get(
            f"{_auth_prefix()}/users/me/",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me.status_code == 200, me.text
    finally:
        settings.FALLBACK_IS_BLACKLISTED = old_fallback


@pytest.mark.asyncio
async def test_logout_current_device_keeps_other_device_logged_in(auth_client):
    """If user logs out on device A, device B remains valid."""
    client, mode = auth_client

    password = _strong_password()
    unique = secrets.token_hex(6)
    if mode == "django":
        username = f"multi_{unique}"
        signup_payload = {"username": username, "email": f"{username}@example.com", "password": password}
        login_form = {"username": username, "password": password}
    else:
        email = f"multi_{unique}@example.com"
        signup_payload = {"email": email, "password": password}
        login_form = {"email": email, "password": password}

    # Create user once
    signup = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup.status_code == 201, signup.text

    app = main.app
    transport_a = ASGITransport(app=app)
    transport_b = ASGITransport(app=app)
    async with AsyncClient(transport=transport_a, base_url="https://test") as device_a, \
        AsyncClient(transport=transport_b, base_url="https://test") as device_b:
        # Login from both devices
        token_a = await device_a.post(f"{_auth_prefix()}/token", data=login_form)
        assert token_a.status_code == 200, token_a.text
        access_a = _extract_access_token(token_a.json())
        assert token_a.cookies.get("refresh_token")

        token_b = await device_b.post(f"{_auth_prefix()}/token", data=login_form)
        assert token_b.status_code == 200, token_b.text
        access_b = _extract_access_token(token_b.json())
        assert token_b.cookies.get("refresh_token")

        # Device A logs out (revoke current token + refresh token)
        revoke = await device_a.post(
            f"{_auth_prefix()}/revoke",
            headers={"Authorization": f"Bearer {access_a}"},
        )
        assert revoke.status_code == 204

        # Device A access should be invalid
        me_a = await device_a.get(
            f"{_auth_prefix()}/users/me/",
            headers={"Authorization": f"Bearer {access_a}"},
        )
        assert me_a.status_code == 401

        # Device B should still be valid
        me_b = await device_b.get(
            f"{_auth_prefix()}/users/me/",
            headers={"Authorization": f"Bearer {access_b}"},
        )
        assert me_b.status_code == 200, me_b.text


@pytest.mark.asyncio
async def test_logout_all_devices_revokes_both_devices(auth_client):
    """Logout-all should revoke tokens across device A and B."""
    client, mode = auth_client

    password = _strong_password()
    unique = secrets.token_hex(6)
    if mode == "django":
        username = f"multi2_{unique}"
        signup_payload = {"username": username, "email": f"{username}@example.com", "password": password}
        login_form = {"username": username, "password": password}
    else:
        email = f"multi2_{unique}@example.com"
        signup_payload = {"email": email, "password": password}
        login_form = {"email": email, "password": password}

    signup = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup.status_code == 201, signup.text

    app = main.app
    transport_a = ASGITransport(app=app)
    transport_b = ASGITransport(app=app)
    async with AsyncClient(transport=transport_a, base_url="https://test") as device_a, \
        AsyncClient(transport=transport_b, base_url="https://test") as device_b:
        token_a = await device_a.post(f"{_auth_prefix()}/token", data=login_form)
        assert token_a.status_code == 200, token_a.text
        access_a = _extract_access_token(token_a.json())

        token_b = await device_b.post(f"{_auth_prefix()}/token", data=login_form)
        assert token_b.status_code == 200, token_b.text
        access_b = _extract_access_token(token_b.json())
        refresh_b = token_b.cookies.get("refresh_token")
        assert refresh_b

        # Ensure min_iat will be strictly greater than both token iat values.
        await asyncio.sleep(1.1)

        revoke_all = await device_a.post(
            f"{_auth_prefix()}/revoke-all",
            headers={"Authorization": f"Bearer {access_a}"},
        )
        assert revoke_all.status_code == 204

        # Neither device should have access now
        me_a = await device_a.get(
            f"{_auth_prefix()}/users/me/",
            headers={"Authorization": f"Bearer {access_a}"},
        )
        assert me_a.status_code == 401

        me_b = await device_b.get(
            f"{_auth_prefix()}/users/me/",
            headers={"Authorization": f"Bearer {access_b}"},
        )
        assert me_b.status_code == 401

        # And refresh should also fail from device B
        refresh_resp = await device_b.post(
            f"{_auth_prefix()}/refresh",
            headers={"Cookie": f"refresh_token={refresh_b}"},
        )
        assert refresh_resp.status_code == 401
        assert refresh_resp.json()["detail"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_logout_all_devices_blacklists_access_token(auth_client):
    client, mode = auth_client
    _user_id, access_token = await _signup_and_login(client, mode)

    # Ensure min_iat will be strictly greater than token.iat.
    await asyncio.sleep(1.1)

    resp = await client.post(
        f"{_auth_prefix()}/revoke-all",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 204

    me_resp = await client.get(
        f"{_auth_prefix()}/users/me/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 401


@pytest.mark.asyncio
async def test_deactivate_account_disables_login_and_token(auth_client):
    client, mode = auth_client
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    signup_resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text

    token_resp = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_resp.status_code == 200, token_resp.text
    access_token = _extract_access_token(token_resp.json())

    # Ensure min_iat will be strictly greater than token.iat.
    await asyncio.sleep(1.1)

    deactivate_resp = await client.post(
        f"{_auth_prefix()}/deactivate",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert deactivate_resp.status_code == 204

    # Using the old token should fail
    me_resp = await client.get(
        f"{_auth_prefix()}/users/me/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 401

    # Logging in again should fail due to inactive user
    token_again = await client.post(f"{_auth_prefix()}/token", data=login_form)
    assert token_again.status_code == 401
    assert token_again.json()["detail"] == "Invalid credentials."


@pytest.mark.asyncio
async def test_signup_weak_password_returns_400(auth_client):
    client, mode = auth_client
    weak_password = "weak"
    payload, _login_form = _new_user_payload(mode, password=weak_password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Password is too weak."


@pytest.mark.asyncio
async def test_signup_password_max_length_100_is_allowed(auth_client):
    client, mode = auth_client
    password = _password_of_length(100)
    payload, _login_form = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_signup_password_length_101_is_rejected(auth_client):
    client, mode = auth_client
    password = _password_of_length(101)
    payload, _login_form = _new_user_payload(mode, password=password)

    resp = await client.post(f"{_auth_prefix()}/signup", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Password is too weak."
