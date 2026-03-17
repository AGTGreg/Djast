import pytest
import pytest_asyncio
import importlib
import secrets
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import clear_mappers

import auth.forms
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

    if mode == "email":
        email = f"user_{unique}@example.com"
        return (
            {"email": email, "password": password},
            {"email": email, "password": password},
        )

    raise AssertionError(f"Unknown auth mode: {mode}")


def _extract_access_token(token_response_json: dict) -> str:
    return token_response_json["access_token"]



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
            close = getattr(client, "aclose", None)
            if callable(close):
                await close()
            else:
                await client.close()


@pytest_asyncio.fixture(params=["django", "email"])
async def auth_client(request, db_engine, db_session):
    """
    Fixture that sets up the app with the specified auth mode.
    Yields (client, mode, db_session) so tests can query the DB directly.
    """
    mode = request.param
    settings.AUTH_USER_MODEL_TYPE = mode

    # Disable rate limiting for functional tests
    from djast.rate_limit import limiter
    limiter.enabled = False

    clear_mappers()
    Base.metadata.clear()

    importlib.reload(auth.forms)
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
        transport=ASGITransport(app=app), base_url="https://test"
    ) as c:
        yield c, mode, db_session

    app.dependency_overrides.clear()

    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    settings.AUTH_USER_MODEL_TYPE = "django"
    clear_mappers()
    Base.metadata.clear()
    importlib.reload(auth.forms)
    importlib.reload(auth.models)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------


async def _signup(client: AsyncClient, mode: str) -> tuple[int, dict, dict]:
    """Sign up a user. Returns (user_id, signup_payload, login_form)."""
    password = _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=password)

    with patch(
        "auth.utils.auth_backend.send_verification_email",
        new_callable=AsyncMock,
    ):
        resp = await client.post(
            f"{_auth_prefix()}/signup", json=signup_payload
        )
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]
    return user_id, signup_payload, login_form


# -----------------------------------------------------------------------------
# Test cases
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_signup_creates_email_address(auth_client):
    """After signup, an EmailAddress record should exist with verified=False."""
    client, mode, session = auth_client
    user_id, signup_payload, _ = await _signup(client, mode)

    from auth.models import EmailAddress
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    expected_email = signup_payload.get("email", "")
    if expected_email:
        assert email_addr is not None
        assert email_addr.email == expected_email
        assert email_addr.verified is False
        assert email_addr.primary is True
    else:
        # Django mode with no email — no EmailAddress row
        assert email_addr is None


@pytest.mark.asyncio
async def test_verify_email_success(auth_client):
    """Sign up, create token, POST /verify-email, assert 200 and verified=True."""
    client, mode, session = auth_client
    user_id, signup_payload, _ = await _signup(client, mode)

    from auth.models import User, EmailAddress
    user = await User.objects(session).get(id=user_id)
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    if not email_addr:
        pytest.skip("No email address for this user mode")

    from auth.utils.tokens import get_email_verification_token_generator
    token_gen = get_email_verification_token_generator()
    token = token_gen.make_token(user, email_addr)

    resp = await client.post(
        f"{_auth_prefix()}/verify-email",
        json={"token": token},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["message"] == "Email verified successfully."

    # Refresh from DB
    await session.refresh(email_addr)
    assert email_addr.verified is True


@pytest.mark.asyncio
async def test_verify_email_invalid_token(auth_client):
    """POST with garbage token should return 400."""
    client, mode, session = auth_client

    resp = await client.post(
        f"{_auth_prefix()}/verify-email",
        json={"token": "totally-invalid-garbage-token"},
    )
    assert resp.status_code == 400
    assert "Invalid or expired" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_verify_email_expired_token(auth_client):
    """Token that is older than max_age_seconds should fail validation."""
    client, mode, session = auth_client
    user_id, _, _ = await _signup(client, mode)

    from auth.models import User, EmailAddress
    user = await User.objects(session).get(id=user_id)
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    if not email_addr:
        pytest.skip("No email address for this user mode")

    from auth.utils.tokens import get_email_verification_token_generator
    token_gen = get_email_verification_token_generator()
    token = token_gen.make_token(user, email_addr)

    # Patch time.time to simulate expiration (90000 seconds ahead, > 86400 max_age)
    import time as time_mod
    real_time = time_mod.time

    with patch("auth.utils.tokens.time.time", return_value=real_time() + 90000):
        resp = await client.post(
            f"{_auth_prefix()}/verify-email",
            json={"token": token},
        )

    assert resp.status_code == 400
    assert "Invalid or expired" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_verify_email_single_use(auth_client):
    """Verifying the same token twice should fail the second time."""
    client, mode, session = auth_client
    user_id, _, _ = await _signup(client, mode)

    from auth.models import User, EmailAddress
    user = await User.objects(session).get(id=user_id)
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    if not email_addr:
        pytest.skip("No email address for this user mode")

    from auth.utils.tokens import get_email_verification_token_generator
    token_gen = get_email_verification_token_generator()
    token = token_gen.make_token(user, email_addr)

    # First verification should succeed
    resp1 = await client.post(
        f"{_auth_prefix()}/verify-email",
        json={"token": token},
    )
    assert resp1.status_code == 200

    # Second verification with the same token should fail
    # (email_addr.verified changed, so HMAC no longer matches)
    resp2 = await client.post(
        f"{_auth_prefix()}/verify-email",
        json={"token": token},
    )
    assert resp2.status_code == 400
    assert "Invalid or expired" in resp2.json()["detail"]


@pytest.mark.asyncio
async def test_login_blocked_mandatory_verification(auth_client):
    """With EMAIL_VERIFICATION='mandatory', unverified users cannot login."""
    client, mode, session = auth_client
    _, _, login_form = await _signup(client, mode)

    # Django mode without email has no EmailAddress row — verification gate passes
    from auth.models import EmailAddress
    email_addr = await EmailAddress.objects(session).get(
        user_id=(await client.post(
            f"{_auth_prefix()}/signup",
            json=_new_user_payload(mode, password=_strong_password("b"))[0],
        )).json().get("user_id"),
        primary=True,
    )
    # Use the original user — re-check with the first signup
    old_val = settings.EMAIL_VERIFICATION
    settings.EMAIL_VERIFICATION = "mandatory"
    try:
        resp = await client.post(
            f"{_auth_prefix()}/token",
            data=login_form,
        )
        # If there's an email address, login should be blocked
        from auth.models import EmailAddress as EA
        first_user_email = await EA.objects(session).get(
            user_id=1, primary=True,
        )
        if first_user_email and not first_user_email.verified:
            assert resp.status_code == 403, resp.text
            assert resp.json()["detail"] == "Email verification required."
        else:
            # No email address row — gate passes
            assert resp.status_code == 200
    finally:
        settings.EMAIL_VERIFICATION = old_val


@pytest.mark.asyncio
async def test_login_allowed_optional_verification(auth_client):
    """With EMAIL_VERIFICATION='optional', unverified users can still login."""
    client, mode, session = auth_client

    old_val = settings.EMAIL_VERIFICATION
    settings.EMAIL_VERIFICATION = "optional"
    try:
        _, _, login_form = await _signup(client, mode)
        resp = await client.post(
            f"{_auth_prefix()}/token",
            data=login_form,
        )
        assert resp.status_code == 200, resp.text
        assert "access_token" in resp.json()
    finally:
        settings.EMAIL_VERIFICATION = old_val


@pytest.mark.asyncio
async def test_login_allowed_after_verification(auth_client):
    """With EMAIL_VERIFICATION='mandatory', verified users can login."""
    client, mode, session = auth_client
    user_id, _, login_form = await _signup(client, mode)

    from auth.models import User, EmailAddress
    user = await User.objects(session).get(id=user_id)
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    if not email_addr:
        pytest.skip("No email address for this user mode")

    # Verify the email
    from auth.utils.tokens import get_email_verification_token_generator
    token_gen = get_email_verification_token_generator()
    token = token_gen.make_token(user, email_addr)

    verify_resp = await client.post(
        f"{_auth_prefix()}/verify-email",
        json={"token": token},
    )
    assert verify_resp.status_code == 200

    # Now login with mandatory verification should succeed
    old_val = settings.EMAIL_VERIFICATION
    settings.EMAIL_VERIFICATION = "mandatory"
    try:
        resp = await client.post(
            f"{_auth_prefix()}/token",
            data=login_form,
        )
        assert resp.status_code == 200, resp.text
        assert "access_token" in resp.json()
    finally:
        settings.EMAIL_VERIFICATION = old_val


@pytest.mark.asyncio
async def test_resend_verification_requires_auth(auth_client):
    """POST to /resend-verification without auth should return 401 or 403."""
    client, mode, session = auth_client

    resp = await client.post(f"{_auth_prefix()}/resend-verification")
    # Without auth, either 401 (missing bearer) or 403 (CSRF) is acceptable
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_resend_verification_already_verified(auth_client):
    """Resending after email is already verified should return 400."""
    client, mode, session = auth_client
    user_id, _, login_form = await _signup(client, mode)

    from auth.models import User, EmailAddress
    user = await User.objects(session).get(id=user_id)
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    if not email_addr:
        pytest.skip("No email address for this user mode")

    # Verify the email first
    from auth.utils.tokens import get_email_verification_token_generator
    token_gen = get_email_verification_token_generator()
    token = token_gen.make_token(user, email_addr)

    verify_resp = await client.post(
        f"{_auth_prefix()}/verify-email",
        json={"token": token},
    )
    assert verify_resp.status_code == 200

    # Login to get access token
    login_resp = await client.post(
        f"{_auth_prefix()}/token",
        data=login_form,
    )
    assert login_resp.status_code == 200
    access_token = _extract_access_token(login_resp.json())

    # Try to resend verification
    resp = await client.post(
        f"{_auth_prefix()}/resend-verification",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Email is already verified."


@pytest.mark.asyncio
async def test_resend_verification_cooldown(auth_client):
    """Second resend within cooldown period should return 429."""
    client, mode, session = auth_client
    user_id, _, login_form = await _signup(client, mode)

    from auth.models import EmailAddress
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )

    if not email_addr:
        pytest.skip("No email address for this user mode")

    # Login to get access token
    login_resp = await client.post(
        f"{_auth_prefix()}/token",
        data=login_form,
    )
    assert login_resp.status_code == 200
    access_token = _extract_access_token(login_resp.json())

    auth_headers = {"Authorization": f"Bearer {access_token}"}

    # First resend should succeed (mock out send_verification_email entirely)
    with patch(
        "auth.utils.auth_backend.send_verification_email",
        new_callable=AsyncMock,
    ) as mock_send:
        resp1 = await client.post(
            f"{_auth_prefix()}/resend-verification",
            headers=auth_headers,
        )
    assert resp1.status_code == 200

    # Second resend should hit cooldown — mock send_verification_email to raise
    from auth import exceptions as auth_exceptions

    async def raise_cooldown(*args, **kwargs):
        raise auth_exceptions.EmailCooldown("Please wait.")

    with patch(
        "auth.utils.auth_backend.send_verification_email",
        side_effect=raise_cooldown,
    ):
        resp2 = await client.post(
            f"{_auth_prefix()}/resend-verification",
            headers=auth_headers,
        )
    assert resp2.status_code == 429
    assert "wait" in resp2.json()["detail"].lower()


@pytest.mark.asyncio
async def test_django_user_no_email_bypasses_verification(auth_client):
    """Django user without email should bypass mandatory verification gate."""
    client, mode, session = auth_client

    if mode != "django":
        pytest.skip("Only applicable to django auth mode")

    # Create a user without email
    unique = secrets.token_hex(6)
    username = f"noemail_{unique}"
    password = _strong_password()
    signup_payload = {"username": username, "password": password}
    login_form = {"username": username, "password": password}

    with patch(
        "auth.utils.auth_backend.send_verification_email",
        new_callable=AsyncMock,
    ):
        resp = await client.post(
            f"{_auth_prefix()}/signup", json=signup_payload
        )
    assert resp.status_code == 201, resp.text
    user_id = resp.json()["user_id"]

    # Confirm no EmailAddress row exists
    from auth.models import EmailAddress
    email_addr = await EmailAddress.objects(session).get(
        user_id=user_id, primary=True,
    )
    assert email_addr is None

    # Login with mandatory verification should succeed (no EmailAddress row)
    old_val = settings.EMAIL_VERIFICATION
    settings.EMAIL_VERIFICATION = "mandatory"
    try:
        resp = await client.post(
            f"{_auth_prefix()}/token",
            data=login_form,
        )
        assert resp.status_code == 200, resp.text
        assert "access_token" in resp.json()
    finally:
        settings.EMAIL_VERIFICATION = old_val
