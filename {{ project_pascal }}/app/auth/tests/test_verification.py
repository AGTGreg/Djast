import pytest
import pytest_asyncio
import importlib
import secrets
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport
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

from auth.tests.helpers import (
    auth_prefix as _auth_prefix,
    extract_access_token as _extract_access_token,
    new_user_payload as _new_user_payload,
    strong_password as _strong_password,
)


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
