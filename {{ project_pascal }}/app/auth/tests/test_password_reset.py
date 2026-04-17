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
    patch_time_ahead as _patch_time_ahead,
    strong_password as _strong_password,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _signup_user(client: AsyncClient, mode: str, password: str | None = None):
    """Sign up a user and return (signup_payload, login_form, signup_response)."""
    pw = password or _strong_password()
    signup_payload, login_form = _new_user_payload(mode, password=pw)
    resp = await client.post(f"{_auth_prefix()}/signup", json=signup_payload)
    assert resp.status_code == 201, resp.text
    return signup_payload, login_form, resp


def _get_email_from_payload(signup_payload: dict) -> str:
    """Extract the email from a signup payload."""
    return signup_payload["email"]


async def _get_user_from_db(session, user_id: int):
    """Fetch a User object from the DB."""
    from auth.models import User
    user = await User.objects(session).get(id=user_id)
    return user


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_forgot_password_returns_success_for_existing_user(auth_client):
    client, mode, session = auth_client
    password = _strong_password()
    signup_payload, _, resp = await _signup_user(client, mode, password)
    email = _get_email_from_payload(signup_payload)

    with patch(
        "auth.utils.auth_backend.check_email_cooldown",
        new_callable=AsyncMock,
    ), patch(
        "djast.utils.email.send_template_email",
        new_callable=AsyncMock,
    ):
        resp = await client.post(
            f"{_auth_prefix()}/forgot-password",
            json={"email": email},
        )

    assert resp.status_code == 200
    assert "If an account" in resp.json()["message"]


@pytest.mark.asyncio
async def test_forgot_password_returns_success_for_nonexistent_email(auth_client):
    client, mode, session = auth_client

    resp = await client.post(
        f"{_auth_prefix()}/forgot-password",
        json={"email": f"nonexistent_{secrets.token_hex(6)}@example.com"},
    )
    assert resp.status_code == 200
    assert "If an account" in resp.json()["message"]


@pytest.mark.asyncio
async def test_forgot_password_sends_email(auth_client):
    client, mode, session = auth_client
    password = _strong_password()
    signup_payload, _, resp = await _signup_user(client, mode, password)
    email = _get_email_from_payload(signup_payload)

    mock_send = AsyncMock()

    with patch(
        "auth.utils.auth_backend.check_email_cooldown",
        new_callable=AsyncMock,
    ), patch(
        "djast.utils.email.send_template_email",
        mock_send,
    ):
        resp = await client.post(
            f"{_auth_prefix()}/forgot-password",
            json={"email": email},
        )

    assert resp.status_code == 200
    mock_send.assert_called_once()
    call_kwargs = mock_send.call_args
    # Verify the email was sent to the correct address
    assert email in call_kwargs.kwargs.get(
        "to", call_kwargs.args[1] if len(call_kwargs.args) > 1 else []
    )


@pytest.mark.asyncio
async def test_reset_password_success(auth_client):
    client, mode, session = auth_client
    password = _strong_password("old")
    signup_payload, _, resp = await _signup_user(client, mode, password)
    user_id = resp.json()["user_id"]

    user = await _get_user_from_db(session, user_id)
    assert user is not None

    from auth.utils.tokens import get_password_reset_token_generator
    token = get_password_reset_token_generator().make_token(user)

    new_password = _strong_password("new")
    resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={"token": token, "new_password": new_password},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Password reset successfully."


@pytest.mark.asyncio
async def test_reset_password_can_login_with_new_password(auth_client):
    client, mode, session = auth_client
    old_password = _strong_password("old")
    signup_payload, login_form, resp = await _signup_user(client, mode, old_password)
    user_id = resp.json()["user_id"]

    user = await _get_user_from_db(session, user_id)
    from auth.utils.tokens import get_password_reset_token_generator
    token = get_password_reset_token_generator().make_token(user)

    new_password = _strong_password("new")
    reset_resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={"token": token, "new_password": new_password},
    )
    assert reset_resp.status_code == 200

    # Build login form with the new password
    if mode == "django":
        new_login_form = {
            "username": signup_payload["username"],
            "password": new_password,
        }
    else:
        new_login_form = {
            "email": signup_payload["email"],
            "password": new_password,
        }

    token_resp = await client.post(
        f"{_auth_prefix()}/token", data=new_login_form
    )
    assert token_resp.status_code == 200
    assert "access_token" in token_resp.json()


@pytest.mark.asyncio
async def test_reset_password_cannot_login_with_old_password(auth_client):
    client, mode, session = auth_client
    old_password = _strong_password("old")
    signup_payload, login_form, resp = await _signup_user(client, mode, old_password)
    user_id = resp.json()["user_id"]

    user = await _get_user_from_db(session, user_id)
    from auth.utils.tokens import get_password_reset_token_generator
    token = get_password_reset_token_generator().make_token(user)

    new_password = _strong_password("new")
    reset_resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={"token": token, "new_password": new_password},
    )
    assert reset_resp.status_code == 200

    # Try logging in with the old password
    token_resp = await client.post(
        f"{_auth_prefix()}/token", data=login_form
    )
    assert token_resp.status_code == 401


@pytest.mark.asyncio
async def test_reset_password_invalid_token(auth_client):
    client, mode, session = auth_client

    resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={
            "token": "totallyinvalidgarbage",
            "new_password": _strong_password(),
        },
    )
    assert resp.status_code == 400
    assert "Invalid or expired" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_reset_password_expired_token(auth_client):
    client, mode, session = auth_client
    password = _strong_password("old")
    signup_payload, _, resp = await _signup_user(client, mode, password)
    user_id = resp.json()["user_id"]

    user = await _get_user_from_db(session, user_id)
    from auth.utils.tokens import get_password_reset_token_generator

    # Generate token at current time
    token = get_password_reset_token_generator().make_token(user)

    # Patch time.time to simulate expiry (more than 3600 seconds later)
    import auth.utils.tokens as tokens_module
    real_time = tokens_module.time.time
    with patch.object(
        tokens_module.time,
        "time",
        side_effect=lambda: real_time() + 7200,
    ):
        resp = await client.post(
            f"{_auth_prefix()}/reset-password",
            json={
                "token": token,
                "new_password": _strong_password("new"),
            },
        )

    assert resp.status_code == 400
    assert "Invalid or expired" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_reset_password_single_use(auth_client):
    client, mode, session = auth_client
    password = _strong_password("old")
    signup_payload, _, resp = await _signup_user(client, mode, password)
    user_id = resp.json()["user_id"]

    user = await _get_user_from_db(session, user_id)
    from auth.utils.tokens import get_password_reset_token_generator
    token = get_password_reset_token_generator().make_token(user)

    new_password = _strong_password("new")
    first_resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={"token": token, "new_password": new_password},
    )
    assert first_resp.status_code == 200

    # Second attempt with the same token should fail because the
    # password hash changed, invalidating the HMAC
    second_resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={
            "token": token,
            "new_password": _strong_password("another"),
        },
    )
    assert second_resp.status_code == 400
    assert "Invalid or expired" in second_resp.json()["detail"]


@pytest.mark.asyncio
async def test_reset_password_weak_password(auth_client):
    client, mode, session = auth_client
    password = _strong_password("old")
    signup_payload, _, resp = await _signup_user(client, mode, password)
    user_id = resp.json()["user_id"]

    user = await _get_user_from_db(session, user_id)
    from auth.utils.tokens import get_password_reset_token_generator
    token = get_password_reset_token_generator().make_token(user)

    resp = await client.post(
        f"{_auth_prefix()}/reset-password",
        json={"token": token, "new_password": "123"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_revokes_sessions(auth_client):
    client, mode, session = auth_client
    old_password = _strong_password("old")
    signup_payload, login_form, resp = await _signup_user(
        client, mode, old_password
    )
    user_id = resp.json()["user_id"]

    # Login to get an access token
    token_resp = await client.post(
        f"{_auth_prefix()}/token", data=login_form
    )
    assert token_resp.status_code == 200
    access_token = _extract_access_token(token_resp.json())

    # Verify the token works
    me_resp = await client.get(
        f"{_auth_prefix()}/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 200

    # Reset the password with time advanced so min_iat > token.iat
    user = await _get_user_from_db(session, user_id)
    from auth.utils.tokens import get_password_reset_token_generator
    token = get_password_reset_token_generator().make_token(user)

    new_password = _strong_password("new")
    with _patch_time_ahead(seconds=2):
        reset_resp = await client.post(
            f"{_auth_prefix()}/reset-password",
            json={"token": token, "new_password": new_password},
        )
        assert reset_resp.status_code == 200

        # The old access token should no longer work
        me_resp = await client.get(
            f"{_auth_prefix()}/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert me_resp.status_code == 401


@pytest.mark.asyncio
async def test_forgot_password_inactive_user(auth_client):
    client, mode, session = auth_client
    password = _strong_password()
    signup_payload, _, resp = await _signup_user(client, mode, password)
    user_id = resp.json()["user_id"]
    email = _get_email_from_payload(signup_payload)

    # Deactivate the user
    user = await _get_user_from_db(session, user_id)
    await user.update(session, is_active=False)
    await session.commit()

    mock_send = AsyncMock()

    with patch(
        "auth.utils.auth_backend.check_email_cooldown",
        new_callable=AsyncMock,
    ), patch(
        "djast.utils.email.send_template_email",
        mock_send,
    ):
        resp = await client.post(
            f"{_auth_prefix()}/forgot-password",
            json={"email": email},
        )

    assert resp.status_code == 200
    assert "If an account" in resp.json()["message"]
    # Should NOT send email for inactive users
    mock_send.assert_not_called()
