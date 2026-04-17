"""Shared helpers for auth tests.

These are plain functions (not fixtures) because they take arguments and are
used across many tests in different ways. Import what you need:

    from auth.tests.helpers import (
        auth_prefix, strong_password, new_user_payload, signup_and_login,
    )
"""
from __future__ import annotations

import secrets
from datetime import timedelta
from typing import NamedTuple
from unittest.mock import patch

from httpx import AsyncClient

import auth.utils.auth_backend
from djast.settings import settings
from djast.utils import timezone as dj_timezone


class ProtectedEndpoint(NamedTuple):
    """An auth endpoint that requires a valid access token."""
    method: str
    path: str  # relative to ``auth_prefix()``
    body: dict | None = None


# Spec of every endpoint that requires authentication. Consumed by the
# parametrized "missing token returns 401" test in ``test_views.py`` to guard
# against wiring regressions (e.g. accidentally removing
# ``Depends(get_current_user)``).
# Whenever a new protected endpoint is added, append it here.
PROTECTED_ENDPOINTS: tuple[ProtectedEndpoint, ...] = (
    ProtectedEndpoint(
        "POST", "/change-password",
        {"old_password": "x", "new_password": "x"},
    ),
    ProtectedEndpoint("POST", "/logout"),
    ProtectedEndpoint("POST", "/logout-all"),
    ProtectedEndpoint("POST", "/deactivate"),
    ProtectedEndpoint("GET", "/users/me"),
    ProtectedEndpoint("POST", "/resend-verification"),
    ProtectedEndpoint("DELETE", "/oauth/google/link"),
    ProtectedEndpoint("POST", "/set-password", {"new_password": "x"}),
)


def auth_prefix() -> str:
    return f"{settings.APP_PREFIX}/auth"


def strong_password(seed: str | None = None) -> str:
    """Return a password that satisfies the password validation policy."""
    suffix = seed or ""
    return f"StrongPassword123!{suffix}"


def password_of_length(length: int) -> str:
    """Build a password of exactly ``length`` that satisfies the policy."""
    if length < 8:
        raise ValueError("length must be >= 8")
    base = "Aa1!"
    password = base + ("a" * (length - len(base)))
    assert len(password) == length
    return password


def new_user_payload(mode: str, *, password: str) -> tuple[dict, dict]:
    """Build signup/login payloads for the given auth mode.

    Returns ``(signup_payload, login_form_payload)``.
    """
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


def extract_access_token(token_response_json: dict) -> str:
    return token_response_json["access_token"]


async def signup_and_login(client: AsyncClient, mode: str) -> tuple[int, str]:
    """Sign up a fresh user and log in. Returns ``(user_id, access_token)``."""
    password = strong_password()
    signup_payload, login_form = new_user_payload(mode, password=password)

    signup_resp = await client.post(
        f"{auth_prefix()}/signup",
        json=signup_payload,
    )
    assert signup_resp.status_code == 201, signup_resp.text
    user_id = signup_resp.json()["user_id"]

    token_resp = await client.post(
        f"{auth_prefix()}/token",
        data=login_form,
    )
    assert token_resp.status_code == 200, token_resp.text
    access_token = extract_access_token(token_resp.json())
    assert access_token
    return user_id, access_token


def patch_time_ahead(seconds: int = 2):
    """Patch ``dj_timezone.now`` to return current time + offset.

    Used instead of ``asyncio.sleep()`` to advance ``min_iat > token.iat``
    without introducing real delays that cause flaky Redis-related failures.
    """
    real_now = dj_timezone.now
    return patch.object(
        auth.utils.auth_backend.dj_timezone,
        "now",
        side_effect=lambda: real_now() + timedelta(seconds=seconds),
    )
