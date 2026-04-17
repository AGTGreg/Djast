"""OAuth2 social login utilities for Google and GitHub providers.

Handles authorization URL generation, callback processing, and
user creation/linking. Uses Authlib for OAuth2/OIDC protocol handling.
"""
from __future__ import annotations

import json
import logging
import secrets
import re
import uuid
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from sqlalchemy.ext.asyncio import AsyncSession

from djast.settings import settings
from auth.models import User, OAuthAccount, EmailAddress
from auth.utils.auth_backend import redis_client
from auth import exceptions as auth_exceptions


logger = logging.getLogger(__name__)

# OAuth state token TTL in seconds
_OAUTH_STATE_TTL = 300  # 5 minutes
_OAUTH_STATE_PREFIX = "oauth_state:"
_OAUTH_CODE_PREFIX = "oauth_code:"

# Provider configuration registry
PROVIDER_CONFIGS: dict[str, dict[str, Any]] = {
    "google": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v3/userinfo",
        "scopes": "openid email profile",
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scopes": "read:user user:email",
    },
}

SUPPORTED_PROVIDERS = frozenset(PROVIDER_CONFIGS.keys())


def _get_provider_credentials(provider: str) -> tuple[str, str]:
    """Return (client_id, client_secret) for the given provider."""
    provider_upper = provider.upper()
    client_id = getattr(settings, f"OAUTH_{provider_upper}_CLIENT_ID", "")
    client_secret = getattr(settings, f"OAUTH_{provider_upper}_CLIENT_SECRET", "")
    return client_id, client_secret


def is_provider_enabled(provider: str) -> bool:
    """Check if an OAuth provider is enabled in settings."""
    if provider not in SUPPORTED_PROVIDERS:
        return False
    return getattr(settings, f"OAUTH_{provider.upper()}_ENABLED", False)


def validate_provider(provider: str) -> None:
    """Validate that a provider is supported and enabled.

    Raises:
        auth_exceptions.OAuthProviderDisabled: If the provider is not enabled.
    """
    if provider not in SUPPORTED_PROVIDERS:
        raise auth_exceptions.OAuthProviderDisabled(
            f"Unsupported OAuth provider: {provider}"
        )
    if not is_provider_enabled(provider):
        raise auth_exceptions.OAuthProviderDisabled(
            f"OAuth provider '{provider}' is not enabled."
        )


def _create_oauth_client(provider: str) -> AsyncOAuth2Client:
    """Create an Authlib async OAuth2 client for the given provider."""
    config = PROVIDER_CONFIGS[provider]
    client_id, client_secret = _get_provider_credentials(provider)

    return AsyncOAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        authorize_url=config["authorize_url"],
        token_endpoint=config["token_url"],
        scope=config["scopes"],
    )


async def get_authorization_url(
    provider: str,
    callback_url: str,
) -> str:
    """Generate the OAuth authorization URL and store state in Redis.

    Args:
        provider: The OAuth provider name (e.g. "google", "github").
        callback_url: The callback URL for the OAuth provider to redirect to.

    Returns:
        The full authorization URL to redirect the user to.
    """
    validate_provider(provider)
    client = _create_oauth_client(provider)

    state = secrets.token_urlsafe(32)
    await redis_client.setex(
        f"{_OAUTH_STATE_PREFIX}{state}", _OAUTH_STATE_TTL, provider
    )

    url, _ = client.create_authorization_url(
        PROVIDER_CONFIGS[provider]["authorize_url"],
        redirect_uri=callback_url,
        state=state,
    )
    return url


async def _validate_state(state: str, provider: str) -> None:
    """Validate and consume a one-time OAuth state token from Redis.

    Raises:
        auth_exceptions.OAuthError: If the state is invalid or expired.
    """
    key = f"{_OAUTH_STATE_PREFIX}{state}"
    stored_provider = await redis_client.getdel(key)  # atomic get+delete

    if not stored_provider:
        raise auth_exceptions.OAuthError("Invalid or expired OAuth state.")

    if stored_provider != provider:
        raise auth_exceptions.OAuthError("OAuth state mismatch.")


async def _fetch_google_profile(
    access_token: str,
) -> dict[str, str]:
    """Fetch user profile from Google's userinfo endpoint.

    Returns:
        Dict with keys: provider_user_id, email, name
    """
    async with httpx.AsyncClient() as http:
        resp = await http.get(
            PROVIDER_CONFIGS["google"]["userinfo_url"],
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        data = resp.json()

    email = data.get("email", "")
    if not email:
        raise auth_exceptions.OAuthError(
            "Google account has no email address."
        )

    return {
        "provider_user_id": data["sub"],
        "email": email,
        "name": data.get("name", ""),
    }


async def _fetch_github_profile(
    access_token: str,
) -> dict[str, str]:
    """Fetch user profile from GitHub's user and emails endpoints.

    Returns:
        Dict with keys: provider_user_id, email, name
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient() as http:
        # Fetch user profile
        resp = await http.get(
            PROVIDER_CONFIGS["github"]["userinfo_url"],
            headers=headers,
        )
        resp.raise_for_status()
        user_data = resp.json()

        # Fetch verified emails
        email = user_data.get("email", "")
        if not email:
            emails_resp = await http.get(
                PROVIDER_CONFIGS["github"]["emails_url"],
                headers=headers,
            )
            emails_resp.raise_for_status()
            emails = emails_resp.json()
            # Prefer primary verified email
            for e in emails:
                if e.get("primary") and e.get("verified"):
                    email = e["email"]
                    break
            # Fallback to any verified email
            if not email:
                for e in emails:
                    if e.get("verified"):
                        email = e["email"]
                        break

    if not email:
        raise auth_exceptions.OAuthError(
            "GitHub account has no verified email address."
        )

    return {
        "provider_user_id": str(user_data["id"]),
        "email": email,
        "name": user_data.get("name") or user_data.get("login", ""),
    }


_PROFILE_FETCHERS = {
    "google": _fetch_google_profile,
    "github": _fetch_github_profile,
}


async def handle_callback(
    provider: str,
    code: str,
    state: str,
    callback_url: str,
    session: AsyncSession,
) -> User:
    """Process an OAuth callback: exchange code, fetch profile, create/link user.

    Args:
        provider: The OAuth provider name.
        code: The authorization code from the provider.
        state: The state parameter for CSRF validation.
        callback_url: The callback URL (must match what was sent to provider).
        session: The async database session.

    Returns:
        The authenticated User instance.
    """
    validate_provider(provider)
    await _validate_state(state, provider)

    # Exchange authorization code for access token
    client = _create_oauth_client(provider)
    try:
        token = await client.fetch_token(
            PROVIDER_CONFIGS[provider]["token_url"],
            code=code,
            redirect_uri=callback_url,
        )
    except Exception as exc:
        logger.error(f"OAuth code exchange failed for {provider}: {exc}")
        raise auth_exceptions.OAuthError("OAuth authentication failed.")

    provider_access_token = token.get("access_token", "")
    if not provider_access_token:
        raise auth_exceptions.OAuthError("No access token from provider.")

    # Fetch user profile from provider
    fetcher = _PROFILE_FETCHERS[provider]
    try:
        profile = await fetcher(provider_access_token)
    except auth_exceptions.OAuthError:
        raise
    except Exception as exc:
        logger.error(f"OAuth profile fetch failed for {provider}: {exc}")
        raise auth_exceptions.OAuthError("OAuth authentication failed.")

    return await get_or_create_oauth_user(
        session=session,
        provider=provider,
        provider_user_id=profile["provider_user_id"],
        email=profile["email"],
        name=profile.get("name", ""),
    )


async def get_or_create_oauth_user(
    session: AsyncSession,
    provider: str,
    provider_user_id: str,
    email: str,
    name: str,
) -> User:
    """Find or create a user for the given OAuth identity.

    1. If OAuthAccount exists for (provider, provider_user_id) → return linked user.
    2. If a User with matching email exists → link OAuthAccount, return user.
    3. Create a new User (with unusable password) + OAuthAccount.

    Args:
        session: The async database session.
        provider: OAuth provider name.
        provider_user_id: The user's ID on the provider.
        email: The user's email from the provider.
        name: The user's display name from the provider.

    Returns:
        The User instance.
    """
    email = User.normalize_email(email)

    # 1. Check existing OAuthAccount
    oauth_account = await OAuthAccount.objects(session).get(
        provider=provider, provider_user_id=provider_user_id
    )
    if oauth_account:
        user = await User.objects(session).get(
            id=oauth_account.user_id, is_active=True
        )
        if not user:
            raise auth_exceptions.OAuthError(
                "Account is deactivated."
            )
        return user

    # 2. Check existing User by email — auto-link
    user = await User.objects(session).get(email=email)
    if user:
        if not user.is_active:
            raise auth_exceptions.OAuthError(
                "Account is deactivated."
            )
        await OAuthAccount.objects(session).create(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id,
            provider_email=email,
        )
        # Mark email as verified (OAuth provider already verified it)
        email_addr = await EmailAddress.objects(session).get(
            user_id=user.id, email=email,
        )
        if email_addr and not email_addr.verified:
            await email_addr.update(session, verified=True)
        elif not email_addr:
            await EmailAddress.objects(session).create(
                user_id=user.id, email=email, verified=True, primary=True,
            )
        return user

    # 3. Create new user with unusable password
    user = await _create_oauth_user(session, email, name)
    await OAuthAccount.objects(session).create(
        user_id=user.id,
        provider=provider,
        provider_user_id=provider_user_id,
        provider_email=email,
    )
    # Create verified EmailAddress (OAuth provider already verified it)
    if email:
        await EmailAddress.objects(session).create(
            user_id=user.id, email=email, verified=True, primary=True,
        )
    return user


async def _create_oauth_user(
    session: AsyncSession,
    email: str,
    name: str,
) -> User:
    """Create a new User with an unusable password for OAuth-only auth.

    Handles both 'email' and 'django' AUTH_USER_MODEL_TYPE modes.
    """
    from auth.utils.hashers import make_password

    unusable_password = await make_password(None)

    if settings.AUTH_USER_MODEL_TYPE == "email":
        user = await User.objects(session).create(
            email=email,
            password=unusable_password,
        )
    else:
        # Django mode: generate a unique username
        username = await _generate_username(session, email, name)
        user = await User.objects(session).create(
            username=username,
            email=email,
            password=unusable_password,
        )
    return user


_MAX_USERNAME_ATTEMPTS = 10


async def _generate_username(
    session: AsyncSession,
    email: str,
    name: str,
) -> str:
    """Generate a unique username for a new OAuth user in Django mode.

    Derives from the email prefix or display name, appending a UUID suffix
    to ensure uniqueness. Retries up to ``_MAX_USERNAME_ATTEMPTS`` times
    with a fresh UUID each attempt.
    """
    # Start with email prefix, fall back to name
    base = email.split("@")[0] if email else name
    # Sanitize: keep only alphanumeric, dots, hyphens, underscores
    base = re.sub(r"[^\w.\-]", "", base)
    # Truncate to fit Django's 150-char limit with room for suffix
    base = base[:140] or "user"

    for _ in range(_MAX_USERNAME_ATTEMPTS):
        candidate = f"{base}_{uuid.uuid4().hex[:8]}"
        if not await User.objects(session).exists(username=candidate):
            return candidate

    logger.error(
        f"Failed to generate unique username after "
        f"{_MAX_USERNAME_ATTEMPTS} attempts (base: {base})"
    )
    raise auth_exceptions.OAuthError(
        "Unable to generate a unique username. Please try again."
    )


# OAuth authorization code exchange ==========================================

async def store_oauth_tokens(
    access_token: str,
    refresh_token: str,
    user_id: int,
) -> str:
    """Store tokens in Redis keyed by a one-time authorization code.

    Returns the code for the frontend to exchange via POST.
    """
    code = secrets.token_urlsafe(32)
    payload = json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": user_id,
    })
    await redis_client.setex(
        f"{_OAUTH_CODE_PREFIX}{code}",
        settings.OAUTH_CODE_TTL,
        payload,
    )
    return code


async def consume_oauth_code(code: str) -> dict:
    """Consume a one-time authorization code and return stored tokens.

    Raises:
        auth_exceptions.OAuthError: If the code is invalid or expired.
    """
    key = f"{_OAUTH_CODE_PREFIX}{code}"
    payload = await redis_client.getdel(key)  # atomic get+delete
    if not payload:
        raise auth_exceptions.OAuthError(
            "Invalid or expired authorization code."
        )
    return json.loads(payload)
