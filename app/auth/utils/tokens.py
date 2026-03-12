"""HMAC-based token generator for email verification and password reset.

Inspired by Django's PasswordResetTokenGenerator. Tokens encode
user_id + timestamp, signed with HMAC-SHA256. The HMAC key incorporates
mutable user state so tokens auto-invalidate when that state changes
(e.g., password change, email verification, deactivation).
"""
from __future__ import annotations

import hashlib
import hmac
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import TYPE_CHECKING

from djast.settings import settings

if TYPE_CHECKING:
    from auth.models import EmailAddress


class TokenGenerator:
    """HMAC-based token generator with purpose-namespaced keys.

    Tokens are URL-safe, time-limited, and self-invalidating when the
    underlying user state changes.
    """

    def __init__(self, purpose: str, max_age_seconds: int) -> None:
        self.purpose = purpose
        self.max_age_seconds = max_age_seconds

    def _make_hash_value(
        self,
        user,
        email_address: EmailAddress | None = None,
    ) -> str:
        """Build the value that gets HMAC'd.

        Includes mutable user state so the token invalidates on password
        change, login, verification, or deactivation.
        """
        login_timestamp = ""
        if user.last_login is not None:
            login_timestamp = str(int(user.last_login.timestamp()))

        parts = [
            str(user.id),
            user.password,
            login_timestamp,
            str(user.is_active),
        ]

        if email_address is not None:
            parts.append(email_address.email)
            parts.append(str(email_address.verified))

        return ":".join(parts)

    def make_token(
        self,
        user,
        email_address: EmailAddress | None = None,
    ) -> str:
        """Generate a time-stamped, HMAC-signed token for the user."""
        timestamp = int(time.time())
        hash_value = self._make_hash_value(user, email_address)

        key = f"{settings.SECRET_KEY}{self.purpose}".encode()
        message = f"{user.id}:{timestamp}:{hash_value}".encode()
        mac = hmac.new(key, message, hashlib.sha256).hexdigest()

        token_plain = f"{user.id}:{timestamp}:{mac}"
        return urlsafe_b64encode(token_plain.encode()).decode().rstrip("=")

    def validate_token(self, token: str) -> tuple[int, bool]:
        """Extract user_id from a token without full validation.

        Returns (user_id, is_parseable). The caller must fetch the user
        and call check_token() for full HMAC validation.
        """
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = urlsafe_b64decode(padded).decode()
            parts = decoded.split(":", 2)
            if len(parts) != 3:
                return (0, False)
            user_id = int(parts[0])
            return (user_id, True)
        except Exception:
            return (0, False)

    def check_token(
        self,
        user,
        token: str,
        email_address: EmailAddress | None = None,
    ) -> bool:
        """Full token validation: HMAC check + expiry."""
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = urlsafe_b64decode(padded).decode()
            parts = decoded.split(":", 2)
            if len(parts) != 3:
                return False

            user_id = int(parts[0])
            timestamp = int(parts[1])
            provided_mac = parts[2]

            if user_id != user.id:
                return False

            # Check expiry
            age = int(time.time()) - timestamp
            if age < 0 or age > self.max_age_seconds:
                return False

            # Recompute HMAC and compare
            hash_value = self._make_hash_value(user, email_address)
            key = f"{settings.SECRET_KEY}{self.purpose}".encode()
            message = f"{user.id}:{timestamp}:{hash_value}".encode()
            expected_mac = hmac.new(key, message, hashlib.sha256).hexdigest()

            return hmac.compare_digest(provided_mac, expected_mac)
        except Exception:
            return False


def get_email_verification_token_generator() -> TokenGenerator:
    """Return a token generator configured for email verification."""
    return TokenGenerator(
        purpose="email-verify",
        max_age_seconds=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_SECONDS,
    )


def get_password_reset_token_generator() -> TokenGenerator:
    """Return a token generator configured for password reset."""
    return TokenGenerator(
        purpose="password-reset",
        max_age_seconds=settings.PASSWORD_RESET_TOKEN_EXPIRE_SECONDS,
    )
