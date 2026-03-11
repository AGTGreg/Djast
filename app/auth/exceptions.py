from fastapi import HTTPException, status


class PasswordIsWeak(Exception):
    """Exception raised when a password does not meet strength requirements."""
    pass


class UserDoesNotExist(Exception):
    """Exception raised when a user does not exist."""
    pass


class UserAlreadyExists(Exception):
    """Exception raised when a user already exists."""
    pass


class UserIsInactive(Exception):
    """Exception raised when a user is inactive."""
    pass


class InvalidCredentials(Exception):
    """Exception raised when provided credentials are invalid."""
    pass


class InvalidToken(Exception):
    """Exception raised when an access token is invalid."""
    pass


class RefreshTokenExpired(Exception):
    """Exception raised when a refresh token has expired."""
    pass


class AccountLockedOut(Exception):
    """Exception raised when an account is temporarily locked due to too many failed login attempts."""
    pass


class EmailNotVerified(Exception):
    """Raised when login is blocked due to unverified email under mandatory verification."""
    pass


class EmailCooldown(Exception):
    """Raised when an email was sent too recently (within cooldown period)."""
    pass


class OAuthProviderDisabled(Exception):
    """Raised when an OAuth provider is not enabled in settings."""
    pass


class OAuthError(Exception):
    """Raised when an OAuth flow fails (state mismatch, token exchange, profile fetch)."""
    pass


def credentials_exception() -> HTTPException:
    """Return a fresh 401 HTTPException for invalid credentials."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
