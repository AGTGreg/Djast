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


CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Invalid credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)
