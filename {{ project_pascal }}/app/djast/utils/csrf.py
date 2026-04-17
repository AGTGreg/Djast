"""Opt-in double-submit cookie CSRF protection.

CSRF is **not** enforced globally.  Instead, endpoints that need it
explicitly declare ``csrf_protect`` as a FastAPI dependency::

    from djast.utils.csrf import csrf_protect

    @router.post("/my-endpoint", dependencies=[Depends(csrf_protect)])
    async def my_endpoint(request: Request):
        ...

This is the correct pattern for an API framework that authenticates via
Bearer tokens (which are immune to CSRF).  CSRF protection is only
meaningful for endpoints that rely on cookie-based authentication
(e.g., the refresh-token endpoint).

Utility helpers (``generate_csrf_token``, ``set_csrf_cookie``,
``delete_csrf_cookie``) remain available for endpoints that issue or
clear CSRF cookies.
"""
import secrets

from fastapi import Request, HTTPException, status, Response

from djast.settings import settings


def generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(settings.CSRF_TOKEN_LENGTH)


def set_csrf_cookie(response: Response, token: str) -> None:
    """Set the CSRF token as a readable (non-httponly) cookie."""
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=token,
        httponly=False,
        secure=settings.DEBUG is False,
        samesite="lax",
        path=f"{settings.APP_PREFIX}/auth",
    )


def delete_csrf_cookie(response: Response) -> None:
    """Delete the CSRF cookie."""
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path=f"{settings.APP_PREFIX}/auth",
    )


async def csrf_protect(request: Request) -> None:
    """FastAPI dependency that enforces double-submit cookie CSRF validation.

    Use as a per-endpoint dependency on routes that authenticate via cookies::

        @router.post("/refresh", dependencies=[Depends(csrf_protect)])
        async def refresh_token(...):
            ...

    Validates that the ``X-CSRF-Token`` header matches the ``csrf_token``
    cookie using constant-time comparison.
    """
    cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
    header_token = request.headers.get(settings.CSRF_HEADER_NAME)

    if not cookie_token or not header_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing.",
        )

    if not secrets.compare_digest(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch.",
        )
