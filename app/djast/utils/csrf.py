"""Double-submit cookie CSRF protection.

Enforced globally via ``csrf_protect`` (added as an app-level dependency in
``main.py``).  All state-changing requests (POST, PUT, PATCH, DELETE) are
checked by default.  Use the ``@csrf_exempt`` decorator on individual
endpoints that must skip the check (login, signup, token exchange, etc.).

This mirrors Django's ``CsrfViewMiddleware`` + ``@csrf_exempt`` pattern.
"""
import secrets
from typing import Callable

from fastapi import Request, HTTPException, status, Response

from djast.settings import settings


# Registry of endpoint functions that skip CSRF validation.
_csrf_exempt_endpoints: set[Callable] = set()

# HTTP methods that never require CSRF validation.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def csrf_exempt(func: Callable) -> Callable:
    """Mark an endpoint as exempt from CSRF protection.

    Usage::

        @router.post("/token")
        @csrf_exempt
        async def login(request: Request, ...):
            ...

    The decorator must be placed **after** ``@router`` so it wraps the
    actual function that FastAPI registers as the route endpoint.
    """
    _csrf_exempt_endpoints.add(func)
    return func


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
    """Global FastAPI dependency that enforces CSRF on state-changing requests.

    Added to the application via ``app = FastAPI(dependencies=[...])``.
    Skips validation for safe HTTP methods and endpoints decorated with
    ``@csrf_exempt``.
    """
    if not settings.CSRF_ENABLED:
        return

    if request.method in _SAFE_METHODS:
        return

    # Check if the resolved endpoint is exempt.
    route = request.scope.get("route")
    if route and getattr(route, "endpoint", None) in _csrf_exempt_endpoints:
        return

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
