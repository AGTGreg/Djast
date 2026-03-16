"""Admin panel API endpoints.

All endpoints except /admin/config/ and /admin/login/ require admin
authentication (is_staff or is_superuser).  The /admin/login/ endpoint
authenticates the user AND verifies staff status before issuing tokens.
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from djast.database import get_async_session
from djast.settings import settings
from djast.rate_limit import limiter
from admin.registry import site
from admin.schemas import (
    AdminChangePasswordRequest,
    AdminConfigResponse,
    BulkDeleteRequest,
    BulkDeleteResponse,
    PaginatedResponse,
    SchemaResponse,
)
from admin.utils.dependencies import get_admin_user
from admin.utils.crud import (
    admin_set_password,
    bulk_delete_records,
    create_record,
    delete_record,
    get_record,
    list_records,
    update_record,
)
from auth.exceptions import PasswordIsWeak
from auth.models import User
from auth.schemas import AccessToken
from auth.utils.auth_backend import authenticate_user, set_refresh_cookie
from auth.forms import OAuth2EmailRequestForm
from auth import exceptions as auth_exceptions

from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()

AdminLoginForm = OAuth2PasswordRequestForm
if settings.AUTH_USER_MODEL_TYPE == "email":
    AdminLoginForm = OAuth2EmailRequestForm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_entry(app: str, model: str):
    """Look up a model entry from the registry or raise 404."""
    entry = site.get_model_entry(app, model)
    if entry is None:
        raise HTTPException(404, "Model not found.")
    return entry


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@router.get("/config/", response_model=AdminConfigResponse)
async def admin_config() -> AdminConfigResponse:
    """Return admin configuration (auth mode). No auth required."""
    return AdminConfigResponse(auth_type=settings.AUTH_USER_MODEL_TYPE)


@router.post("/login/", response_model=AccessToken)
@limiter.limit(settings.AUTH_RATE_LIMIT_LOGIN)
async def admin_login(
    request: Request,
    response: Response,
    form_data: Annotated[AdminLoginForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> AccessToken:
    """Authenticate and verify admin (is_staff or is_superuser) status.

    Uses the same auth backend as /auth/token but rejects non-admin users
    with 403 before issuing tokens.
    """
    try:
        user = await User.objects(session).get(
            **{User.USERNAME_FIELD: form_data.username},
        )
        if user and not (user.is_staff or user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required.",
            )

        access_token, refresh_token = await authenticate_user(
            session=session,
            username=form_data.username,
            password=form_data.password,
        )
        set_refresh_cookie(response, refresh_token)
        return AccessToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    except auth_exceptions.EmailNotVerified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email verification required.",
        )
    except auth_exceptions.AccountLockedOut:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )
    except (
        auth_exceptions.UserIsInactive,
        auth_exceptions.UserDoesNotExist,
        auth_exceptions.InvalidCredentials,
    ):
        raise auth_exceptions.credentials_exception()


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------

@router.get("/schema/", response_model=SchemaResponse)
async def admin_schema(
    admin: Annotated[User, Depends(get_admin_user)],
) -> dict:
    """Return the full registry schema."""
    return site.get_schema()


@router.get("/{app}/{model}/", response_model=PaginatedResponse)
async def admin_list(
    app: str,
    model: str,
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    search: str | None = Query(None),
    ordering: str | None = Query(None),
) -> dict:
    """Paginated list of records with search and ordering."""
    entry = _resolve_entry(app, model)
    return await list_records(
        session, entry,
        page=page, page_size=page_size,
        search=search, ordering=ordering,
    )


@router.get("/{app}/{model}/{record_id}/")
async def admin_detail(
    app: str,
    model: str,
    record_id: int,
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Single record by id."""
    entry = _resolve_entry(app, model)
    result = await get_record(session, entry, record_id)
    if result is None:
        raise HTTPException(404, "Record not found.")
    return result


@router.post("/{app}/{model}/", status_code=status.HTTP_201_CREATED)
async def admin_create(
    app: str,
    model: str,
    body: dict[str, Any],
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Create a new record."""
    entry = _resolve_entry(app, model)
    try:
        return await create_record(session, entry, body)
    except PasswordIsWeak as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))


@router.patch("/{app}/{model}/{record_id}/")
async def admin_update(
    app: str,
    model: str,
    record_id: int,
    body: dict[str, Any],
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Partial update a record."""
    entry = _resolve_entry(app, model)
    result = await update_record(session, entry, record_id, body)
    if result is None:
        raise HTTPException(404, "Record not found.")
    return result


@router.delete(
    "/{app}/{model}/{record_id}/",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def admin_delete(
    app: str,
    model: str,
    record_id: int,
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    """Delete a record."""
    entry = _resolve_entry(app, model)
    deleted = await delete_record(session, entry, record_id)
    if not deleted:
        raise HTTPException(404, "Record not found.")


@router.post("/{app}/{model}/bulk-delete/", response_model=BulkDeleteResponse)
async def admin_bulk_delete(
    app: str,
    model: str,
    body: BulkDeleteRequest,
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> BulkDeleteResponse:
    """Delete multiple records by ids."""
    entry = _resolve_entry(app, model)
    count = await bulk_delete_records(session, entry, body.ids)
    return BulkDeleteResponse(deleted=count)


@router.post("/{app}/{model}/{record_id}/set-password/")
async def admin_set_password_view(
    app: str,
    model: str,
    record_id: int,
    body: AdminChangePasswordRequest,
    admin: Annotated[User, Depends(get_admin_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Admin password change for AbstractBaseUser models."""
    entry = _resolve_entry(app, model)
    if not entry.is_user_model:
        raise HTTPException(404, "Password change not supported for this model.")
    try:
        await admin_set_password(session, entry, record_id, body.new_password)
    except LookupError:
        raise HTTPException(404, "User not found.")
    except PasswordIsWeak as e:
        raise HTTPException(400, str(e))
    return {"message": "Password changed successfully."}
