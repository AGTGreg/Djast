from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Body,
    Request,
    Response
)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from djast.settings import settings
from djast.database import get_async_session
from auth.models import User, OAuthAccount
from auth.schemas import (
    UserRead,
    UserCreate,
    PasswordChange,
    SetPassword,
    BaseResponse,
    AccessToken,
    CreateUserResponse,
    TokenData
)

from auth.forms import OAuth2EmailRequestForm
from auth.utils import auth_backend
from auth.utils.auth_backend import set_refresh_cookie, get_current_user
from auth.utils import oauth as oauth_utils
from auth import exceptions as auth_exceptions

from djast.rate_limit import limiter

router = APIRouter()


LoginForm = OAuth2PasswordRequestForm
if settings.AUTH_USER_MODEL_TYPE == "email":
    LoginForm = OAuth2EmailRequestForm


@router.post(
    "/signup",
    response_model=CreateUserResponse,
    status_code=status.HTTP_201_CREATED
)
@limiter.limit(settings.AUTH_RATE_LIMIT_SIGNUP)
async def signup(
    request: Request,
    user_in: Annotated[UserCreate, Body()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> CreateUserResponse:
    """
    Create a new user account. Returns the ID of the created user.
    This is intended for public user registration.
    """
    if settings.ALLOW_SIGNUP is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User registration is disabled."
        )

    try:
        new_user: User = await auth_backend.create_user(
            session=session,
            user_data=user_in
        )

    except auth_exceptions.PasswordIsWeak as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    except auth_exceptions.UserAlreadyExists as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while creating the user."
        )
    else:
        return CreateUserResponse(user_id=new_user.id)


@router.post("/token", response_model=AccessToken)
@limiter.limit(settings.AUTH_RATE_LIMIT_LOGIN)
async def login(
    request: Request,
    response: Response,
    form_data: Annotated[LoginForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> AccessToken:
    """
    Creates new access and refresh tokens. Sets the refresh token cookie and
    returns the access token.
    """
    try:
        access_token, refresh_token = await auth_backend.authenticate_user(
            session=session,
            username=form_data.username,
            password=form_data.password
        )
        set_refresh_cookie(response, refresh_token)
        return AccessToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    except auth_exceptions.AccountLockedOut:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later."
        )
    except auth_exceptions.UserIsInactive:
        raise auth_exceptions.CREDENTIALS_EXCEPTION
    except auth_exceptions.UserDoesNotExist:
        raise auth_exceptions.CREDENTIALS_EXCEPTION
    except auth_exceptions.InvalidCredentials:
        raise auth_exceptions.CREDENTIALS_EXCEPTION
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during authentication."
        )


@router.post("/refresh", response_model=AccessToken)
@limiter.limit(settings.AUTH_RATE_LIMIT_REFRESH)
async def refresh_token(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> AccessToken:
    """
    Get a new access token and refresh token by providing a valid refresh token
    in the request cookies.
    """
    refresh_token = request.cookies.get("refresh_token", None)

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token is missing."
        )

    try:
        access_token, refresh_token = await auth_backend.refresh_access_token(
            session=session,
            refresh_token=refresh_token
        )
        set_refresh_cookie(response, refresh_token)
        return AccessToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    except auth_exceptions.InvalidToken:
        raise auth_exceptions.CREDENTIALS_EXCEPTION
    except auth_exceptions.RefreshTokenExpired:
        raise auth_exceptions.CREDENTIALS_EXCEPTION
    except auth_exceptions.UserDoesNotExist:
        raise auth_exceptions.CREDENTIALS_EXCEPTION
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while refreshing the token."
        )


@router.post("/change-password", response_model=BaseResponse)
@limiter.limit(settings.AUTH_RATE_LIMIT_CHANGE_PASSWORD)
async def change_password(
    request: Request,
    password_change: Annotated[PasswordChange, Body()],
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> BaseResponse:
    if not await user.authenticate(
        session,
        password_change.old_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Old password is incorrect."
        )

    await user.set_password(password_change.new_password)
    await user.save(session)
    await auth_backend.logout_user_all_devices(
        session=session, user_id=user.id)

    return BaseResponse(message="Password changed successfully.")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def logout(
    request: Request,
    response: Response,
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> None:
    """
    Standard Logout: Revokes ONLY the token used to make this request.
    """
    refresh_token = request.cookies.get("refresh_token", None)

    await auth_backend.logout_user(
        session=session,
        token_data=token_data,
        refresh_token=refresh_token
    )

    response.delete_cookie(
        key="refresh_token", path=f"{settings.APP_PREFIX}/auth")


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def logout_all_devices(
    request: Request,
    response: Response,
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> None:
    """
    Global Logout: Revokes ALL tokens for the user.
    """
    await auth_backend.logout_user_all_devices(
        session=session,
        user_id=int(token_data.sub)
    )
    response.delete_cookie(
        key="refresh_token", path=f"{settings.APP_PREFIX}/auth")


@router.post("/deactivate", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def deactivate_account(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> None:
    """
    Deactivate the authenticated user's account.
    """
    await auth_backend.deactivate_user(
        session=session,
        user=user
    )


@router.get("/users/me", response_model=UserRead)
@limiter.limit(settings.AUTH_RATE_LIMIT_USER_ME)
async def read_users_me(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    return user


# OAuth Endpoints =============================================================

def _build_callback_url(request: Request, provider: str) -> str:
    """Build the OAuth callback URL for the given provider."""
    return str(request.url_for("oauth_callback", provider=provider))


@router.get("/oauth/{provider}/authorize")
@limiter.limit(settings.AUTH_RATE_LIMIT_OAUTH)
async def oauth_authorize(
    request: Request,
    provider: str,
) -> RedirectResponse:
    """Redirect to OAuth provider's consent screen."""
    try:
        url = await oauth_utils.get_authorization_url(
            provider=provider,
            callback_url=_build_callback_url(request, provider),
        )
    except auth_exceptions.OAuthProviderDisabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not available."
        )
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


@router.get("/oauth/{provider}/callback")
@limiter.limit(settings.AUTH_RATE_LIMIT_OAUTH)
async def oauth_callback(
    request: Request,
    provider: str,
    code: str,
    state: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> RedirectResponse:
    """Handle OAuth callback, create/link user, issue tokens."""
    try:
        oauth_utils.validate_provider(provider)
    except auth_exceptions.OAuthProviderDisabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth provider '{provider}' is not available."
        )

    try:
        user = await oauth_utils.handle_callback(
            provider=provider,
            code=code,
            state=state,
            callback_url=_build_callback_url(request, provider),
            session=session,
        )
    except auth_exceptions.OAuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # Issue tokens using the same flow as password auth
    access_token_data, access_token = auth_backend.encode_token(
        user_id=user.id, token_type="access"
    )
    refresh_token_data, refresh_token = auth_backend.encode_token(
        user_id=user.id, token_type="refresh"
    )

    from auth.models import RefreshToken
    await RefreshToken.objects(session).create(
        key=refresh_token_data.jti,
        user_id=user.id,
        issued_at=auth_backend._dt_from_ts(refresh_token_data.iat),
        expires_at=auth_backend._dt_from_ts(refresh_token_data.exp),
    )

    # Redirect to frontend with access token in URL fragment
    redirect_url = (
        f"{settings.OAUTH_LOGIN_REDIRECT_URL}"
        f"#access_token={access_token}"
        f"&token_type=bearer"
        f"&expires_in={settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60}"
    )
    response = RedirectResponse(
        url=redirect_url, status_code=status.HTTP_302_FOUND
    )
    set_refresh_cookie(response, refresh_token)
    return response


@router.delete(
    "/oauth/{provider}/link",
    status_code=status.HTTP_204_NO_CONTENT,
)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def oauth_unlink(
    request: Request,
    provider: str,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> None:
    """Unlink a social account from the authenticated user."""
    if provider not in oauth_utils.SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unsupported OAuth provider: {provider}",
        )

    oauth_account = await OAuthAccount.objects(session).get(
        provider=provider, user_id=user.id,
    )
    if not oauth_account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No linked account for this provider.",
        )

    # Prevent unlinking if it's the user's only auth method
    has_password = await user.has_usable_password()
    other_oauth_count = await OAuthAccount.objects(session).count(
        user_id=user.id,
    )
    if not has_password and other_oauth_count <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot unlink the only authentication method.",
        )

    await oauth_account.delete(session)


@router.post("/set-password", response_model=BaseResponse)
@limiter.limit(settings.AUTH_RATE_LIMIT_CHANGE_PASSWORD)
async def set_password(
    request: Request,
    password_data: Annotated[SetPassword, Body()],
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> BaseResponse:
    """Set a password for an OAuth-only user who has no current password."""
    if not settings.OAUTH_ALLOW_SET_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setting a password is not allowed.",
        )

    if await user.has_usable_password():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a password. Use change-password instead.",
        )

    try:
        await user.set_password(password_data.new_password)
    except auth_exceptions.PasswordIsWeak as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    await user.save(session)
    return BaseResponse(message="Password set successfully.")
