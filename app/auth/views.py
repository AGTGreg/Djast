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
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from djast.settings import settings
from djast.database import get_async_session
from auth.models import User
from auth.schemas import (
    UserRead,
    UserCreate,
    PasswordChange,
    BaseResponse,
    AccessToken,
    CreateUserResponse,
    TokenData
)

from auth.forms import OAuth2EmailRequestForm
from auth.utils import auth_backend
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
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=settings.DEBUG is False,  # Must be secure in production
            samesite="lax",
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )
        return AccessToken(
            access_token=access_token,
            token_type="bearer"
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
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=settings.DEBUG is False,  # Must be secure in production
            samesite="lax",
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )
        return AccessToken(
            access_token=access_token,
            token_type="bearer"
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
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    try:
        user = await auth_backend.get_user_from_token_data(
            session=session,
            token_data=token_data
        )

    except auth_exceptions.InvalidToken:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    except auth_exceptions.UserDoesNotExist:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

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
        session=session, user_id=int(token_data.sub))

    return BaseResponse(message="Password changed successfully.")


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def logout(
    request: Request,
    response: Response,
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    """
    Standard Logout: Revokes ONLY the token used to make this request.
    """
    refresh_token = request.cookies.get("refresh_token", None)

    await auth_backend.logout_user(
        session=session,
        token_data=token_data,
        refresh_token=refresh_token
    )

    response.delete_cookie(key="refresh_token")


@router.post("/revoke-all", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def logout_all_devices(
    request: Request,
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    """
    Global Logout: Revokes ALL tokens for the user.
    """
    await auth_backend.logout_user_all_devices(
        session=session,
        user_id=int(token_data.sub)
    )


@router.post("/deactivate", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.AUTH_RATE_LIMIT_REVOKE)
async def deactivate_account(
    request: Request,
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    """
    Deactivate the authenticated user's account.
    """
    try:
        user = await auth_backend.get_user_from_token_data(
            session=session,
            token_data=token_data
        )

    except auth_exceptions.InvalidToken:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    except auth_exceptions.UserDoesNotExist:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    await auth_backend.deactivate_user(
        session=session,
        user=user
    )


@router.get("/users/me/", response_model=UserRead)
@limiter.limit(settings.AUTH_RATE_LIMIT_USER_ME)
async def read_users_me(
    request: Request,
    token_data: Annotated[TokenData, Depends(auth_backend.validate_access_token)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    try:
        user = await auth_backend.get_user_from_token_data(
            session=session,
            token_data=token_data
        )

    except auth_exceptions.InvalidToken:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    except auth_exceptions.UserDoesNotExist:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    return user
