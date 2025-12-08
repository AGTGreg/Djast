import jwt
import secrets

from typing import Annotated
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Body, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from djast.settings import settings
from djast.utils import timezone as dj_timezone
from djast.database import get_async_session
from auth.models import User, RefreshToken as DBRefreshToken
from auth.schemas import Token, TokenData, UserRead

from auth.utils.hashers import check_password


oauth2_scheme = \
    OAuth2PasswordBearer(tokenUrl=f"{settings.APP_PREFIX}/auth/token")

router = APIRouter()


class OAuth2EmailRequestForm:
    """
    This is a dependency class, use it like:
    `def login(form_data: OAuth2EmailRequestForm = Depends())`
    It creates a form that requests `email` and `password`.
    """
    def __init__(
        self,
        grant_type: str = Form(default=None, pattern="password"),
        email: str = Form(),
        password: str = Form(),
        scope: str = Form(default=""),
        client_id: str | None = Form(default=None),
        client_secret: str | None = Form(default=None),
    ):
        self.grant_type = grant_type
        # OAuth2 spec requires 'username' field. We map email to it
        # so downstream code remains generic.
        self.username = email
        self.password = password
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret


if settings.AUTH_USER_MODEL_TYPE == "email":
    LoginForm = OAuth2EmailRequestForm
else:
    LoginForm = OAuth2PasswordRequestForm


def create_refresh_token() -> str:
    return secrets.token_hex(20)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = dj_timezone.now() + expires_delta
    else:
        expire = \
            dj_timezone.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return encoded_jwt


async def authenticate_user(session: AsyncSession, username: str, password: str):
    user = await User.objects(session).get(**{User.USERNAME_FIELD: username})
    if not user:
        # Prevent timing attacks and user enumeration
        await check_password(password=password, encoded="invalid", setter=None)
        return False
    if not await user.authenticate(session, password):
        return False
    return user


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(sub=username)
    except InvalidTokenError:
        raise credentials_exception

    user = await User.objects(session).get(**{User.USERNAME_FIELD: token_data.sub})
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[LoginForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> Token:
    user = await authenticate_user(
        session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": getattr(user, User.USERNAME_FIELD)}, expires_delta=access_token_expires
    )

    refresh_token = create_refresh_token()
    refresh_expires_at = \
        dj_timezone.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # Save refresh token to DB
    await DBRefreshToken.objects(session).create(
        key=refresh_token,
        user_id=user.id,
        expires_at=refresh_expires_at
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: Annotated[str, Body(embed=True)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
) -> Token:
    db_token = await DBRefreshToken.objects(session).get(key=refresh_token)
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiration
    current_time = dj_timezone.now()
    token_expires = db_token.expires_at

    # Handle naive datetime from SQLite
    if token_expires.tzinfo is None:
        token_expires = token_expires.replace(tzinfo=current_time.tzinfo)

    if token_expires < current_time:
        await db_token.delete(session)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await User.objects(session).get(id=db_token.user_id, is_active=True)
    if not user:
        await db_token.delete(session)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create new access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": getattr(user, User.USERNAME_FIELD)}, expires_delta=access_token_expires
    )

    # Rotate refresh token
    await db_token.delete(session)

    new_refresh_token = create_refresh_token()
    new_refresh_expires_at = \
        dj_timezone.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    await DBRefreshToken.objects(session).create(
        key=new_refresh_token,
        user_id=user.id,
        expires_at=new_refresh_expires_at
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=new_refresh_token
    )


@router.post("/logout")
async def logout(
    refresh_token: Annotated[str, Body(embed=True)],
    session: Annotated[AsyncSession, Depends(get_async_session)]
):
    db_token = await DBRefreshToken.objects(session).get(key=refresh_token)
    if db_token:
        await db_token.delete(session)
    return {"message": "Successfully logged out"}


@router.get("/users/me/", response_model=UserRead)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user
