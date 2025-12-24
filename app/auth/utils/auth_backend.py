import jwt
import redis.asyncio as redis

import asyncio
import time

from typing import Annotated, Tuple
from datetime import timedelta
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError
from sqlalchemy import update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from ulid import ULID

from djast.settings import settings
from djast.utils import timezone as dj_timezone
from auth.models import User, RefreshToken
from auth.schemas import TokenData, UserCreate
from auth import exceptions as auth_exceptions

from auth.utils.hashers import check_password


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.APP_PREFIX}/auth/token")

redis_client = redis.from_url(
    settings.REDIS_URL, encoding="utf-8", decode_responses=True)


# Refresh token cleanup =======================================================
_REFRESH_TOKEN_EXPIRED_GLOBAL_CLEANUP_LOCK_KEY = (
    "cleanup:refresh_tokens:expired:lock"
)
_REFRESH_TOKEN_EXPIRED_LOCAL_COOLDOWN_SECONDS = 30
_refresh_token_cleanup_local_lock = asyncio.Lock()
_refresh_token_cleanup_last_attempt_monotonic: float = 0.0


async def cleanup_expired_refresh_tokens(
    session: AsyncSession,
    *,
    now: datetime | None = None,
) -> int:
    """Delete refresh tokens that are past their expiry.

    Notes:
        - Uses djast's timezone utility for an aware 'now'.
        - Does not commit; relies on surrounding request/session management.

    Returns:
        Number of rows deleted, if available.
    """
    current_time = now or dj_timezone.now()

    result = await session.execute(
        delete(RefreshToken).where(RefreshToken.expires_at <= current_time)
    )
    return int(getattr(result, "rowcount", 0) or 0)


async def maybe_cleanup_expired_refresh_tokens(session: AsyncSession) -> int:
    """Run a global expired-token delete at most once per interval.

    This avoids periodic tasks by performing opportunistic cleanup during
    normal auth flows.
    """
    global _refresh_token_cleanup_last_attempt_monotonic

    interval_seconds = int(
        getattr(
            settings,
            "REFRESH_TOKEN_EXPIRED_GLOBAL_CLEANUP_INTERVAL_SECONDS",
            3600,
        )
        or 3600
    )
    if interval_seconds <= 0:
        return 0

    # Per-worker cooldown: avoid hitting Redis on every request.
    # Use a lock to prevent concurrent requests from stampeding.
    async with _refresh_token_cleanup_local_lock:
        now_mono = time.monotonic()
        if (
            (now_mono - _refresh_token_cleanup_last_attempt_monotonic)
            < _REFRESH_TOKEN_EXPIRED_LOCAL_COOLDOWN_SECONDS
        ):
            return 0
        _refresh_token_cleanup_last_attempt_monotonic = now_mono

    try:
        acquired = await redis_client.set(
            _REFRESH_TOKEN_EXPIRED_GLOBAL_CLEANUP_LOCK_KEY,
            "1",
            ex=interval_seconds,
            nx=True,
        )
    except Exception:
        # Cleanup must never break authentication.
        return 0

    if not acquired:
        return 0

    try:
        return await cleanup_expired_refresh_tokens(
            session=session,
            now=dj_timezone.now(),
        )
    except Exception:
        # Cleanup must never break authentication.
        return 0


# DateTime Utilities ==========================================================
def _dt_from_ts(ts: int) -> datetime:
    return datetime.fromtimestamp(int(ts), ZoneInfo(settings.TIME_ZONE))


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=ZoneInfo(settings.TIME_ZONE))
    return dt


def _ts_from_dt(dt: datetime) -> int:
    dt = _ensure_aware(dt)
    return int(dt.timestamp())


def _within_refresh_reuse_grace(used_at: datetime | None) -> bool:
    if used_at is None:
        return False
    used_at = _ensure_aware(used_at)
    grace = int(getattr(settings, "REFRESH_TOKEN_REUSE_GRACE_SECONDS", 0) or 0)
    if grace <= 0:
        return False
    now = dj_timezone.now()
    age_seconds = (now - used_at).total_seconds()
    return age_seconds <= grace


def _is_expired(expires_at: datetime) -> bool:
    expires_at = _ensure_aware(expires_at)
    now = dj_timezone.now()
    return expires_at <= now


# Token Utilities =============================================================
def encode_token_data(token_data: TokenData) -> str:
    return jwt.encode(
        token_data.model_dump(),
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def encode_token(
    user_id: int,
    token_type: str,
    *,
    jti: str | None = None,
    exp: int | None = None,
    iat: int | None = None,
) -> Tuple[TokenData, str]:
    """Encode a JWT for a user.

    By default, generates a *new* token (new jti/iat/exp).
    If you provide any of jti/exp/iat, you must provide all three.
    """
    token_type = token_type.lower()
    sub = str(user_id)

    override_any = any(v is not None for v in (jti, exp, iat))
    override_all = all(v is not None for v in (jti, exp, iat))
    if override_any and not override_all:
        raise ValueError("If overriding token fields, jti/exp/iat must all be provided.")

    if override_all:
        if iat > exp:
            raise ValueError("Invalid token timestamps: iat cannot be greater than exp.")
        data = TokenData(sub=sub, type=token_type, exp=int(exp), jti=str(jti), iat=int(iat))
        return data, encode_token_data(data)

    now = dj_timezone.now()
    iat_ts = int(now.timestamp())
    jti_val = str(ULID())

    if token_type == "access":
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    elif token_type == "refresh":
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    else:
        raise ValueError("Invalid token type for encoding.")

    exp_ts = int(expire.timestamp())
    data = TokenData(sub=sub, type=token_type, exp=exp_ts, jti=jti_val, iat=iat_ts)
    return data, encode_token_data(data)


def decode_token(token: str, *, verify_exp: bool = True) -> TokenData:
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_exp": verify_exp},
    )
    return TokenData(**payload)


class TokenBlacklist():
    def __init__(self):
        self.base_prefix = "blacklist:"
        self.token_prefix = f"{self.base_prefix}token:"
        self.user_prefix = f"{self.base_prefix}user:"

    async def add_token(self, token_data: TokenData):
        """Blacklist a specific token (Logout current device)"""
        if any([
            token_data.jti is None,
            token_data.exp is None,
            token_data.type != "access"
        ]):
            raise ValueError("Invalid token data for blacklisting.")

        now = dj_timezone.now().timestamp()
        ttl = int(token_data.exp - now)
        if ttl > 0:
            await redis_client.setex(
                f"{self.token_prefix}{token_data.jti}", ttl, "revoked")

    async def add_all_for_user(self, user_id: int):
        """
        Blacklist ALL tokens for a user (Logout all devices).
        We set a 'min_iat' (minimum issued_at) timestamp.
        Any token issued BEFORE this time is invalid.
        """
        now_ts = int(dj_timezone.now().timestamp())

        # We only need to keep this restriction for the max lifespan of a
        # token. After 15 mins, all old tokens naturally expire anyway.
        ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

        await redis_client.setex(
            f"{self.user_prefix}{user_id}:min_iat", ttl, now_ts)

    async def is_blacklisted(self, token_data: TokenData) -> bool:
        """
        Returns True if token is blacklisted.
        """
        # 1. Check specific Token JTI
        if await redis_client.get(f"{self.token_prefix}{token_data.jti}"):
            return True

        # 2. Check User "Logout All" Timestamp
        min_iat = await redis_client.get(f"{self.user_prefix}{token_data.sub}:min_iat")
        if min_iat:
            if token_data.iat < int(min_iat):
                return True

        return False


async def validate_access_token(
    access_token: Annotated[str, Depends(oauth2_scheme)]
) -> TokenData:
    """ Validate an access token and return the corresponding data.

    Args:
        token (str): The access token string to validate.
    Raises:
        auth_exceptions.CREDENTIALS_EXCEPTION: If the access token is invalid or expired.
    """
    try:
        access_token_data = decode_token(access_token)
    except (InvalidTokenError, ValidationError):
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    if access_token_data.type != "access":
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    current_time = int(dj_timezone.now().timestamp())
    if access_token_data.exp < current_time:
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    if await TokenBlacklist().is_blacklisted(access_token_data):
        raise auth_exceptions.CREDENTIALS_EXCEPTION

    return access_token_data


async def validate_refresh_token(
    session: AsyncSession,
    refresh_token: str
) -> RefreshToken:
    """Validate a refresh token and return the db record of that token.

    Args:
        session (AsyncSession): Database session for querying.
        refresh_token (str): The refresh token string to validate.

    Raises:
        auth_exceptions.InvalidToken: If the refresh token is invalid.
        auth_exceptions.RefreshTokenExpired: If the refresh token has expired.

    Returns:
        RefreshToken: The corresponding RefreshToken object if valid.
    """
    try:
        refresh_token_data = decode_token(refresh_token, verify_exp=False)
    except (InvalidTokenError, ValidationError):
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    if refresh_token_data.type != "refresh":
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    db_refresh_token = await RefreshToken.objects(session).get(
        key=refresh_token_data.jti
    )

    if not db_refresh_token:
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    if db_refresh_token.revoked_at is not None:
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    if db_refresh_token.used_at is not None:
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    # Check expiration
    if _is_expired(db_refresh_token.expires_at):
        raise auth_exceptions.RefreshTokenExpired("Refresh token has expired.")

    return db_refresh_token


# Authentication & User Utilities =============================================
async def create_user(session: AsyncSession, user_data: UserCreate) -> User:
    """ Creates a new user in the database.

    Args:
        session (AsyncSession): Database session for querying.
        user_data (UserCreate): The user creation data.

    Raises:
        auth_exceptions.UserAlreadyExistsError: Raised when a user with the
            given username/email already exists.
        auth_exceptions.PasswordIsWeak: Raised when the provided password
            does not meet strength requirements.

    Returns:
        User: The newly created user instance.
    """
    existing_user = await User.objects(session).get(
        **{User.USERNAME_FIELD: getattr(user_data, User.USERNAME_FIELD)}
    )

    if existing_user:
        raise auth_exceptions.UserAlreadyExists("This user already exists.")

    new_user = await User.create_user(session, **user_data.model_dump())

    return new_user


async def authenticate_user(
    session: AsyncSession,
    username: str,
    password: str
) -> Tuple[str, str]:
    """ Authenticates a user and creates access and refresh tokens.

    Args:
        session (AsyncSession): Database session for querying.
        username (str): Username or Email of the user (depends on User.USERNAME_FIELD).
        password (str): Password of the user.

    Raises:
        auth_exceptions.UserIsInactive: Raised when the user account is inactive.
        auth_exceptions.UserDoesNotExist: Raised when the user does not exist.
        auth_exceptions.InvalidCredentials: Raised when the provided credentials are invalid.

    Returns:
        Tuple[str, str]: A tuple containing the access token and refresh token.
    """
    await maybe_cleanup_expired_refresh_tokens(session)

    user = await User.objects(session).get(**{User.USERNAME_FIELD: username})

    if not user:
        # Prevent timing attacks and user enumeration
        await check_password(password=password, encoded="invalid", setter=None)
        raise auth_exceptions.UserDoesNotExist("User not found.")

    if user.is_active is False:
        await check_password(password=password, encoded="invalid", setter=None)
        raise auth_exceptions.UserIsInactive("User account is inactive.")

    if not await user.authenticate(session, password):
        raise auth_exceptions.InvalidCredentials("Invalid credentials.")

    access_token_data, access_token = encode_token(
        user_id=user.id, token_type="access")
    refresh_token_data, refresh_token = encode_token(
        user_id=user.id, token_type="refresh")

    await RefreshToken.objects(session).create(
        key=refresh_token_data.jti,
        user_id=user.id,
        issued_at=_dt_from_ts(refresh_token_data.iat),
        expires_at=_dt_from_ts(refresh_token_data.exp),
    )

    return access_token, refresh_token


async def logout_user(
    session: AsyncSession,
    token_data: TokenData,
    refresh_token: str | None
) -> None:
    """ Logs out the user by blacklisting the current access token and deleting
    the provided refresh token.

    Args:
        session (AsyncSession): Database session for querying.
        token_user (TokenUser): The token user data.

    Returns:
        None
    """
    await TokenBlacklist().add_token(token_data)
    if refresh_token:
        try:
            db_refresh_token = await validate_refresh_token(
                session=session,
                refresh_token=refresh_token
            )
        except auth_exceptions.RefreshTokenExpired:
            return
        except auth_exceptions.InvalidToken:
            return

        await db_refresh_token.update(session, revoked_at=dj_timezone.now())

    await maybe_cleanup_expired_refresh_tokens(session)


async def logout_user_all_devices(
    session: AsyncSession,
    user_id: int
) -> None:
    """ Logs out the user from all devices by blacklisting all tokens.

    Args:
        session (AsyncSession): Database session for querying.
        user_id (int): The user ID to log out.

    Returns:
        None
    """

    now = dj_timezone.now()

    refresh_tokens = await RefreshToken.objects(session).filter(user_id=user_id)
    for token in refresh_tokens:
        await token.update(session, revoked_at=now)

    # Blacklist all access tokens for this user
    await TokenBlacklist().add_all_for_user(user_id=user_id)

    await maybe_cleanup_expired_refresh_tokens(session)


async def refresh_access_token(
    session: AsyncSession,
    refresh_token: str
) -> Tuple[str, str]:
    """ Refresh the access token using a valid refresh token and rotate the
    refresh token.

    Args:
        session (AsyncSession): Database session for querying.
        refresh_token (str): The refresh token string.

    Raises:
        auth_exceptions.InvalidToken: If the refresh token is invalid.
        auth_exceptions.RefreshTokenExpired: If the refresh token has expired.
        auth_exceptions.UserDoesNotExist: If the user associated with the
            refresh token does not exist.
    Returns:
        Tokens: The new access and refresh tokens.
    """
    try:
        refresh_token_data = decode_token(refresh_token, verify_exp=False)
    except (InvalidTokenError, ValidationError):
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    if refresh_token_data.type != "refresh":
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    await maybe_cleanup_expired_refresh_tokens(session)

    db_refresh_token = await RefreshToken.objects(session).get(key=refresh_token_data.jti)
    if not db_refresh_token or db_refresh_token.revoked_at is not None:
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    if _is_expired(db_refresh_token.expires_at):
        raise auth_exceptions.RefreshTokenExpired("Refresh token has expired.")

    user = await User.objects(session).get(
        id=db_refresh_token.user_id, is_active=True)

    if not user:
        await db_refresh_token.update(session, revoked_at=dj_timezone.now())
        raise auth_exceptions.UserDoesNotExist(
            "User does not exist or is inactive.")

    # Create new access token
    access_token_data, access_token = encode_token(
        user_id=user.id, token_type="access")

    # Rotate refresh token (single-use). If the token was already rotated very
    # recently (duplicate request), return the replacement token instead.
    if db_refresh_token.used_at is not None:
        if (
            _within_refresh_reuse_grace(db_refresh_token.used_at)
            and db_refresh_token.replaced_by_key
        ):
            replacement = await RefreshToken.objects(session).get(
                key=db_refresh_token.replaced_by_key
            )
            if (
                replacement
                and replacement.revoked_at is None
                and not _is_expired(replacement.expires_at)
            ):
                replacement_iat = _ts_from_dt(replacement.issued_at)
                replacement_exp = _ts_from_dt(replacement.expires_at)
                _data, replacement_jwt = encode_token(
                    user_id=replacement.user_id,
                    token_type="refresh",
                    jti=replacement.key,
                    exp=replacement_exp,
                    iat=replacement_iat,
                )
                return access_token, replacement_jwt
        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    new_refresh_token_data, new_refresh_token = encode_token(user_id=user.id, token_type="refresh")

    consume_stmt = (
        update(RefreshToken)
        .where(
            RefreshToken.key == db_refresh_token.key,
            RefreshToken.used_at.is_(None),
            RefreshToken.revoked_at.is_(None),
        )
        .values(
            used_at=dj_timezone.now(),
            replaced_by_key=new_refresh_token_data.jti,
        )
    )
    result = await session.execute(consume_stmt)
    rows = int(getattr(result, "rowcount", 0) or 0)

    if rows != 1:
        current = await RefreshToken.objects(session).get(key=db_refresh_token.key)
        if (
            current
            and current.revoked_at is None
            and current.used_at is not None
            and _within_refresh_reuse_grace(current.used_at)
            and current.replaced_by_key
        ):
            replacement = await RefreshToken.objects(session).get(
                key=current.replaced_by_key
            )
            if (
                replacement
                and replacement.revoked_at is None
                and not _is_expired(replacement.expires_at)
            ):
                replacement_iat = _ts_from_dt(replacement.issued_at)
                replacement_exp = _ts_from_dt(replacement.expires_at)
                _data, replacement_jwt = encode_token(
                    user_id=replacement.user_id,
                    token_type="refresh",
                    jti=replacement.key,
                    exp=replacement_exp,
                    iat=replacement_iat,
                )
                return access_token, replacement_jwt

        raise auth_exceptions.InvalidToken("Invalid refresh token.")

    await RefreshToken.objects(session).create(
        key=new_refresh_token_data.jti,
        user_id=user.id,
        issued_at=_dt_from_ts(new_refresh_token_data.iat),
        expires_at=_dt_from_ts(new_refresh_token_data.exp),
    )

    return access_token, new_refresh_token


async def get_user_from_token_data(
    session: AsyncSession,
    token_data: TokenData
) -> User | None:
    """ Retrieve the user associated with the given token data.

    Args:
        session (AsyncSession): Database session for querying.
        token_data (TokenData): The token data containing the user ID.

    Raises:
        auth_exceptions.UserDoesNotExist: If the user does not exist or is inactive.

    Returns:
        User: The corresponding User object.
    """
    try:
        user_id = int(token_data.sub)
    except (ValueError, TypeError):
        raise auth_exceptions.InvalidToken("Invalid access token.")

    user = await User.objects(session).get(id=user_id, is_active=True)

    if not user:
        raise auth_exceptions.UserDoesNotExist("User does not exist or is inactive.")

    return user


async def deactivate_user(
    session: AsyncSession,
    user: User
) -> None:
    """ Deactivate a user and revoke all their tokens.

    Args:
        session (AsyncSession): Database session for querying.
        user (User): The user to deactivate.

    Returns:
        None
    """
    user.is_active = False
    await user.save(session)

    await logout_user_all_devices(session=session, user_id=user.id)
