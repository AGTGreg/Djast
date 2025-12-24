"""
Minimal Auth models based on:
 - [Django BaseUser](https://github.com/django/django/blob/main/django/contrib/auth/base_user.py)
 - [Django Auth Models](https://github.com/django/django/blob/main/django/contrib/auth/models.py)
"""
from __future__ import annotations

from typing import Optional
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncSession

from djast.settings import settings
from djast.db import models
from djast.utils import timezone as dj_timezone
from auth.utils.password_validators import check_password_strength
from auth.utils.hashers import (
    make_password,
    check_password,
    is_password_usable
)


class AbstractBaseUser(models.Model):
    """
    A minimal User Abstract.

    This model provides the core fields and methods for a user model.
    Do not inherit from this class directly; inherit from
    `AbstractEmailUser` or `AbstractDjangoUser` instead.
    """
    __abstract__ = True

    is_active: Mapped[bool] = mapped_column(default=True)
    password: Mapped[str] = mapped_column(String(255))
    date_joined: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=dj_timezone.now,
        server_default=func.now()
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        default=None,
        nullable=True
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id})>"

    @classmethod
    async def create_user(
        cls,
        session: AsyncSession,
        password: str,
        **fields,
    ):
        """
        Create and save a user with the given password and fields.

        Args:
            session: The async database session.
            password: The plain-text password (will be hashed).
            **fields: Fields to set on the user (e.g., email, username).

        Returns:
            The newly created user instance.
        """
        check_password_strength(password)
        hashed_password = await make_password(password)
        user = await cls.objects(session).create(
            password=hashed_password,
            **fields,
        )
        return user

    async def set_unusable_password(self) -> None:
        """
        Set a password value that will never be a valid hash.
        Used for users who authenticate via external systems.
        """
        self.password = await make_password(None)

    async def has_usable_password(self) -> bool:
        """
        Return True if the user has a usable password.
        """
        return is_password_usable(self.password)

    async def set_password(self, raw_password: str) -> None:
        """
        Set the user's password to the given raw string,
        taking care of the password hashing.

        Args:
            raw_password: The plain-text password to set.
        """
        check_password_strength(raw_password)
        self.password = await make_password(raw_password)

    async def authenticate(
        self,
        session: AsyncSession,
        raw_password: str
    ) -> bool:
        """
        Check password and update last_login on success.
        """
        async def rehash_setter(new_password: str) -> None:
            await self.set_password(new_password)

        is_correct = await check_password(
            raw_password, self.password, setter=rehash_setter)

        if not self.is_active:
            return False

        if is_correct:
            await self.update(session, last_login=dj_timezone.now())

        return is_correct


class AbstractEmailUser(AbstractBaseUser):
    """
    A minimal User Abstract with email as unique identifier.

    This model uses `email` as the unique identifier for authentication
    instead of usernames.
    """
    __abstract__ = True

    USERNAME_FIELD = 'email'

    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)

    def __repr__(self) -> str:
        return f"<User(email={self.email})>"

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email by lowercasing the domain part."""
        email = email or ""
        try:
            email_name, domain_part = email.strip().rsplit("@", 1)
        except ValueError:
            pass
        else:
            email = email_name + "@" + domain_part.lower()
        return email

    @classmethod
    async def create_user(
        cls,
        session: AsyncSession,
        email: str,
        password: str,
        **fields,
    ):
        """
        Create and save a user with the given email and password.
        """
        email = cls.normalize_email(email)
        return await super().create_user(
            session, password=password, email=email, **fields)


class AbstractDjangoUser(AbstractBaseUser):
    """
    A Django compatible User Abstract.

    This model is designed to be compatible with Django's authentication
    system. It includes all the necessary fields to work seamlessly with
    Django.

    Email is not unique in this model to align with Django's default behavior.
    """
    __abstract__ = True

    USERNAME_FIELD = 'username'

    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), default="")
    first_name: Mapped[str] = mapped_column(String(150), default="")
    last_name: Mapped[str] = mapped_column(String(150), default="")
    is_staff: Mapped[bool] = mapped_column(default=False)
    is_superuser: Mapped[bool] = mapped_column(default=False)

    def __repr__(self) -> str:
        return f"<User(username={self.username})>"

    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email by lowercasing the domain part."""
        email = email or ""
        try:
            email_name, domain_part = email.strip().rsplit("@", 1)
        except ValueError:
            pass
        else:
            email = email_name + "@" + domain_part.lower()
        return email

    @classmethod
    async def create_user(
        cls,
        session: AsyncSession,
        username: str,
        password: str,
        email: str | None = None,
        **fields,
    ):
        """
        Create and save a user with the given username, email, and password.
        """
        if email is not None:
            email = cls.normalize_email(email)
        return await super().create_user(
            session,
            password=password,
            username=username,
            email=email,
            **fields
        )


if settings.AUTH_USER_MODEL_TYPE == "email":
    class User(AbstractEmailUser):
        """ Use this User model for authentication
        """
        pass
else:
    class User(AbstractDjangoUser):
        """ Use this User model for authentication
        """
        pass


class RefreshToken(models.Model):
    """ Token model for storing authentication tokens

    Implements refresh-token *families* to support replay detection and
    family-wide revocation.
    """
    key: Mapped[str] = mapped_column(String(26), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id", ondelete="CASCADE"))
    created: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=dj_timezone.now,
        server_default=func.now()
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=dj_timezone.now,
        server_default=func.now(),
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        default=None,
        nullable=True,
        index=True,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        default=None,
        nullable=True,
        index=True,
    )
    replaced_by_key: Mapped[Optional[str]] = mapped_column(
        String(26),
        default=None,
        nullable=True,
        index=True,
    )

    def __repr__(self) -> str:
        return f"<Token(key={self.key}, user_id={self.user_id})>"
