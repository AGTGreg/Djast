"""
Minimal Auth models based on:
 - [Django BaseUser](https://github.com/django/django/blob/main/django/contrib/auth/base_user.py)
 - [Django Auth Models](https://github.com/django/django/blob/main/django/contrib/auth/models.py)
"""
from __future__ import annotations
from typing import Optional
from datetime import datetime

from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.ext.asyncio import AsyncSession

from djast.db import models
from djast.utils.timezone import now
from djast.utils.hashers import amake_password, acheck_password


class AbstractBaseUser(models.Model):
    """
    A minimal User Abstract.

    This model provides the core fields and methods for a user model.
    Uses `email` as the unique identifier for authentication instead of usernames.
    """
    __abstract__ = True

    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    password: Mapped[str] = mapped_column(String(128))
    date_joined: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=now,
        server_default=func.now()
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        default=None,
        nullable=True
    )

    def __repr__(self) -> str:
        return f"<User(email={self.email})>"

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
        hashed_password = await amake_password(password)
        user = await cls.objects(session).create(
            password=hashed_password,
            **fields,
        )
        return user

    async def set_password(self, session: AsyncSession, raw_password: str) -> None:
        """
        Set the user's password to the given raw string,
        taking care of the password hashing.

        Args:
            session: The async database session.
            raw_password: The plain-text password to set.
        """
        self.password = await amake_password(raw_password)
        await self.objects(session).update(self)

    async def password_is_correct(self, raw_password: str) -> bool:
        """
        Check if the given raw string is the correct password
        for this user.

        Args:
            raw_password: The plain-text password to check.
        Returns:
            True if the password is correct, False otherwise.
        """
        return await acheck_password(raw_password, self.password)


class AbstractDjangoUser(AbstractBaseUser):
    """
    A Django compatible User Abstract.

    This model is designed to be compatible with Django's authentication system.
    It includes all the necessary fields to work seamlessly with Django.

    Email is not unique in this model to align with Django's default behavior.
    """
    __abstract__ = True

    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), default="")
    first_name: Mapped[str] = mapped_column(String(150), default="")
    last_name: Mapped[str] = mapped_column(String(150), default="")
    is_staff: Mapped[bool] = mapped_column(default=False)
    is_superuser: Mapped[bool] = mapped_column(default=False)


class User(AbstractDjangoUser):
    """
    Minimal user.
    """
    pass
