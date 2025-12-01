"""
Minimal Auth models based on:
 - [Django BaseUser](https://github.com/django/django/blob/main/django/contrib/auth/base_user.py)
 - [Django Auth Models](https://github.com/django/django/blob/main/django/contrib/auth/models.py)
"""
from typing import Optional
from datetime import datetime

from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from djast.db import models
from djast.utils.timezone import now


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
        return f"<User(username={self.username}, email={self.email})>"


class AbstractDjangoUser(AbstractBaseUser):
    """
    A Django compatible User model.

    This model is designed to be compatible with Django's authentication system.
    It includes all the necessary fields and methods to work seamlessly with Django.

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
