"""
Minimal Auth models based on:
 - [Django BaseUser](https://github.com/django/django/blob/main/django/contrib/auth/base_user.py)
 - [Django Auth Models](https://github.com/django/django/blob/main/django/contrib/auth/models.py)
"""
from typing import Optional
from datetime import datetime

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from djast.db import models


class AbstractBaseUser(models.Model):
    """
    A simple User Abstract.

    Design choices:
    - Minimal
    - Django compatible (but I don't really want first_name, last_name, etc. in AbstractBaseUser)
    Consider fields: password, date_joined, last_login, first_name, last_name
    """
    __abstract__ = True

    username: Mapped[str] = mapped_column(String(150), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(128))

    is_active: Mapped[bool] = mapped_column(default=True)
    is_superuser: Mapped[bool] = mapped_column(default=False)

    last_login: Mapped[Optional[datetime]] = mapped_column(default=None)

    def __repr__(self) -> str:
        return f"<User(username={self.username}, email={self.email})>"


class User(AbstractBaseUser):
    """
    Minimal user.
    """
    pass