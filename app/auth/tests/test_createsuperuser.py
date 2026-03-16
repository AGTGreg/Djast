"""Tests for the createsuperuser management command."""

from __future__ import annotations

from unittest.mock import patch, call

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from djast.db.models import Base
from djast.settings import settings
from djast.commands import createsuperuser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(engine):
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def session(session_factory):
    async with session_factory() as session:
        yield session


# ---------------------------------------------------------------------------
# _create_superuser (async, hits real DB)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_django_superuser(session_factory, session):
    """Django mode: creates user with is_superuser and is_staff True."""
    with patch(
        "djast.commands.createsuperuser.async_session_factory", session_factory
    ):
        await createsuperuser._create_superuser(
            {"username": "admin", "email": "admin@example.com", "password": "Test1234!"}
        )

    from auth.models import User
    user = await User.objects(session).get(username="admin")
    assert user is not None
    assert user.is_superuser is True
    assert user.is_staff is True
    assert user.email == "admin@example.com"


@pytest.mark.asyncio
async def test_create_email_superuser(session_factory, session):
    """Email mode: creates user with is_superuser and is_staff True."""
    if settings.AUTH_USER_MODEL_TYPE != "email":
        pytest.skip("Only runs under AUTH_USER_MODEL_TYPE=email")

    with patch(
        "djast.commands.createsuperuser.async_session_factory", session_factory
    ):
        await createsuperuser._create_superuser(
            {"email": "admin@example.com", "password": "Test1234!"}
        )

    from auth.models import User
    user = await User.objects(session).get(email="admin@example.com")
    assert user is not None
    assert user.is_superuser is True
    assert user.is_staff is True


@pytest.mark.asyncio
async def test_create_superuser_weak_password(session_factory):
    """Weak password raises an error."""
    with patch(
        "djast.commands.createsuperuser.async_session_factory", session_factory
    ):
        with pytest.raises(Exception):
            await createsuperuser._create_superuser(
                {"username": "admin", "password": "weak"}
            )


# ---------------------------------------------------------------------------
# Prompt functions (mocked input)
# ---------------------------------------------------------------------------

def test_prompt_django_fields():
    """Django prompt collects username, optional email, and password."""
    with (
        patch("builtins.input", side_effect=["admin", "admin@test.com"]),
        patch("getpass.getpass", side_effect=["Test1234!", "Test1234!"]),
    ):
        fields = createsuperuser._prompt_django_fields()

    assert fields == {
        "username": "admin",
        "email": "admin@test.com",
        "password": "Test1234!",
    }


def test_prompt_django_fields_no_email():
    """Django prompt works without email."""
    with (
        patch("builtins.input", side_effect=["admin", ""]),
        patch("getpass.getpass", side_effect=["Test1234!", "Test1234!"]),
    ):
        fields = createsuperuser._prompt_django_fields()

    assert fields == {"username": "admin", "password": "Test1234!"}
    assert "email" not in fields


def test_prompt_django_blank_username():
    """Blank username exits with error."""
    with (
        patch("builtins.input", side_effect=["", ""]),
        pytest.raises(SystemExit),
    ):
        createsuperuser._prompt_django_fields()


def test_prompt_django_password_mismatch():
    """Mismatched passwords exit with error."""
    with (
        patch("builtins.input", side_effect=["admin", ""]),
        patch("getpass.getpass", side_effect=["Test1234!", "Different1!"]),
        pytest.raises(SystemExit),
    ):
        createsuperuser._prompt_django_fields()


def test_prompt_email_fields():
    """Email prompt collects email and password."""
    with (
        patch("builtins.input", return_value="admin@test.com"),
        patch("getpass.getpass", side_effect=["Test1234!", "Test1234!"]),
    ):
        fields = createsuperuser._prompt_email_fields()

    assert fields == {"email": "admin@test.com", "password": "Test1234!"}


def test_prompt_email_blank():
    """Blank email exits with error."""
    with (
        patch("builtins.input", return_value=""),
        pytest.raises(SystemExit),
    ):
        createsuperuser._prompt_email_fields()


def test_prompt_email_password_mismatch():
    """Mismatched passwords exit with error."""
    with (
        patch("builtins.input", return_value="admin@test.com"),
        patch("getpass.getpass", side_effect=["Test1234!", "Different1!"]),
        pytest.raises(SystemExit),
    ):
        createsuperuser._prompt_email_fields()
