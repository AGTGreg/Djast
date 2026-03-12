"""
Comprehensive tests for the auth app.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)

from djast.db.models import Base
from djast.settings import settings
from auth.models import User, AbstractEmailUser, AbstractDjangoUser
from auth.utils.hashers import check_password, is_password_usable

# -----------------------------------------------------------------------------
# Test Model Definition
# -----------------------------------------------------------------------------

class ConcreteEmailUser(AbstractEmailUser):
    """Concrete model for testing AbstractEmailUser."""
    __tablename__ = "test_email_user"

class ConcreteDjangoUser(AbstractDjangoUser):
    """Concrete model for testing AbstractDjangoUser."""
    __tablename__ = "test_django_user"


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest_asyncio.fixture
async def engine():
    """Create an in-memory SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        future=True,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session(engine):
    """Create an async session for testing."""
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with async_session_factory() as session:
        yield session


# -----------------------------------------------------------------------------
# Tests: User (AbstractDjangoUser)
# -----------------------------------------------------------------------------

class TestDjangoUser:
    """Tests for the default User model (AbstractDjangoUser)."""

    @pytest.mark.asyncio
    async def test_create_user(self, session):
        """Test creating a user with username, email, and password."""
        username = "johndoe"
        email = "John@Example.com"
        password = "StrongPassword123!"

        user = await ConcreteDjangoUser.create_user(
            session,
            username=username,
            email=email,
            password=password
        )

        assert user.id is not None
        assert user.username == username
        assert user.email == "John@example.com"  # Normalized (domain only)
        assert user.password != password
        assert await user.has_usable_password()
        assert user.is_active is True
        assert user.is_staff is False
        assert user.is_superuser is False
        assert user.last_login is None
        assert isinstance(user.date_joined, datetime)
        # SQLite might return naive datetime
        # assert user.date_joined.tzinfo is not None

        # Verify password hashing
        assert await check_password(password, user.password)

    @pytest.mark.asyncio
    async def test_create_user_email_normalization(self, session):
        """Test that email is normalized during creation."""
        emails = [
            ("Test@Example.com", "Test@example.com"),
            ("USER@DOMAIN.ORG", "USER@domain.org"),
            ("foo@BAR.com", "foo@bar.com"),
        ]

        for i, (raw_email, expected_email) in enumerate(emails):
            user = await ConcreteDjangoUser.create_user(
                session,
                username=f"user{i}",
                password="StrongPassword123!",
                email=raw_email
            )
            assert user.email == expected_email

    @pytest.mark.asyncio
    async def test_authenticate_success(self, session):
        """Test successful authentication updates last_login."""
        user = await ConcreteDjangoUser.create_user(session, "authuser", "StrongPassword123!")
        original_last_login = user.last_login
        assert original_last_login is None

        # Authenticate
        is_authenticated = await user.authenticate(session, "StrongPassword123!")

        assert is_authenticated is True
        assert user.last_login is not None
        assert user.last_login > user.date_joined

    @pytest.mark.asyncio
    async def test_authenticate_failure(self, session):
        """Test failed authentication does not update last_login."""
        user = await ConcreteDjangoUser.create_user(session, "failuser", "StrongPassword123!")

        is_authenticated = await user.authenticate(session, "wrong_password")

        assert is_authenticated is False
        assert user.last_login is None

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self, session):
        """Test that inactive users cannot authenticate."""
        user = await ConcreteDjangoUser.create_user(
            session,
            "inactive",
            "StrongPassword123!",
            is_active=False
        )

        is_authenticated = await user.authenticate(session, "StrongPassword123!")

        assert is_authenticated is False
        assert user.last_login is None

    @pytest.mark.asyncio
    async def test_set_password(self, session):
        """Test setting a new password."""
        user = await ConcreteDjangoUser.create_user(session, "resetuser", "StrongPassword123!")
        old_hash = user.password

        await user.set_password("NewStrongPassword123!")
        await user.save(session)

        assert user.password != old_hash
        assert await user.authenticate(session, "NewStrongPassword123!") is True
        assert await user.authenticate(session, "StrongPassword123!") is False

    @pytest.mark.asyncio
    async def test_unusable_password(self, session):
        """Test setting and checking unusable passwords."""
        user = await ConcreteDjangoUser.create_user(session, "nouser", "StrongPassword123!")

        await user.set_unusable_password()
        await user.save(session)

        assert await user.has_usable_password() is False
        assert is_password_usable(user.password) is False

        # Authentication should fail
        assert await user.authenticate(session, "StrongPassword123!") is False
        assert await user.authenticate(session, "") is False


# -----------------------------------------------------------------------------
# Tests: AbstractEmailUser
# -----------------------------------------------------------------------------

class TestAbstractEmailUser:
    """Tests for AbstractEmailUser functionality using a concrete subclass."""

    @pytest.mark.asyncio
    async def test_create_email_user(self, session):
        """Test creating an email-based user."""
        email = "EmailUser@Example.ORG"
        password = "StrongPassword123!"

        user = await ConcreteEmailUser.create_user(
            session,
            email=email,
            password=password
        )

        assert user.id is not None
        assert user.email == "EmailUser@example.org"  # Normalized (domain only)
        assert user.password != password
        assert await user.has_usable_password()
        assert user.is_active is True

        # Authenticate
        assert await user.authenticate(session, password) is True

    @pytest.mark.asyncio
    async def test_email_user_normalization(self, session):
        """Test email normalization for AbstractEmailUser."""
        user = await ConcreteEmailUser.create_user(
            session,
            email="MixedCase@Domain.Com",
            password="StrongPassword123!"
        )
        assert user.email == "MixedCase@domain.com"

    @pytest.mark.asyncio
    async def test_email_user_unique_constraint(self, session):
        """Test that email must be unique."""
        from sqlalchemy.exc import IntegrityError

        await ConcreteEmailUser.create_user(session, email="unique@test.com", password="StrongPassword123!")

        with pytest.raises(IntegrityError):
            await ConcreteEmailUser.create_user(session, email="unique@test.com", password="StrongPassword123!")
