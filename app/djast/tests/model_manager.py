"""
Comprehensive tests for djast.db.models.Manager class.

This module tests the Django-style async Manager exposed on Base.objects.
All tests use an in-memory SQLite database for isolation and speed.

Run tests with:
    pytest djast/tests/model_manager.py -v
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from typing import Optional

from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Mapped, mapped_column

from djast.db.models import Manager, Model, Base


# -----------------------------------------------------------------------------
# Test Model Definition
# -----------------------------------------------------------------------------

class SampleUser(Model):
    """Sample model for Manager tests."""
    __tablename__ = "sample_user"

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    age: Mapped[Optional[int]] = mapped_column(nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)


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


@pytest_asyncio.fixture
async def manager(session) -> Manager[SampleUser]:
    """Return a Manager bound to the test session."""
    return SampleUser.objects(session)


@pytest_asyncio.fixture
async def populated_session(session):
    """
    Create a session with pre-populated test data.
    Returns the session after adding sample users.
    """
    manager = SampleUser.objects(session)
    await manager.create(name="Alice", email="alice@example.com", age=30, is_active=True)
    await manager.create(name="Bob", email="bob@example.com", age=25, is_active=True)
    await manager.create(name="Charlie", email="charlie@example.com", age=35, is_active=False)
    return session


# -----------------------------------------------------------------------------
# Tests: Manager Initialization and Session Binding
# -----------------------------------------------------------------------------

class TestManagerInitialization:
    """Tests for Manager initialization and session binding."""

    def test_manager_initialization(self):
        """Test that Manager can be initialized with a model class."""
        manager = Manager(SampleUser)
        assert manager._model == SampleUser
        assert manager._session is None

    def test_manager_with_session(self, session):
        """Test that with_session returns a new Manager bound to the session."""
        manager = Manager(SampleUser)
        bound_manager = manager.with_session(session)

        assert bound_manager._session == session
        assert bound_manager._model == SampleUser
        # Original manager should remain unbound
        assert manager._session is None

    def test_get_session_raises_without_binding(self):
        """Test that _get_session raises RuntimeError when no session is bound."""
        manager = Manager(SampleUser)
        with pytest.raises(RuntimeError, match="No session bound"):
            manager._get_session()

    def test_get_session_returns_bound_session(self, session):
        """Test that _get_session returns the bound session."""
        manager = SampleUser.objects(session)
        assert manager._get_session() == session

    def test_model_objects_method(self, session):
        """Test that Model.objects() returns a properly bound Manager."""
        manager = SampleUser.objects(session)
        assert isinstance(manager, Manager)
        assert manager._session == session
        assert manager._model == SampleUser


# -----------------------------------------------------------------------------
# Tests: Create Operations
# -----------------------------------------------------------------------------

class TestManagerCreate:
    """Tests for Manager.create() method."""

    @pytest.mark.asyncio
    async def test_create_single_instance(self, manager):
        """Test creating a single instance."""
        user = await manager.create(
            name="John Doe",
            email="john@example.com",
            age=28
        )

        assert user.id is not None
        assert user.name == "John Doe"
        assert user.email == "john@example.com"
        assert user.age == 28
        assert user.is_active is True  # Default value

    @pytest.mark.asyncio
    async def test_create_with_all_fields(self, manager):
        """Test creating an instance with all fields specified."""
        user = await manager.create(
            name="Jane Doe",
            email="jane@example.com",
            age=32,
            is_active=False
        )

        assert user.name == "Jane Doe"
        assert user.email == "jane@example.com"
        assert user.age == 32
        assert user.is_active is False

    @pytest.mark.asyncio
    async def test_create_with_nullable_field(self, manager):
        """Test creating an instance with nullable field set to None."""
        user = await manager.create(
            name="No Age User",
            email="noage@example.com",
            age=None
        )

        assert user.age is None

    @pytest.mark.asyncio
    async def test_create_multiple_instances(self, manager):
        """Test creating multiple instances sequentially."""
        user1 = await manager.create(name="User1", email="user1@example.com")
        user2 = await manager.create(name="User2", email="user2@example.com")

        assert user1.id != user2.id
        assert user1.name == "User1"
        assert user2.name == "User2"


# -----------------------------------------------------------------------------
# Tests: Bulk Create Operations
# -----------------------------------------------------------------------------

class TestManagerBulkCreate:
    """Tests for Manager.bulk_create() method."""

    @pytest.mark.asyncio
    async def test_bulk_create(self, session, manager):
        """Test bulk creating multiple instances."""
        users = [
            SampleUser(name="User1", email="bulk1@example.com"),
            SampleUser(name="User2", email="bulk2@example.com"),
            SampleUser(name="User3", email="bulk3@example.com"),
        ]

        result = await manager.bulk_create(users)

        assert len(result) == 3
        all_users = await manager.all()
        assert len(all_users) == 3

    @pytest.mark.asyncio
    async def test_bulk_create_with_refresh(self, session, manager):
        """Test bulk creating with refresh=True to get updated state."""
        users = [
            SampleUser(name="RefreshUser1", email="refresh1@example.com"),
            SampleUser(name="RefreshUser2", email="refresh2@example.com"),
        ]

        result = await manager.bulk_create(users, refresh=True)

        assert len(result) == 2
        for user in result:
            assert user.id is not None

    @pytest.mark.asyncio
    async def test_bulk_create_empty_list(self, manager):
        """Test bulk creating with an empty list."""
        result = await manager.bulk_create([])
        assert result == []


# -----------------------------------------------------------------------------
# Tests: Query Operations - all, get, filter, first
# -----------------------------------------------------------------------------

class TestManagerQueryOperations:
    """Tests for Manager query methods: all, get, filter, first."""

    @pytest.mark.asyncio
    async def test_all_empty_table(self, manager):
        """Test all() returns empty sequence when table is empty."""
        result = await manager.all()
        assert result == []

    @pytest.mark.asyncio
    async def test_all_with_data(self, populated_session):
        """Test all() returns all rows."""
        manager = SampleUser.objects(populated_session)
        result = await manager.all()
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_get_existing_record(self, populated_session):
        """Test get() returns matching record."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(email="alice@example.com")

        assert user is not None
        assert user.name == "Alice"
        assert user.email == "alice@example.com"

    @pytest.mark.asyncio
    async def test_get_nonexistent_record(self, populated_session):
        """Test get() returns None for non-existent record."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(email="nonexistent@example.com")
        assert user is None

    @pytest.mark.asyncio
    async def test_get_with_multiple_filters(self, populated_session):
        """Test get() with multiple filter kwargs."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(name="Alice", is_active=True)

        assert user is not None
        assert user.name == "Alice"

    @pytest.mark.asyncio
    async def test_filter_returns_matching_rows(self, populated_session):
        """Test filter() returns all matching rows."""
        manager = SampleUser.objects(populated_session)
        active_users = await manager.filter(is_active=True)

        assert len(active_users) == 2
        for user in active_users:
            assert user.is_active is True

    @pytest.mark.asyncio
    async def test_filter_no_matches(self, populated_session):
        """Test filter() returns empty sequence when no matches."""
        manager = SampleUser.objects(populated_session)
        result = await manager.filter(age=100)
        assert result == []

    @pytest.mark.asyncio
    async def test_first_returns_single_row(self, populated_session):
        """Test first() returns a single row."""
        manager = SampleUser.objects(populated_session)
        user = await manager.first()

        assert user is not None
        assert isinstance(user, SampleUser)

    @pytest.mark.asyncio
    async def test_first_empty_table(self, manager):
        """Test first() returns None when table is empty."""
        result = await manager.first()
        assert result is None


# -----------------------------------------------------------------------------
# Tests: Count and Exists Operations
# -----------------------------------------------------------------------------

class TestManagerCountAndExists:
    """Tests for Manager.count() and Manager.exists() methods."""

    @pytest.mark.asyncio
    async def test_count_empty_table(self, manager):
        """Test count() returns 0 for empty table."""
        count = await manager.count()
        assert count == 0

    @pytest.mark.asyncio
    async def test_count_all_rows(self, populated_session):
        """Test count() returns total row count."""
        manager = SampleUser.objects(populated_session)
        count = await manager.count()
        assert count == 3

    @pytest.mark.asyncio
    async def test_count_with_filter(self, populated_session):
        """Test count() with filter kwargs."""
        manager = SampleUser.objects(populated_session)
        count = await manager.count(is_active=True)
        assert count == 2

    @pytest.mark.asyncio
    async def test_count_with_no_matches(self, populated_session):
        """Test count() returns 0 when no matches."""
        manager = SampleUser.objects(populated_session)
        count = await manager.count(age=999)
        assert count == 0

    @pytest.mark.asyncio
    async def test_exists_returns_true(self, populated_session):
        """Test exists() returns True when record exists."""
        manager = SampleUser.objects(populated_session)
        exists = await manager.exists(email="alice@example.com")
        assert exists is True

    @pytest.mark.asyncio
    async def test_exists_returns_false(self, populated_session):
        """Test exists() returns False when record doesn't exist."""
        manager = SampleUser.objects(populated_session)
        exists = await manager.exists(email="nonexistent@example.com")
        assert exists is False

    @pytest.mark.asyncio
    async def test_exists_with_multiple_filters(self, populated_session):
        """Test exists() with multiple filter kwargs."""
        manager = SampleUser.objects(populated_session)
        exists = await manager.exists(name="Charlie", is_active=False)
        assert exists is True


# -----------------------------------------------------------------------------
# Tests: Update Operations
# -----------------------------------------------------------------------------

class TestModelUpdate:
    """Tests for Model.update() method."""

    @pytest.mark.asyncio
    async def test_update_single_field(self, populated_session):
        """Test updating a single field on an instance."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(email="alice@example.com")

        await user.update(populated_session, name="Alice Updated")

        assert user.name == "Alice Updated"
        assert user.email == "alice@example.com"  # Unchanged

    @pytest.mark.asyncio
    async def test_update_multiple_fields(self, populated_session):
        """Test updating multiple fields at once."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(email="bob@example.com")

        await user.update(populated_session, name="Bob Updated", age=99, is_active=False)

        assert user.name == "Bob Updated"
        assert user.age == 99
        assert user.is_active is False

    @pytest.mark.asyncio
    async def test_update_in_place(self, populated_session):
        """Test that update modifies the instance in place."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(email="alice@example.com")
        original_id = user.id

        await user.update(populated_session, name="New Name")

        assert user.id == original_id
        assert user.name == "New Name"


# -----------------------------------------------------------------------------
# Tests: Delete Operations
# -----------------------------------------------------------------------------

class TestManagerDelete:
    """Tests for Manager.delete() and Manager.delete_all() methods."""

    @pytest.mark.asyncio
    async def test_delete_single_instance(self, populated_session):
        """Test deleting a single instance."""
        manager = SampleUser.objects(populated_session)
        user = await manager.get(email="alice@example.com")

        await user.delete(populated_session)

        # Verify deletion
        deleted_user = await manager.get(email="alice@example.com")
        assert deleted_user is None
        assert await manager.count() == 2

    @pytest.mark.asyncio
    async def test_delete_all_with_filter(self, populated_session):
        """Test delete_all() with filter kwargs."""
        manager = SampleUser.objects(populated_session)

        deleted_count = await manager.delete_all(is_active=False)

        assert deleted_count == 1
        assert await manager.count() == 2
        # Charlie was inactive and should be deleted
        assert await manager.get(email="charlie@example.com") is None

    @pytest.mark.asyncio
    async def test_delete_all_no_filter(self, populated_session):
        """Test delete_all() without filters deletes all rows."""
        manager = SampleUser.objects(populated_session)

        deleted_count = await manager.delete_all()

        assert deleted_count == 3
        assert await manager.count() == 0

    @pytest.mark.asyncio
    async def test_delete_all_no_matches(self, populated_session):
        """Test delete_all() returns 0 when no matches."""
        manager = SampleUser.objects(populated_session)

        deleted_count = await manager.delete_all(age=999)

        assert deleted_count == 0
        assert await manager.count() == 3  # No rows deleted


# -----------------------------------------------------------------------------
# Tests: Get or Create Operations
# -----------------------------------------------------------------------------

class TestManagerGetOrCreate:
    """Tests for Manager.get_or_create() method."""

    @pytest.mark.asyncio
    async def test_get_or_create_creates_new(self, manager):
        """Test get_or_create creates new instance when not found."""
        user, created = await manager.get_or_create(
            email="newuser@example.com",
            defaults={"name": "New User", "age": 25}
        )

        assert created is True
        assert user.email == "newuser@example.com"
        assert user.name == "New User"
        assert user.age == 25

    @pytest.mark.asyncio
    async def test_get_or_create_gets_existing(self, populated_session):
        """Test get_or_create returns existing instance."""
        manager = SampleUser.objects(populated_session)

        user, created = await manager.get_or_create(
            email="alice@example.com",
            defaults={"name": "Should Not Be Used"}
        )

        assert created is False
        assert user.email == "alice@example.com"
        assert user.name == "Alice"  # Original name, not defaults

    @pytest.mark.asyncio
    async def test_get_or_create_without_defaults(self, manager):
        """Test get_or_create without defaults dict."""
        user, created = await manager.get_or_create(
            name="Simple User",
            email="simple@example.com"
        )

        assert created is True
        assert user.name == "Simple User"
        assert user.email == "simple@example.com"

    @pytest.mark.asyncio
    async def test_get_or_create_lookup_uses_kwargs(self, populated_session):
        """Test that get_or_create uses kwargs for lookup, not defaults."""
        manager = SampleUser.objects(populated_session)

        # Alice exists with age=30, but we're looking for email only
        user, created = await manager.get_or_create(
            email="alice@example.com",
            defaults={"name": "Different Name", "age": 100}
        )

        assert created is False
        assert user.name == "Alice"
        assert user.age == 30  # Original value, not from defaults


# -----------------------------------------------------------------------------
# Tests: Update or Create Operations
# -----------------------------------------------------------------------------

class TestManagerUpdateOrCreate:
    """Tests for Manager.update_or_create() method."""

    @pytest.mark.asyncio
    async def test_update_or_create_creates_new(self, manager):
        """Test update_or_create creates new instance when not found."""
        user, created = await manager.update_or_create(
            email="brand_new@example.com",
            defaults={"name": "Brand New User", "age": 22}
        )

        assert created is True
        assert user.email == "brand_new@example.com"
        assert user.name == "Brand New User"
        assert user.age == 22

    @pytest.mark.asyncio
    async def test_update_or_create_updates_existing(self, populated_session):
        """Test update_or_create updates existing instance with defaults."""
        manager = SampleUser.objects(populated_session)

        user, created = await manager.update_or_create(
            email="alice@example.com",
            defaults={"name": "Alice Updated", "age": 99}
        )

        assert created is False
        assert user.email == "alice@example.com"
        assert user.name == "Alice Updated"
        assert user.age == 99

    @pytest.mark.asyncio
    async def test_update_or_create_partial_update(self, populated_session):
        """Test update_or_create with partial defaults."""
        manager = SampleUser.objects(populated_session)

        user, created = await manager.update_or_create(
            email="bob@example.com",
            defaults={"name": "Bob Modified"}
        )

        assert created is False
        assert user.name == "Bob Modified"
        assert user.age == 25  # Original value preserved

    @pytest.mark.asyncio
    async def test_update_or_create_without_defaults(self, manager):
        """Test update_or_create without defaults creates with kwargs only."""
        user, created = await manager.update_or_create(
            name="Minimal User",
            email="minimal@example.com"
        )

        assert created is True
        assert user.name == "Minimal User"
        assert user.email == "minimal@example.com"


# -----------------------------------------------------------------------------
# Tests: Base Query Method
# -----------------------------------------------------------------------------

class TestManagerBaseQuery:
    """Tests for Manager._base_query() method."""

    @pytest.mark.asyncio
    async def test_base_query_returns_select(self, manager):
        """Test that _base_query returns a Select statement."""
        from sqlalchemy.sql import Select
        query = manager._base_query()
        assert isinstance(query, Select)


# -----------------------------------------------------------------------------
# Tests: Edge Cases and Error Handling
# -----------------------------------------------------------------------------

class TestManagerEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_create_with_invalid_field_raises(self, manager):
        """Test that creating with invalid field raises an error."""
        with pytest.raises(TypeError):
            await manager.create(
                name="Test",
                email="test@example.com",
                nonexistent_field="value"
            )

    @pytest.mark.asyncio
    async def test_filter_with_invalid_field_raises(self, populated_session):
        """Test that filtering with invalid field raises an error."""
        manager = SampleUser.objects(populated_session)
        with pytest.raises(Exception):  # SQLAlchemy raises InvalidRequestError
            await manager.filter(nonexistent_field="value")

    @pytest.mark.asyncio
    async def test_manager_operations_without_session_raise(self):
        """Test that operations without bound session raise RuntimeError."""
        manager = Manager(SampleUser)

        with pytest.raises(RuntimeError, match="No session bound"):
            await manager.all()

        with pytest.raises(RuntimeError, match="No session bound"):
            await manager.get(id=1)

        with pytest.raises(RuntimeError, match="No session bound"):
            await manager.create(name="Test", email="test@example.com")

    @pytest.mark.asyncio
    async def test_concurrent_get_or_create_scenario(self, manager):
        """Test get_or_create idempotency (basic scenario)."""
        # Create the same user twice using get_or_create
        user1, created1 = await manager.get_or_create(
            email="concurrent@example.com",
            defaults={"name": "Concurrent User"}
        )
        user2, created2 = await manager.get_or_create(
            email="concurrent@example.com",
            defaults={"name": "Different Name"}
        )

        assert created1 is True
        assert created2 is False
        assert user1.id == user2.id
        assert user2.name == "Concurrent User"  # Original name preserved


# -----------------------------------------------------------------------------
# Tests: Model.get_schema() Method
# -----------------------------------------------------------------------------

class TestModelGetSchema:
    """Tests for Model.get_schema() method."""

    def test_get_schema_returns_pydantic_model(self):
        """Test that get_schema returns a Pydantic BaseModel subclass."""
        from pydantic import BaseModel
        schema = SampleUser.get_schema()
        assert issubclass(schema, BaseModel)

    def test_get_schema_has_correct_fields(self):
        """Test that generated schema has correct fields."""
        schema = SampleUser.get_schema()
        fields = schema.model_fields

        assert "id" in fields
        assert "name" in fields
        assert "email" in fields
        assert "age" in fields
        assert "is_active" in fields

    def test_get_schema_excludes_fields(self):
        """Test that get_schema respects exclude parameter."""
        schema = SampleUser.get_schema(exclude={"id", "is_active"})
        fields = schema.model_fields

        assert "id" not in fields
        assert "is_active" not in fields
        assert "name" in fields
        assert "email" in fields

    def test_get_schema_validates_data(self):
        """Test that generated schema can validate data."""
        schema = SampleUser.get_schema()
        instance = schema(
            id=1,
            name="Test",
            email="test@example.com",
            age=25,
            is_active=True
        )

        assert instance.name == "Test"
        assert instance.email == "test@example.com"

    def test_get_schema_from_attributes(self):
        """Test that schema can be created from ORM model attributes."""
        from pydantic import BaseModel
        schema = SampleUser.get_schema()

        # Verify ConfigDict allows from_attributes
        assert schema.model_config.get("from_attributes") is True


# -----------------------------------------------------------------------------
# Tests: Base and Model Classes
# -----------------------------------------------------------------------------

class TestBaseAndModelClasses:
    """Tests for Base and Model class functionality."""

    def test_model_has_id_column(self):
        """Test that Model subclasses have id column."""
        assert hasattr(SampleUser, "id")

    def test_model_is_abstract(self):
        """Test that Model itself is abstract."""
        assert Model.__abstract__ is True

    def test_tablename_generation(self):
        """Test that tablename is correctly generated."""
        # SampleUser has explicit __tablename__, but we can verify it
        assert SampleUser.__tablename__ == "sample_user"


# -----------------------------------------------------------------------------
# Tests: Integration Tests
# -----------------------------------------------------------------------------

class TestManagerIntegration:
    """Integration tests combining multiple Manager operations."""

    @pytest.mark.asyncio
    async def test_full_crud_workflow(self, manager):
        """Test complete CRUD workflow."""
        # Create
        user = await manager.create(
            name="CRUD User",
            email="crud@example.com",
            age=30
        )
        assert user.id is not None
        user_id = user.id

        # Read
        fetched = await manager.get(id=user_id)
        assert fetched is not None
        assert fetched.name == "CRUD User"

        # Update
        await fetched.update(manager._get_session(), name="Updated CRUD User", age=31)
        assert fetched.name == "Updated CRUD User"
        assert fetched.age == 31

        # Delete
        await fetched.delete(manager._get_session())
        deleted = await manager.get(id=user_id)
        assert deleted is None

    @pytest.mark.asyncio
    async def test_filter_and_bulk_operations(self, manager):
        """Test filtering combined with bulk operations."""
        # Bulk create
        users = [
            SampleUser(name=f"User{i}", email=f"user{i}@example.com", age=20 + i, is_active=i % 2 == 0)
            for i in range(5)
        ]
        await manager.bulk_create(users)

        # Filter active users
        active_users = await manager.filter(is_active=True)
        assert len(active_users) == 3  # Users 0, 2, 4

        # Count inactive
        inactive_count = await manager.count(is_active=False)
        assert inactive_count == 2  # Users 1, 3

        # Delete inactive users
        deleted = await manager.delete_all(is_active=False)
        assert deleted == 2

        # Verify remaining
        remaining = await manager.all()
        assert len(remaining) == 3
        for user in remaining:
            assert user.is_active is True

    @pytest.mark.asyncio
    async def test_update_or_create_workflow(self, manager):
        """Test update_or_create in a typical workflow."""
        # First call - creates
        user1, created1 = await manager.update_or_create(
            email="workflow@example.com",
            defaults={"name": "Workflow User", "age": 25}
        )
        assert created1 is True
        assert user1.name == "Workflow User"

        # Second call - updates
        user2, created2 = await manager.update_or_create(
            email="workflow@example.com",
            defaults={"name": "Updated Workflow User", "age": 26}
        )
        assert created2 is False
        assert user2.name == "Updated Workflow User"
        assert user2.age == 26
        assert user1.id == user2.id

        # Verify only one record exists
        count = await manager.count(email="workflow@example.com")
        assert count == 1
