from __future__ import annotations
import re

from typing import Any, Optional, TypeVar, Generic, TYPE_CHECKING, Sequence

from pydantic import create_model
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, func, inspect, select, delete as sa_delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncSession
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    declared_attr
)

from djast.utils.timezone import now as get_now

if TYPE_CHECKING:
    from sqlalchemy.sql import Select

T = TypeVar("T", bound="Base")


class Manager(Generic[T]):
    """
    Django-style async manager exposed on Base.objects.
    Provides common query shortcuts (all, get, filter, create, delete, etc.)
    using an injected AsyncSession.
    """

    def __init__(self, model_class: type[T]) -> None:
        self._model = model_class
        self._session: AsyncSession | None = None

    def with_session(self, session: AsyncSession) -> "Manager[T]":
        """Return a new Manager bound to the given session."""
        mgr = Manager(self._model)
        mgr._session = session
        return mgr

    def _get_session(self) -> AsyncSession:
        if self._session is None:
            raise RuntimeError(
                "No session bound. Use Model.objects.with_session(session) first."
            )
        return self._session

    # -------------------------------------------------------------------------
    # Query helpers
    # -------------------------------------------------------------------------

    def _base_query(self) -> "Select[tuple[T]]":
        return select(self._model)

    async def all(self) -> Sequence[T]:
        """Return all rows."""
        session = self._get_session()
        result = await session.scalars(self._base_query())
        return result.all()

    async def get(self, **kwargs: Any) -> T | None:
        """
        Fetch a single instance matching the provided column filters.

        Args:
            **kwargs: Attributes to filter which row to return.

        Returns:
            The instance if found, else None.
        """
        session = self._get_session()
        stmt = self._base_query().filter_by(**kwargs)
        return await session.scalar(stmt)

    async def filter(self, **kwargs: Any) -> Sequence[T]:
        """
        Return all rows matching the provided column filters.

        Args:
            **kwargs: Attributes to filter which rows to return.

        Returns:
            A sequence of matching instances.
        """
        session = self._get_session()
        stmt = self._base_query().filter_by(**kwargs)
        result = await session.scalars(stmt)
        return result.all()

    async def first(self) -> T | None:
        """Return the first row or None."""
        session = self._get_session()
        stmt = self._base_query().limit(1)
        return await session.scalar(stmt)

    async def count(self, **kwargs: Any) -> int:
        """
        Return total row count.

        Args:
            **kwargs: Optional attributes to filter which rows to count.

        Returns:
            The count of matching rows.
        """
        from sqlalchemy import func as sa_func
        session = self._get_session()
        stmt = select(sa_func.count()).select_from(self._model)
        if kwargs:
            stmt = stmt.filter_by(**kwargs)
        result = await session.scalar(stmt)
        return result or 0

    async def exists(self, **kwargs: Any) -> bool:
        """
        Return True if at least one matching row exists.

        Args:
            **kwargs: Attributes to filter which rows to check.

        Returns:
            True if a matching row exists, else False.
        """
        return await self.get(**kwargs) is not None

    # -------------------------------------------------------------------------
    # Mutation helpers
    # -------------------------------------------------------------------------

    async def create(self, **kwargs: Any) -> T:
        """
        Insert a new row and return the instance (flushed, not committed).

        Note: This method flushes to the database but does NOT commit.
        When used with FastAPI's `get_async_session` dependency, the session
        commits automatically on successful request completion.
        If using outside of the dependency injection context, you must call
        `await session.commit()` manually.

        Args:
            **kwargs: Attributes to set on the new instance.

        Returns:
            The newly created instance.
        """
        session = self._get_session()
        instance = self._model(**kwargs)
        session.add(instance)
        await session.flush()
        await session.refresh(instance)
        return instance

    async def get_or_create(
        self, defaults: dict[str, Any] | None = None, **kwargs: Any
    ) -> tuple[T, bool]:
        """
        Look up an object with the given kwargs, creating one if necessary.
        Returns a tuple of (instance, created), where created is True if a new
        object was created.

        This method handles race conditions by catching IntegrityError and
        retrying the lookup if another transaction created the row first.

        Args:
            defaults: A dictionary of attributes to set on creation if not found.
            **kwargs: Attributes to filter the lookup.

        Returns:
            A tuple of (instance, created), where 'created' is a boolean indicating
            whether a new instance was created (True) or an existing one was found (False).

        Usage:
            user, created = await User.objects.with_session(session).get_or_create(
                email="test@example.com",
                defaults={"name": "Test User"}
            )
        """
        instance = await self.get(**kwargs)
        if instance is not None:
            return instance, False

        create_kwargs = {**kwargs, **(defaults or {})}
        try:
            instance = await self.create(**create_kwargs)
            return instance, True
        except IntegrityError:
            # Another transaction created the row; rollback partial state and re-fetch
            session = self._get_session()
            await session.rollback()
            instance = await self.get(**kwargs)
            if instance is not None:
                return instance, False
            # If still not found, re-raise - something else went wrong
            raise

    async def update_or_create(
        self, defaults: dict[str, Any] | None = None, **kwargs: Any
    ) -> tuple[T, bool]:
        """
        Look up an object with the given kwargs, updating one with defaults if it exists,
        otherwise create a new one.
        Returns a tuple of (instance, created), where created is True if a new
        object was created.

        This method handles race conditions by catching IntegrityError and
        retrying the lookup/update if another transaction created the row first.

        Args:
            defaults: A dictionary of attributes to update on the instance if found,
                      or to set on creation if not found.
            **kwargs: Attributes to filter the lookup.

        Returns:
            A tuple of (instance, created), where 'created' is a boolean indicating
            whether a new instance was created (True) or an existing one was updated (False).

        Usage:
            user, created = await User.objects.with_session(session).update_or_create(
                email="test@example.com",
                defaults={"name": "Updated Name"}
            )
        """
        defaults = defaults or {}
        instance = await self.get(**kwargs)
        if instance is not None:
            instance = await self.update(instance, **defaults)
            return instance, False

        create_kwargs = {**kwargs, **defaults}
        try:
            instance = await self.create(**create_kwargs)
            return instance, True
        except IntegrityError:
            # Another transaction created the row; rollback partial state and update
            session = self._get_session()
            await session.rollback()
            instance = await self.get(**kwargs)
            if instance is not None:
                instance = await self.update(instance, **defaults)
                return instance, False
            # If still not found, re-raise - something else went wrong
            raise

    async def bulk_create(self, objects: list[T], refresh: bool = False) -> list[T]:
        """
        Insert multiple instances.

        Args:
            objects: A list of instances to be inserted.
            refresh: If True, refresh each instance after insertion to get
            updated state from the database. This is False by default because it
            is highly inefficient for large batches.

        Returns:
            The list of inserted instances.
        """
        session = self._get_session()
        session.add_all(objects)
        await session.flush()
        if refresh:
            for obj in objects:
                await session.refresh(obj)
        return objects

    async def update(self, instance: T, **kwargs: Any) -> T:
        """
        Update attributes on an existing instance.

        Args:
            instance: The instance to be updated.
            **kwargs: Attributes to update on the instance.

        Returns:
            The updated instance.
        """
        session = self._get_session()
        for key, value in kwargs.items():
            setattr(instance, key, value)
        session.add(instance)
        await session.flush()
        await session.refresh(instance)
        return instance

    async def delete(self, instance: T) -> None:
        """
        Delete a single instance.

        Args:
            instance: The instance to be deleted.
        """
        session = self._get_session()
        await session.delete(instance)
        await session.flush()

    async def delete_all(self, **kwargs: Any) -> int:
        """
        Delete all rows matching filters; return count deleted.

        Args:
            **kwargs: Attributes to filter which rows to delete.

        Returns:
            The number of rows deleted.
        """
        session = self._get_session()
        stmt = sa_delete(self._model).filter_by(**kwargs)
        result = await session.execute(stmt)
        await session.flush()
        return result.rowcount


class Base(AsyncAttrs, DeclarativeBase):
    """
    Base class for all models. Inherit from this class to get:
    1. Auto-tablename dirived from class name and module name
    2. AsyncAttrs for awaitable attributes
    """

    @declared_attr.directive
    def __tablename__(cls) -> str:
        """
        Auto-generate table name in snake_case prefixed by parent module name.
        """
        module_name = cls.__module__
        if module_name in ("", "builtins"):
            parent_segment = "app"
        else:
            parent_module = (
                module_name.rsplit(".", 1)[0]
                if "." in module_name
                else module_name
            )
            parent_segment = (
                parent_module.split(".")[-1]
                if parent_module
                else module_name
            )

        snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()
        return f"{parent_segment}_{snake_name}"


class TimestampMixin:
    """Mixin to add timezone aware created_at and updated_at columns."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_now,
        server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=get_now,
        server_default=func.now(),
        onupdate=get_now
    )


class Model(Base):
    """
    Inherit from this class to get:
    1. Integer Primary Key 'id'
    2. Auto-tablename dirived from class name and module name
    3. Django-style async Manager via `objects` attribute
    4. AsyncAttrs for awaitable attributes
    5. Pydantic schema generation via `get_schema` method
    """
    __abstract__ = True

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    @classmethod
    def objects(cls, session) -> "Manager[Any]":
        """
        Return a Manager instance for the model class.

        Args:
            session: An AsyncSession instance to bind to the Manager.

        Returns:
            A Manager instance bound to the provided session.
        """
        return Manager(cls).with_session(session)

    @classmethod
    def get_schema(cls, exclude: set[str] | None = None) -> type[BaseModel]:
        """
        Auto-generate a valid Pydantic BaseModel schema from the model's fields,
        excluding the `exclude` fields. The schema can be used for serialization
        and validation in FastAPI.

        Args:
            exclude: An optional set of field names to exclude from the schema.

        Returns:
            A Pydantic BaseModel subclass representing the schema.
        """
        mapper = inspect(cls)
        fields = {}
        exclude = exclude or set()

        for column in mapper.columns:
            if column.name in exclude:
                continue

            try:
                python_type = column.type.python_type
            except NotImplementedError:
                python_type = Any

            if column.nullable:
                python_type = Optional[python_type]
                default = None
            else:
                default = ...

            fields[column.name] = (python_type, default)

        return create_model(
            f"{cls.__name__}Schema",
            __config__=ConfigDict(from_attributes=True),
            **fields,
        )
