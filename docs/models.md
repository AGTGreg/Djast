**Models Overview**

This document explains the async ORM helpers defined in `app/djast/db/models.py` and shows how to use the provided `Manager`, `Base`, `Model`, and `TimestampMixin`. It also explains how `settings` and `database` shape runtime behavior and provides concise examples for each method.

**Files:** `app/djast/db/models.py`, `app/djast/settings.py`, `app/djast/database.py`

**Quick summary:**
- **Manager**: Django-style async manager exposed as `Model.objects(session)` with common query and mutation helpers.
- **Base**: Declarative base that auto-generates `__tablename__` from the model class and module.
- **TimestampMixin**: Adds timezone-aware `created_at` and `updated_at` columns.
- **Model**: Abstract model adding an integer `id` primary key, instance helpers (`save`, `update`, `delete`), `get_schema` (pydantic), and `objects(session)` to get a `Manager`.

**Settings & database**
- **Settings source:** `app/djast/settings.py` — `settings.DATABASES["default"]` selects DB engine (default is a local SQLite file). Adjust this for production (e.g. `postgresql+asyncpg`).
- **Engine & sessions:** `app/djast/database.py` builds the engine from settings and exposes:
	- `engine` — SQLAlchemy async engine
	- `async_session_factory` — `async_sessionmaker(...)`
	- `get_async_session()` — async generator intended for FastAPI dependency injection. It yields an `AsyncSession`, commits after successful use, and rolls back on exceptions.

Use patterns:
```python
# FastAPI dependency
@router.post("/items")
async def create_item(data: ItemCreate, session: AsyncSession = Depends(get_async_session)):
		item = await Item.objects(session).create(**data.dict())
		return item

# Manual usage (scripts/tests)
from djast.database import async_session_factory

async def manual():
		async with async_session_factory() as session:
				obj = await User.objects(session).create(email="x@example.com")
				await session.commit()  # if not using `get_async_session`
```

**Manager (Model.objects(session))**
The `Manager` is a small, Django-esque async helper bound to an `AsyncSession` via `Model.objects(session)`. Methods are all awaitable and operate with SQLAlchemy Core under the hood.

- **Query helpers**:
	- `all()` — return all rows: `await Model.objects(session).all()`
	- `get(**filters)` — return single instance or `None`
	- `filter(**filters)` — return matching rows
	- `first()` — return first row or `None`
	- `count(**filters)` — integer count
	- `exists(**filters)` — boolean

- **Mutation helpers**:
	- `create(**kwargs)` — construct, add, flush, refresh; does NOT commit the transaction
	- `get_or_create(defaults=None, **kwargs)` — atomic-ish create or return existing; handles `IntegrityError` races
	- `update_or_create(defaults=None, **kwargs)` — update existing or create, with race handling
	- `bulk_create(objects: list[T], refresh: bool = False)` — add many instances, optional refresh
	- `delete_all(**filters)` — bulk delete rows matching filters; returns deleted rowcount

Notes:
- `create` / `bulk_create` / `update_or_create` call `flush()` and `refresh()` as needed but do not `commit()` — `get_async_session` will commit automatically if used as a dependency. For manual sessions, call `await session.commit()`.

**`Base` extras** (`class Base(AsyncAttrs, DeclarativeBase)`)
- Auto `__tablename__`: The table name is generated from the model's module and class name into snake_case prefixed by the parent module segment. Example: a model declared in `myapp.models` with class `Item` becomes table `myapp_item`.
- Inherits `AsyncAttrs` so relationship attributes and deferred loads are awaitable.

**`TimestampMixin`**
- Provides two columns available to include on models:
	- `created_at: DateTime(timezone=True)` — default and server default set to now
	- `updated_at: DateTime(timezone=True)` — updated automatically via `onupdate`

Add it to a model like `class Post(Model, TimestampMixin): ...`

**`Model` extras** (`class Model(Base)`)
- `__abstract__ = True` — not mapped directly
- `id` — integer primary key with index
- Instance helpers (all async):
	- `await instance.save(session)` — adds and flushes the instance and refreshes from DB
	- `await instance.update(session, **kwargs)` — set attributes then save
	- `await instance.delete(session)` — delete and flush
- `@classmethod objects(cls, session)` — returns a `Manager` bound to the provided `AsyncSession` (use this for all queries/mutations)
- `get_schema(cls, exclude: set[str] | None = None)` — auto-generate a `pydantic.BaseModel` for serialization using SQLAlchemy column typing. Uses `pydantic.create_model(..., __config__=ConfigDict(from_attributes=True))`.

**Examples**
Assume a simple `User` model defined like:
```python
# example: app/models/user.py
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from djast.db.models import Model, TimestampMixin

class User(Model, TimestampMixin):
		email: Mapped[str] = mapped_column(String(256), unique=True, index=True, nullable=False)
		name: Mapped[str] = mapped_column(String(120), nullable=True)
```

Usage patterns below import `get_async_session` or `async_session_factory` from `djast.database`.

Manager examples (all async):
```python
from djast.database import get_async_session, async_session_factory
from app.models.user import User

async def example_fastapi(session: AsyncSession = Depends(get_async_session)):
		# create
		user = await User.objects(session).create(email="a@b.com", name="A")

		# get
		user2 = await User.objects(session).get(id=user.id)

		# filter
		users = await User.objects(session).filter(name="A")

		# all
		all_users = await User.objects(session).all()

		# first
		first = await User.objects(session).first()

		# count
		cnt = await User.objects(session).count()

		# exists
		ok = await User.objects(session).exists(email="a@b.com")

		# get_or_create
		u, created = await User.objects(session).get_or_create(
				email="c@d.com",
				defaults={"name": "C"}
		)

		# update_or_create
		u2, created2 = await User.objects(session).update_or_create(
				email="x@y.com",
				defaults={"name": "X"}
		)

		# bulk_create (pass model instances)
		users_to_insert = [User(email=f"u{i}@ex.com") for i in range(3)]
		inserted = await User.objects(session).bulk_create(users_to_insert, refresh=True)

		# delete_all
		deleted_count = await User.objects(session).delete_all(name=None)

		return {
				"created": created,
				"count": cnt,
				"deleted": deleted_count,
		}

async def example_script_manual():
		# manual session (scripts/tests)
		async with async_session_factory() as session:
				u = await User.objects(session).create(email="manual@ex.com")
				await session.commit()  # required for manual sessions

```

Model instance methods examples:
```python
async def instance_examples():
		async with async_session_factory() as session:
				user = User(email="temp@ex.com")

				# save
				await user.save(session)

				# update
				await user.update(session, name="New Name")

				# delete
				await user.delete(session)

				await session.commit()

# get_schema: produce a pydantic model for serialization
UserSchema = User.get_schema(exclude={"password"})
instance = User(email="x@x.com", name="X")
user_data = UserSchema.from_orm(instance)  # or instantiate from attributes
```

**Transaction semantics & race conditions**
- `get_or_create` and `update_or_create` catch `sqlalchemy.exc.IntegrityError` to handle simple race conditions where another transaction concurrently created the same row; on IntegrityError they `rollback()` and re-fetch.
- Most Manager methods `flush()` but do not `commit()` — rely on `get_async_session` to commit. For scripts/tests using `async_session_factory`, call `await session.commit()` when you want to persist changes.

**Tips & gotchas**
- `bulk_create` expects instances (not dictionaries). If you need to create many rows from dicts, first construct model instances.
- `Model.get_schema()` uses SQLAlchemy column python types where available; some SQLAlchemy types may map to `Any` in the generated schema.
- Use `TimestampMixin` when you want automatic `created_at` / `updated_at` tracking.

If you want, I can add short real-world examples using your app structure (e.g. `auth.models.User`) or add a small test file demonstrating these patterns.

