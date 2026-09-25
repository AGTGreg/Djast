# Models

This document covers the ORM layer: how to define models, query data, generate Pydantic schemas, and manage sessions.

**Files:** `app/djast/db/models.py`, `app/djast/database.py`, `app/djast/settings.py`

---

## Defining a Model

Inherit from `models.Model` to get an auto-generated table name, an integer `id` primary key, async attributes, a Django-style manager, and Pydantic schema generation.

```python
from sqlalchemy import String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from djast.db import models


class Author(models.Model, models.TimestampMixin):
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    posts: Mapped[list["Post"]] = relationship(back_populates="author")


class Post(models.Model, models.TimestampMixin):
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, default=None)
    author_id: Mapped[int] = mapped_column(ForeignKey("myapp_author.id"), nullable=False)

    author: Mapped["Author"] = relationship(back_populates="posts")
```

### What `models.Model` gives you

| Feature | Description |
|---------|-------------|
| Auto table name | Derived from module + class name in snake_case (e.g., `myapp_author` for `Author` in `myapp/models.py`) |
| Integer PK | `id` column, primary key, indexed |
| Async attributes | `AsyncAttrs` — you can `await` lazy-loaded relationships |
| Manager | `Model.objects(session)` for Django-style queries |
| Instance methods | `save()`, `update()`, `delete()` |
| Schema generation | `Model.get_schema()` to auto-generate Pydantic models |

### TimestampMixin

Add `models.TimestampMixin` to any model that needs `created_at` and `updated_at` columns. Both are timezone-aware and `updated_at` updates automatically on changes.

```python
class Post(models.Model, models.TimestampMixin):
    ...
```

### Using `Base` directly

If you don't want the automatic `id` primary key (e.g., for composite keys or UUIDs), inherit from `models.Base` instead. You still get the auto table name and async attributes, but you define your own primary key.

---

## Querying with the Manager

Call `Model.objects(session)` to get a manager bound to your session. All methods are async.

### Query methods

```python
# Get all rows
authors = await Author.objects(session).all()

# Get a single row by any field(s) — returns None if not found
author = await Author.objects(session).get(id=1)
author = await Author.objects(session).get(email="jane@example.com")

# Filter — returns a list of matching rows
posts = await Post.objects(session).filter(author_id=1)

# First row or None
author = await Author.objects(session).first()

# Count rows (optionally with filters)
total = await Author.objects(session).count()
active = await Post.objects(session).count(is_published=True)

# Check if a row exists
exists = await Author.objects(session).exists(email="jane@example.com")
```

### Mutation methods

All mutation methods flush to the database but do **not** commit. When used inside a FastAPI endpoint with `get_async_session`, the session commits automatically. For scripts or tests, call `await session.commit()` manually.

```python
# Create a new row
author = await Author.objects(session).create(name="Jane", email="jane@example.com")

# Get or create — returns (instance, created_bool)
author, created = await Author.objects(session).get_or_create(
    email="jane@example.com",
    defaults={"name": "Jane"}
)

# Update or create — updates if exists, creates if not
author, created = await Author.objects(session).update_or_create(
    email="jane@example.com",
    defaults={"name": "Jane Doe"}
)

# Bulk create — pass model instances, not dicts
authors = [Author(name=f"Author {i}", email=f"a{i}@example.com") for i in range(10)]
await Author.objects(session).bulk_create(authors, refresh=True)

# Delete all matching rows — returns the count of deleted rows
deleted = await Post.objects(session).delete_all(author_id=1)
```

`get_or_create` and `update_or_create` handle race conditions using savepoints. If another transaction creates the same row concurrently, the savepoint rolls back (not the full transaction) and the existing row is returned.

### Instance methods

```python
# Save an instance (add + flush + refresh)
post = Post(title="Hello", author_id=1)
await post.save(session)

# Update specific fields
await post.update(session, title="Updated Title")

# Delete
await post.delete(session)
```

---

## Generating Pydantic Schemas

`get_schema()` inspects your model's columns and generates a Pydantic `BaseModel` at runtime. This avoids duplicating field definitions between SQLAlchemy and Pydantic.

```python
# Full schema (all columns)
AuthorRead = Author.get_schema()

# Exclude fields (e.g., for creation where id is auto-generated)
AuthorCreate = Author.get_schema(exclude={"id", "created_at", "updated_at"})
```

The generated schema:
- Maps SQLAlchemy column types to Python types
- Makes nullable columns `Optional` with a default of `None`
- Adds `max_length` constraints for string columns
- Uses `from_attributes=True` so you can pass ORM instances directly to FastAPI responses

When `get_schema()` doesn't fit your use case (custom validation, nested schemas, computed fields), write a regular Pydantic schema instead.

---

## Sessions

### In FastAPI endpoints

Use `get_async_session` as a dependency. It yields an `AsyncSession`, commits on success, and rolls back on exception. You never call `commit()` or `rollback()` yourself.

```python
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from djast.database import get_async_session
from myapp.models import Author

router = APIRouter()

@router.post("/authors")
async def create_author(
    data: AuthorCreate,
    session: AsyncSession = Depends(get_async_session)
):
    return await Author.objects(session).create(**data.model_dump())
```

### In scripts or tests

Use `async_session_factory` directly. You are responsible for committing.

```python
from djast.database import async_session_factory

async with async_session_factory() as session:
    author = await Author.objects(session).create(name="Jane", email="jane@example.com")
    await session.commit()
```

---

## Using SQLAlchemy directly

The manager covers common operations. For complex queries (joins, subqueries, aggregations), use SQLAlchemy directly — you're never locked in.

```python
from sqlalchemy import select

# Custom query
stmt = select(Post).where(Post.author_id == 1).order_by(Post.created_at.desc())
result = await session.scalars(stmt)
posts = result.all()

# Get by primary key
author = await session.get(Author, 1)
```

---

## Database Configuration

The database engine is configured in `djast/settings.py` via the `DATABASES` setting, read from environment variables. **A generated project ships with PostgreSQL configured in `dev.env`** — the same engine production runs, so you develop against the database you deploy on.

The settings defaults fall back to a local SQLite file, which is what you get if no environment is loaded at all. To use SQLite deliberately, set `DB_ENGINE="sqlite"` in `dev.env`. To point at a different PostgreSQL:

```bash
DB_ENGINE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mydb
DB_USER=myuser
DB_PASSWORD=mypassword
```

The engine is built once at startup in `djast/database.py`. SQLite uses `aiosqlite`, PostgreSQL uses `asyncpg`. Both are fully async.

---

## Enum Columns

SQLAlchemy has two defaults here that surprise people coming from Django's `choices`. Both are worth knowing before you write the migration.

```python
import enum
from sqlalchemy import Enum

class Role(enum.StrEnum):
    CLIENT = "client"
    ADMIN = "admin"

class Membership(models.Model):
    __tablename__ = "orgs_membership"

    role: Mapped[Role] = mapped_column(
        Enum(
            Role,
            native_enum=False,
            length=16,
            create_constraint=True,                        # 1
            values_callable=lambda c: [m.value for m in c],  # 2
        ),
        default=Role.CLIENT,
    )
```

1. **`create_constraint` defaults to `False`** (since SQLAlchemy 1.4). Without it the column is a plain `VARCHAR` with **no** CHECK constraint — `makemigrations` reports success and the generated migration looks right. Verify with `SELECT conname FROM pg_constraint WHERE conrelid = 'orgs_membership'::regclass;` if you care.

2. **SQLAlchemy persists enum member *names*, not values.** A `StrEnum` whose values are lowercase stores `'CLIENT'`, not `'client'`. Anything reading the column outside the ORM — a report, an export, a raw query — will expect the values. `values_callable` fixes that.

The admin panel reads the enum directly: an `Enum` column renders as a select with the member values as options, no `field_options` needed. See [Admin Panel](admin.md).
