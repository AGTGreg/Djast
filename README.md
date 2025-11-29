# Djast
> **FastAPI for Django developers.**

## 🚀 Overview

**Djast** is a FastAPI + SQLAlchemy boilerplate designed to bridge the gap between Django and FastAPI. It brings the familiar developer experience of Django: structured apps, a `manage.py` CLI, and centralized configuration to the high-performance, asynchronous world of FastAPI.

### The Philosophy:
Djast does **not** abstract FastAPI and SQLAlchemy or make them heavier or more complex. It doesn't hide the underlying logic behind thick abstraction layers. It is designed for people who want to use a well established and battle testsed stack (FastAPI and SQLAlchemy) **sprinkled with a little bit of "Django magic"**.

Whether you are a Django developer looking for speed, or a FastAPI developer looking for structure, you will appreciate Djast.

## ✨ Features

- **Django-style CLI (`manage.py`)**:
  - `python manage.py startapp <name>`: Generate new modular apps instantly.
  - `python manage.py makemigrations`: Auto-generate Alembic migrations with renaming and drop_table/drop_column detection.
  - `python manage.py migrate`: Apply database migrations.
  - `python manage.py shell`: Interactive shell with app context and session pre-loaded.
- **Familiar Structure**: Organized like a Django project with `djast/settings.py`, `djast/urls.py`, and modular apps.
- **Pure Performance**: Maintains the raw speed of FastAPI and async SQLAlchemy without overhead.
- **Database Ready**: Async SQLAlchemy setup (SQLIte, Postgres) with Alembic for migrations included out of the box.
- **Dockerized**: Includes `Dockerfile` and `docker-compose.yaml` for easy deployment.


## 🛠️ Quick Start

[Follow the quick start guide here](quickstart.md).

## 📂 Project Structure

```text
app/
├── djast/              # Djast configuration (settings, urls, db, commands)
├── myapp/              # Your module here. Created via `manage.py startapp myapp`
├── main.py             # ASGI entry point
├── manage.py           # CLI utility
└── requirements.txt    # Dependencies
```

## ⚙️ Settings

Configuration is managed in `djast/settings.py` using Pydantic's `BaseSettings`.

### Key Settings

-   **`PROJECT_NAME`**: The name of your API (displayed in docs).
-   **`DEBUG`**: Toggles debug mode.
-   **`DATABASES`**: Dictionary configuration for databases. Defaults to SQLite.
-   **`CORS_ALLOW_ORIGINS`**: List of allowed origins for CORS.
-   **`TIME_ZONE`**: For timezone aware datetimes from `timezone` util.


## 🗄️ Database Models

Djast provides a robust base for your SQLAlchemy models, designed to reduce boilerplate and provide a familiar API.

```python
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from djast.db import models

class Item(models.Model):
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    notes: Mapped[str | None] = mapped_column(String(512), default=None)
    is_active: Mapped[bool] = mapped_column(server_default="false", nullable=False)

    def __repr__(self) -> str:
        return f"<Item id={self.id} name={self.name!r}>"
```

### Why inherit from `models.Model`?

Inheriting from `djast.db.models.Model` is the recommended default. You get:
1.  **Automatic Table Naming**: Tables are automatically named based on the app module and class name (e.g., `myapp_item` for an `Item` model in the `myapp` app).
2.  **Async Attributes**: Includes `AsyncAttrs` support, allowing you to await lazy-loaded relationships.
3.  **Automatic Primary Key**: Adds a standard integer `id` primary key column.
4.  **Django-style Manager**: Access to the `objects` interface for queries for common Django-style queries.
5.  **Schema Generation**: Access to `get_schema` for instant Pydantic models.

### Key Features

#### `objects` Manager
The `objects` class method returns a manager instance bound to your async session, providing a Django-like API for common database operations.

```python
# In your view/api
item = await Item.objects(session).get(id=1)  # Get by any field(s)
item = await Item.objects(session).get(name="Greg", is_active=True)  # Multiple filters
items = await Item.objects(session).filter(is_active=True)
new_item = await Item.objects(session).create(name="Greg")
new_item, created = await Item.objects(session).update_or_create(id=1, defaults={"name": "Greg"})
```

#### `get_schema`
Inspects your SQLAlchemy model and generates a Pydantic `BaseModel` on the fly for your CRUD needs.

```python
# Generate a full schema
ItemRead = Item.get_schema()

# Generate a schema excluding specific fields (e.g., for creation)
ItemCreate = Item.get_schema(exclude={"id", "created_at", "updated_at"})
```


## 🔄 Migrations

Djast wraps Alembic to provide a Django-like migration workflow.

### Making Migrations

To generate a new migration based on changes to your models:

```bash
python manage.py makemigrations [message (optional)]
```

**What it does:**
1.  **Interactive Renames**: If it detects a table or column drop paired with a creation, it will ask if you renamed it. If yes, it automatically generates the correct `rename_table` or `alter_column` operations instead of dropping data.
2.  **Safety Checks**: Warns you if a migration contains dangerous operations (like dropping a table or column) that could cause data loss, giving you a chance to abort.
3.  **Auto-init**: If Alembic is not set up, it initializes it automatically on the first run.
4.  Your migrations live in `migrations/`

### Applying Migrations

To apply pending migrations to your database:

```bash
python manage.py migrate
```

**What it does:**
-   Runs `alembic upgrade head`, applying all unapplied migrations to bring your database schema up to date.


## 🐚 Interactive Shell

Debug and interact with your application data using the IPython shell.

```bash
python manage.py shell
```

**Features:**
-   **Auto-Imports**: Automatically imports all your models, `settings`, and the database `engine`.
-   **Async Ready**: Pre-configured with `ipython` and `%autoawait`, so you can run `await` commands directly.
-   **Pre-loaded Session**: A fresh async `session` is available immediately for queries.

**Example Usage:**

```python
# No need to import User!
# Fetch all users
items = await myapp.Item.objects(session).all()

# Create a new user
new_item = await myapp.Item.objects(session).create(name="admin")

# Commit changes
await session.commit()
```


## 🗺️ Roadmap

Planned features for future releases:

- [ ] **Better Test Coverage** - Comprehensive test suite for all core components and utilities
- [ ] **Better documentation** - Cover all modules and utilites.
- [ ] **Auth App** - Pre-built authentication module with JWT tokens, user registration, login, and password management
- [ ] **Basic Admin** - Simple admin interface for managing database records (inspired by Django Admin)
- [ ] **Cookiecutter Templates** - Project and micro-service initialization templates with cookiecutter for quick scaffolding
