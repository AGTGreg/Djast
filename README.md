# Djast

> **FastAPI for Django developers.**

## Overview

**Djast** is a web framework that brings Django's developer experience — structured apps, a `manage.py` CLI, and centralized settings — to FastAPI's async performance.

It does **not** abstract away FastAPI or SQLAlchemy. You work with the same tools you already know, just with a layer of Django-style convenience on top. If you're a Django developer who wants speed, or a FastAPI developer who wants structure, Djast is for you.

## Features

- **Django-style CLI** — `startapp`, `makemigrations`, `migrate`, `shell`, `createsuperuser`
- **Django-style project layout** — Modular apps with `models.py`, `views.py`, `schemas.py`, `utils/`, `tests/`
- **Django-style ORM** — `Model.objects(session).get()`, `.filter()`, `.create()` and more
- **[Admin Panel](docs/admin.md)** — Model registry, CRUD API, React frontend. Register models and get a working admin at `/admin/`
- **[Auth](docs/auth.md)** — Django-compatible user model with `pbkdf2_sha256` hashing, JWT access/refresh tokens, signup, login, email verification, password reset, CSRF protection, brute-force lockout. Works with existing Django databases out of the box
- **[OAuth2](docs/auth.md)** — Optional Google & GitHub social login, disabled by default
- **[Email](docs/email.md)** — Pluggable async backend (console for dev, SMTP for production) with Jinja2 templates
- **[Task Queue](docs/taskiq.md)** — Redis-backed async tasks with retries, cron scheduling, and optional email dispatch
- **[Security](docs/security.md)** — Rate limiting, token blacklisting, brute-force protection, CSRF double-submit cookies
- **Async SQLAlchemy** — SQLite for dev, PostgreSQL for production. Switch with an env var
- **Dockerized** — `docker-compose.yaml` with app, Redis, TaskIQ worker, and scheduler
- **[Production-Ready](docs/production-deployment.md)** — `docker-compose.prod.yml` with Granian ASGI server, Nginx (SSL, static files, WebSocket/SSE), PostgreSQL, Redis, health checks, and resource limits

## Quick Start

### Create a new project

```bash
pip install copier
copier copy gh:AGTGreg/Djast ./my-project --trust
```

You'll be prompted for:

| Prompt | Description | Default |
|--------|-------------|---------|
| `project_name` | Human-readable project name | `My Project` |
| `project_description` | Short description | `A web application built with Djast` |
| `author_name` | Author name | — |
| `auth_user_model` | `django` (username) or `email` (email-based auth) | `django` |

Copier generates a project folder (PascalCase) with a unique `SECRET_KEY` and `DB_PASSWORD` in `dev.env`, ready to run:

```bash
cd my-project/MyProject
docker compose up --build
```

### Learn more

[Follow the quick start guide](quickstart.md) to build a working API in 10 minutes.

## Project Structure

```text
app/
├── djast/              # Core framework (settings, urls, db, commands)
├── admin/              # Built-in admin panel
├── auth/               # Built-in auth module
├── templates/          # Email and code generation templates
├── migrations/         # Alembic migrations
├── myapp/              # Your apps go here (created via manage.py startapp)
├── main.py             # ASGI entry point
├── manage.py           # CLI
└── requirements.txt    # Dependencies
```

## CLI

All commands run from the `app/` directory:

```bash
python manage.py startapp <name>       # Scaffold a new app
python manage.py makemigrations [msg]  # Generate a migration (detects renames, warns on drops)
python manage.py migrate               # Apply migrations
python manage.py shell                 # IPython shell with models, session, and settings loaded
python manage.py createsuperuser       # Create an admin user
```

## Models

Define models by inheriting from `models.Model`. You get an auto-generated table name, integer PK, async attributes, a Django-style manager, and `get_schema()` for instant Pydantic models.

```python
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from djast.db import models

class Item(models.Model):
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(server_default="false", nullable=False)
```

Query with the `objects` manager:

```python
item = await Item.objects(session).get(id=1)
items = await Item.objects(session).filter(is_active=True)
new_item = await Item.objects(session).create(name="Laptop")
```

Generate Pydantic schemas from models:

```python
ItemRead = Item.get_schema()
ItemCreate = Item.get_schema(exclude={"id", "created_at", "updated_at"})
```

For more details, see [Models documentation](docs/models.md).

## Settings

All configuration lives in `djast/settings.py` using Pydantic `BaseSettings`. Key settings:

| Setting | Description |
|---------|-------------|
| `PROJECT_NAME` | API name (shown in docs) |
| `DEBUG` | Debug mode toggle |
| `DATABASES` | Database config (defaults to SQLite) |
| `AUTH_USER_MODEL_TYPE` | `"django"` (username) or `"email"` (email-based auth) |
| `CORS_ALLOW_ORIGINS` | Allowed CORS origins |
| `EMAIL_BACKEND` | `"console"` (dev) or SMTP path (production) |
| `SECRET_KEY` | Used for JWT and token signing |

See `djast/settings.py` for the full list.

## Documentation

- [Quick Start](quickstart.md)
- [Models](docs/models.md)
- [Auth](docs/auth.md)
- [Admin Panel](docs/admin.md)
- [Email](docs/email.md)
- [Task Queue](docs/taskiq.md)
- [Security](docs/security.md)
- [Building an SPA](docs/building_an_spa.md)
- [Production Deployment](docs/production-deployment.md)

## Roadmap

- [x] Auth — JWT, email verification, password reset, OAuth2
- [x] Email — Pluggable async backend with templates
- [x] Task Queue — Redis-backed with retries and cron scheduling
- [x] Admin Panel — Model registry, CRUD API, React frontend
- [x] Production configuration
- [x] Better documentation
- [x] Copier template for project scaffolding
