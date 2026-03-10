# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Djast is a FastAPI + SQLAlchemy boilerplate that provides Django-like developer experience with FastAPI's async performance. Python 3.12, SQLAlchemy 2.0 async ORM, Pydantic 2.0 settings, Alembic migrations.

## Commands

All commands run from the `app/` directory:

```bash
# Dev server
fastapi dev main.py

# Management commands
python manage.py startapp <name>       # Scaffold a new app module
python manage.py makemigrations [msg]  # Generate Alembic migration
python manage.py migrate               # Apply migrations
python manage.py shell                 # IPython shell with auto-imports

# Tests
pytest                                 # All tests
pytest auth/tests/test_views.py -v     # Single test file
pytest auth/tests/ -v                  # All tests in a module

# Docker
docker compose up --build
```

## Project Structure & Design Choices

```
Djast/
├── app/                        # All application code lives here
│   ├── main.py                 # ASGI entry point — app factory
│   ├── manage.py               # Django-style CLI (startapp, migrate, shell)
│   ├── djast/                  # Core framework — shared infrastructure
│   │   ├── settings.py         # Single source of truth for all configuration
│   │   ├── urls.py             # Central router — all app routers registered here
│   │   ├── database.py         # Async session factory & dependency
│   │   ├── rate_limit.py       # SlowAPI + Redis rate limiter
│   │   ├── db/                 # ORM layer (Base, Model, Manager, engine)
│   │   ├── commands/           # CLI commands (startapp, makemigrations, migrate, shell)
│   │   ├── utils/              # Framework-wide utilities
│   │   └── templates/          # Code generation templates for startapp
│   ├── auth/                   # Auth module (built-in app)
│   │   ├── models.py
│   │   ├── views.py
│   │   ├── schemas.py
│   │   ├── utils/
│   │   └── tests/
│   └── <your_app>/             # New apps follow the same structure
├── docker-compose.yaml         # App + Redis services
├── dev.env                     # Development environment variables
└── docs/                       # Documentation
```

### Design Choices

- **Django-style project layout**: Each app is a self-contained module with `models.py`, `views.py`, `schemas.py`, `utils/`, and `tests/`. The `djast/` directory acts like Django's project config — it owns settings, URL routing, and shared infrastructure. New apps are scaffolded with `python manage.py startapp <name>` and plugged in by registering their router in `djast/urls.py`.
- **Async-first**: Everything is async — the session factory, the ORM layer, password hashing, all endpoints. SQLAlchemy `AsyncAttrs` and `async_sessionmaker` are used throughout. No sync database access anywhere.
- **Session lifecycle via dependency injection**: `get_async_session` is a FastAPI dependency that yields an `AsyncSession`, auto-commits on success, and rolls back on exception. Views never manage transactions directly.
- **Manager as the query interface**: `Model.objects(session)` provides a Django-like API for common queries. The Manager flushes but does not commit — that's the session dependency's job. This keeps query logic decoupled from transaction boundaries.
- **Pluggable database engine**: `build_engine()` reads from `settings.DATABASES` and constructs the right async engine (SQLite for dev, PostgreSQL for production). Switching databases requires only environment variable changes.
- **Dynamic CLI**: `manage.py` discovers commands from `djast/commands/` at runtime via `pkgutil`. Each command module exposes a `run()` function. Adding a new command means dropping a new file in that directory.

## Architecture

### Core Framework (`app/djast/`)

- **settings.py** — Centralized Pydantic `BaseSettings` config. All env vars, auth settings, CORS, rate limits defined here. Instantiated as singleton `settings`.
- **urls.py** — APIRouter aggregation point. All app routers are included here.
- **database.py** — AsyncSession factory and `get_async_session` FastAPI dependency (auto-commits on success).
- **rate_limit.py** — SlowAPI rate limiter with Redis storage.
- **db/models.py** — ORM base classes: `Base` (auto-tablename, AsyncAttrs), `Model` (adds int PK, Manager, instance save/update/delete), `TimestampMixin`, `Manager` (Django-style async query API).
- **db/engine.py** — `build_engine()` factory supporting SQLite and PostgreSQL.
- **commands/** — Custom CLI commands loaded dynamically by `manage.py`.
- **templates/module/** — Template files used by `startapp` to scaffold new apps.

### Auth Module (`app/auth/`)

- **models.py** — User model hierarchy: `AbstractBaseUser` → `AbstractDjangoUser`/`AbstractEmailUser` → `User`. `RefreshToken` model with rotation and blacklisting. `AUTH_USER_MODEL_TYPE` setting switches between username ("django") and email-based auth.
- **views.py** — Auth endpoints: signup, login, token refresh (with rotation + replay detection), logout, change password, user info.
- **utils/auth_backend.py** — JWT generation, user creation, authentication logic.
- **utils/hashers.py** — Django-compatible async pbkdf2_sha256 password hashing.

### Key Patterns

- **Manager pattern**: `Model.objects(session).get()`, `.filter()`, `.create()`, `.get_or_create()`, etc. Manager flushes but does NOT commit — the session dependency auto-commits.
- **App factory**: `create_app()` in `main.py` sets up middleware (CORS, rate limiting) and mounts the router with `APP_PREFIX`.
- **Auto-tablename**: Table names derived from module + class name in snake_case (e.g., `auth_user`).
- **New apps**: Created via `python manage.py startapp <name>`, then register the router in `djast/urls.py`.

## Coding Guidelines

This is a boilerplate — all code must be async, performant, secure, easy for developers to use, and clean.

### DRY (Don't Repeat Yourself)

- Extract repeated logic into reusable functions or classes. If you write similar code more than once, abstract it.
- Prefer the Manager pattern (`Model.objects(session)`) for database queries. When a use case doesn't fit the Manager (e.g., complex joins, performance-critical raw queries), either extend the Manager with a new method or use SQLAlchemy directly — whichever is more maintainable, performant, and secure.
- Shared logic belongs in `utils/` within the relevant app module. If logic is used across multiple apps, place it in `djast/utils/`.
- Reuse `TimestampMixin` for any model needing created/updated timestamps. Prefer `Model.get_schema()` to auto-generate Pydantic schemas from models. When `get_schema()` doesn't fit the use case (custom validation, nested schemas, computed fields), either extend `get_schema()` or write a manual Pydantic schema — whichever better serves maintainability, performance, and security.
- Centralise configuration in `djast/settings.py` — never hardcode values that could change per environment.
- Reuse FastAPI dependencies for cross-cutting concerns (auth, sessions, rate limiting) instead of duplicating checks in each view.

### Separation of Concerns

- Each module, class, and function should have one clear responsibility. If you can't describe what it does in one sentence, it's doing too much.
- **models.py** — Data layer only: SQLAlchemy models, relationships, model-level validation. No HTTP or request logic.
- **views.py** — Thin request handlers: parse input, call business logic, return response. Keep complex logic out of views.
- **schemas.py** — Pydantic models for request/response serialization. No business logic or database access.
- **utils/** — Business logic, helpers, and integrations. This is where domain logic lives when it doesn't belong in models or views.
- Keep database session management in FastAPI dependencies (`get_async_session`), not manually in views or utils.
- Don't mix transport concerns (HTTP status codes, request parsing) with domain logic. A utility function should not know it's being called from an endpoint.

### Performance & Async

- Always use `async def` for endpoints and any function that touches the database or I/O.
- Never call blocking/sync I/O inside async functions — it blocks the event loop. Use async libraries or run sync code in an executor.
- Prefer bulk operations (`bulk_create`, batch queries) over loops with individual DB calls.
- Use `await` on lazy-loaded relationships (`AsyncAttrs`) — never trigger implicit sync loads.

### Security

- Validate and sanitise all user input at the boundary (Pydantic schemas, FastAPI dependencies).
- Never expose internal errors, stack traces, or database details in API responses.
- Use parameterised queries (SQLAlchemy handles this) — never interpolate user input into SQL.
- Apply rate limiting to all public-facing endpoints, especially auth-related ones.
- Keep secrets in environment variables, never in code. Reference them through `settings`.

### Maintainability & Clean Code

- Type-hint all function signatures (parameters and return types).
- Use `async`/`await` consistently — never mix sync DB calls with async session code.
- Prefer early returns over deeply nested conditionals.
- Name variables and functions descriptively — avoid single-letter names outside of comprehensions.
- Keep functions focused on a single responsibility. If a function does multiple unrelated things, split it.
- Write code for the next developer: favour readability over cleverness. If a pattern needs explanation, add a brief comment on *why*, not *what*.
- When adding new features, follow the existing module structure (`models.py`, `views.py`, `schemas.py`, `utils/`). Consistency across apps makes the boilerplate easy to learn.

## Development Workflow

### Before Starting

- Consult `CHANGELOG.md` in the project root to understand what has already been built and changed. This avoids duplicating work or conflicting with recent changes.
- Read existing code in the affected modules before modifying them.

### Build & Validate

1. **Write tests first or alongside the feature** — every new endpoint, utility, or model method needs test coverage. Tests go in `<app>/tests/`.
2. **Run the full test suite after every change** — not just the tests for the code you touched. Other modules may depend on what you changed.
   ```bash
   cd app && pytest -v
   ```
3. **Generate and apply migrations** if models were added or modified:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```
4. **Start the dev server (if not allready running) and verify** the feature works end-to-end — endpoints return correct responses, error cases are handled, auth flows work.
5. **Run linting** to catch style issues

### After Completing

- Add an entry to `CHANGELOG.md` describing what was added, changed, or fixed.
- Confirm the full test suite still passes before considering the work done.

## Testing

- pytest + pytest-asyncio with in-memory SQLite for isolation.
- Tests live in `<app>/tests/` directories (e.g., `auth/tests/`).
- Auth tests use `httpx.AsyncClient` for endpoint testing and `async_sessionmaker` fixtures.
- Every new endpoint needs at least: a success case, an auth/permission failure case, and an invalid input case.
- Every new utility or model method needs unit tests covering expected behaviour and edge cases.

## Dependencies

Defined in `app/requirements.txt` (no pyproject.toml). Key: FastAPI, SQLAlchemy[asyncio], Pydantic-settings, Alembic, PyJWT, SlowAPI, Redis, aiosqlite.
