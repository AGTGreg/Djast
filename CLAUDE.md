# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Djast is a FastAPI + SQLAlchemy framework that provides Django-like developer experience with FastAPI's async performance. Python 3.12, SQLAlchemy 2.0 async ORM, Pydantic 2.0 settings, Alembic migrations.

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

# TaskIQ (task queue)
taskiq worker djast.taskiq:broker djast.tasks <app>.tasks --reload   # Start worker
taskiq scheduler djast.scheduler:scheduler --reload                  # Start cron scheduler

# Docker (includes app, redis, taskiq worker, taskiq scheduler)
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
│   │   ├── taskiq.py           # Taskiq broker configuration
│   │   ├── scheduler.py        # Taskiq cron scheduler
│   │   ├── tasks.py            # Framework-level async tasks (e.g., send_email task)
│   │   ├── db/                 # ORM layer (Base, Model, Manager, engine)
│   │   ├── commands/           # CLI commands (startapp, makemigrations, migrate, shell)
│   │   ├── utils/              # Framework-wide utilities
│   │   │   ├── email.py        # Email API (send_email, send_template_email, EmailMessage)
│   │   │   ├── email_backends/ # Pluggable backends (console, SMTP)
│   │   │   └── tasks.py        # run_in_executor for CPU-bound work in async tasks
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
- **Pluggable email backend**: Django-inspired pattern — swap email delivery by changing `EMAIL_BACKEND` setting. Custom backends subclass `BaseEmailBackend` and implement `send_message()`. Optional TaskIQ integration for async dispatch.
- **Async task queue (TaskIQ)**: Redis-backed broker with retry middleware. Tasks defined per-app in `tasks.py`. Cron scheduling via decorator. Worker and scheduler run as separate Docker services. Tests use `InMemoryBroker` — no Redis needed.
- **Optional OAuth**: Social login (Google, GitHub) disabled by default. Enabled per-provider via settings. Authorization code exchange pattern keeps tokens server-side. `OAuthAccount` model links multiple providers to one user.

## Architecture

### Core Framework (`app/djast/`)

- **settings.py** — Centralized Pydantic `BaseSettings` config. All env vars, auth settings, CORS, rate limits defined here. Instantiated as singleton `settings`.
- **urls.py** — APIRouter aggregation point. All app routers are included here.
- **database.py** — AsyncSession factory and `get_async_session` FastAPI dependency (auto-commits on success).
- **rate_limit.py** — SlowAPI rate limiter with Redis storage.
- **db/models.py** — ORM base classes: `Base` (auto-tablename, AsyncAttrs), `Model` (adds int PK, Manager, instance save/update/delete), `TimestampMixin`, `Manager` (Django-style async query API).
- **db/engine.py** — `build_engine()` factory supporting SQLite and PostgreSQL.
- **taskiq.py** — Taskiq broker setup with Redis backend, `SmartRetryMiddleware` (exponential backoff + jitter), and `ListQueueBroker`. Import broker from here for task definitions.
- **scheduler.py** — `TaskiqScheduler` for cron-based task scheduling. Runs as a separate process.
- **tasks.py** — Framework-level tasks (e.g., `send_email_task`). App-specific tasks go in `<app>/tasks.py`.
- **utils/email.py** — Async email API: `send_email()`, `send_template_email()`, `EmailMessage`, `BaseEmailBackend`, `get_email_backend()`. Pluggable backends via `EMAIL_BACKEND` setting. Jinja2 template rendering for HTML emails. Optionally routes through TaskIQ when `EMAIL_USE_TASKIQ=True`.
- **utils/email_backends/** — `ConsoleEmailBackend` (dev default, prints to stdout), `SMTPEmailBackend` (production, wraps fastapi-mail). Custom backends subclass `BaseEmailBackend`.
- **utils/tasks.py** — `run_in_executor()` for running CPU-bound sync code inside async tasks.
- **commands/** — Custom CLI commands loaded dynamically by `manage.py`.
- **templates/module/** — Template files used by `startapp` to scaffold new apps (includes `tasks.py` template).

### Auth Module (`app/auth/`)

- **models.py** — User model hierarchy: `AbstractBaseUser` → `AbstractDjangoUser`/`AbstractEmailUser` → `User`. `RefreshToken` model with rotation and blacklisting. `OAuthAccount` model linking social identities to users. `AUTH_USER_MODEL_TYPE` setting switches between username ("django") and email-based auth.
- **views.py** — Auth endpoints: signup, login, token refresh (with rotation + replay detection), logout, change password, user info. OAuth endpoints: `GET /auth/oauth/{provider}/authorize`, `GET /auth/oauth/{provider}/callback`, `POST /auth/oauth/token`, `DELETE /auth/oauth/{provider}/link`, `POST /auth/set-password`.
- **utils/auth_backend.py** — JWT generation, user creation, authentication logic.
- **utils/hashers.py** — Django-compatible async pbkdf2_sha256 password hashing.
- **utils/oauth.py** — OAuth2 social login (Google, GitHub). Uses Authlib for OIDC. Redis-backed state tokens for CSRF. Authorization code exchange pattern (tokens stored behind one-time code, not exposed in redirect URL). Toggled via `OAUTH_GOOGLE_ENABLED` / `OAUTH_GITHUB_ENABLED` (disabled by default).

### Key Patterns

- **Manager pattern**: `Model.objects(session).get()`, `.filter()`, `.create()`, `.get_or_create()`, etc. Manager flushes but does NOT commit — the session dependency auto-commits.
- **App factory**: `create_app()` in `main.py` sets up middleware (CORS, rate limiting) and mounts the router with `APP_PREFIX`.
- **Auto-tablename**: Table names derived from module + class name in snake_case (e.g., `auth_user`).
- **New apps**: Created via `python manage.py startapp <name>`, then register the router in `djast/urls.py`.
- **Task queue**: Define tasks in `<app>/tasks.py` using `@broker.task` decorator (import broker from `djast.taskiq`). Enqueue with `.kiq()`. Cron schedules via `schedule=[{"cron": "..."}]` on the decorator. Tests use `InMemoryBroker` via `_reset_broker()`.
- **Email sending**: Use `send_email()` / `send_template_email()` from `djast.utils.email`. Backends are swappable via `EMAIL_BACKEND` setting. When `EMAIL_USE_TASKIQ=True`, emails are dispatched async via task queue (attachments not supported in this mode).
- **CSRF protection**: Opt-in double-submit cookie pattern. Not enforced globally (Bearer token auth is immune to CSRF). Endpoints authenticating via cookies can add `Depends(csrf_protect)`. Login/refresh set `csrf_token` cookie; protected endpoints require matching `X-CSRF-Token` header.

## Coding Guidelines

This is a framework — all code must be async, performant, secure, easy for developers to use, and clean.

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
- When adding new features, follow the existing module structure (`models.py`, `views.py`, `schemas.py`, `utils/`). Consistency across apps makes the framework easy to learn.

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
- TaskIQ tests use `InMemoryBroker` via `_reset_broker()` fixture — no Redis required. Call task functions directly (not `.kiq()`) for unit tests; mock `.kiq()` to test view integration.
- Every new endpoint needs at least: a success case, an auth/permission failure case, and an invalid input case.
- Every new utility or model method needs unit tests covering expected behaviour and edge cases.

## Dependencies

Defined in `app/requirements.txt` (no pyproject.toml). Key: FastAPI, SQLAlchemy[asyncio], Pydantic-settings, Alembic, PyJWT, SlowAPI, Redis, aiosqlite, Authlib (OAuth), fastapi-mail (SMTP email), Taskiq + taskiq-redis + taskiq-aiohttp (task queue), Jinja2 (email templates).
