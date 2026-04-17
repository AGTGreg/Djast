# Changelog

## 17-04-26

 - **Refactored: Unify `auth_client` fixture**: The `auth_client` fixture (parametrized over `["django", "email"]`) now lives in `app/auth/tests/conftest.py` and yields `(client, mode, db_session)`. Removed byte-for-byte duplicates from `test_views.py`, `test_verification.py`, and `test_password_reset.py`. All 35 unpack sites in `test_views.py` updated from 2-tuple to 3-tuple (trailing `_db_session` is ignored where unused). Also consolidated `_signup_and_login` in `app/auth/tests/test_oauth.py` to import from `auth.tests.helpers` instead of the local hardcoded-user variant.
 - **Fixed: Rate-limit test isolation**: `redis_cleanup` in `app/auth/tests/conftest.py` and `app/admin/tests/conftest.py` now flushes both `REDIS_URL` (DB 1) and `RATE_LIMIT_REDIS_URL` (DB 2) so SlowAPI keys don't leak across tests. `rate_limit_client` in `app/auth/tests/test_rate_limit.py` now pins `AUTH_USER_MODEL_TYPE = "django"` and reloads `auth.forms`, which resolves `LoginForm` at import time — previously running the file in isolation failed with 422 because `LoginForm` stayed bound to the email form. The redundant manual Redis flush inside `rate_limit_client` was removed (autouse fixture handles it).
 - **Refactored: Decouple CSRF tests from main.app**: `test_csrf_protect_rejects_missing_header`, `test_csrf_protect_rejects_wrong_token`, and `test_csrf_protect_succeeds_with_correct_token` in `app/auth/tests/test_views.py` now run against a throwaway `FastAPI` app provided by a new local `csrf_client` fixture. Removes in-place mutation of `main.app.routes` and the redundant `[django]/[email]` parametrization (CSRF behavior is auth-mode-independent). `test_endpoints_without_csrf_dependency_are_not_checked` is unchanged — it still tests a real endpoint.
 - **Added: Wiring-regression tests for protected auth endpoints**: New parametrized test `test_protected_endpoint_rejects_missing_token` in `app/auth/tests/test_views.py` asserts 401 for every protected endpoint when called without an Authorization header. Driven by a new `PROTECTED_ENDPOINTS` tuple in `app/auth/tests/helpers.py` covering `POST /auth/change-password`, `/logout`, `/logout-all`, `/deactivate`, `GET /auth/users/me`, `POST /auth/resend-verification`, `DELETE /auth/oauth/{provider}/link`, `POST /auth/set-password`. Append to the tuple when adding new protected endpoints.
 - **Refactored: Centralise test fixtures and helpers**: Added `app/pyproject.toml` with pytest config (`asyncio_mode = "auto"`, `testpaths = ["."]`). Added `app/conftest.py` with shared `db_engine` and `db_session` fixtures. Added `app/auth/tests/conftest.py` and `app/admin/tests/conftest.py` with scoped `redis_cleanup` autouse fixture. Added `app/auth/tests/helpers.py` exporting `auth_prefix`, `strong_password`, `password_of_length`, `new_user_payload`, `signup_and_login`, `extract_access_token`, `patch_time_ahead`. Removed duplicated copies from `app/auth/tests/test_views.py`, `test_oauth.py`, `test_password_reset.py`, `test_verification.py`, `test_rate_limit.py`, `app/djast/tests/test_health.py`, and `app/admin/tests/test_views.py`.

## 28-03-26
 - **Added: Copier template**: Converted the project into a Copier template for project scaffolding. Users can run `copier copy` to generate a new project with parameterized project name, description, auth model type, and auto-generated secrets. Template uses `_templates_suffix: ".jinja"` to avoid conflicts with email templates. (`copier.yml`, `{{ project_pascal }}/`, `_generate_secrets.py`, `Makefile`)

## 24-03-26
 - **Added: Production deployment setup**: Self-contained Docker Compose production config (`docker-compose.prod.yml`) with Nginx reverse proxy (SSL termination, gzip, security headers, WebSocket/SSE proxying, static/media serving), PostgreSQL, Redis, Granian ASGI server, TaskIQ worker, and TaskIQ scheduler. All services include health checks, restart policies, and resource limits.
 - **Added: Granian ASGI server**: Replaced `fastapi run` (Uvicorn) with Granian for production. Best-in-class WebSocket/SSE performance, worker crash recovery with crash loop detection, memory-based and lifetime-based worker recycling, built-in backpressure. (`app/Dockerfile`, `app/requirements.txt`)
 - **Added: Health check endpoints**: `GET /health` (liveness — app is responding) and `GET /health/ready` (readiness — app + database + Redis reachable). Mounted at root level, outside `/api/v1` prefix and rate limiting. Returns 503 with per-service status when dependencies are down. (`djast/health.py`, `main.py`)
 - **Added: Granian proxy headers support**: `wrap_asgi_with_proxy_headers` applied in production mode so `X-Forwarded-For` / `X-Forwarded-Proto` from Nginx are trusted. Configurable via `PROXY_TRUSTED_HOSTS` setting. (`main.py`, `djast/settings.py`)
 - **Added: Nginx configuration**: Reverse proxy with SSL placeholder paths (`/etc/nginx/ssl/`), TLS 1.2+1.3, proxy headers, WebSocket upgrade support, SSE streaming (`proxy_buffering off`), static/media file serving with caching, gzip compression, security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). (`nginx/nginx.conf`, `nginx/Dockerfile`)
 - **Added: Production environment template** (`prod.env.example`): Documented template with PostgreSQL, Redis, SMTP email, CORS, proxy, and all security settings.
 - **Added: `.dockerignore`** (`app/.dockerignore`): Excludes `__pycache__`, test artifacts, and SQLite databases from production Docker image.
 - **Fixed: Dockerfile missing application code COPY**: Added `COPY . ${APP_HOME}` so production containers include app code without volume mounts. (`app/Dockerfile`)
 - **Changed: `asyncpg` driver enabled by default**: PostgreSQL driver uncommented in `requirements.txt` for production use.

## 21-03-26
 - **Fixed: `NameError` in `auth/forms.py` when using email auth mode**: `LoginForm` referenced `OAuth2EmailRequestForm` before its definition. (`auth/forms.py`)
 - **Fixed: `get_or_create` / `update_or_create` rolled back entire transaction on conflict**: Replaced `session.rollback()` with `session.begin_nested()` savepoints so only the conflicting operation is rolled back. (`djast/db/models.py`)
 - **Improved: Admin password schema validates against `PASSWORD_VALIDATION_REGEX`**: Uses `@field_validator` with `re.fullmatch` instead of `min_length=1`, returning 422 at the schema boundary. Stays in sync with custom regex in settings. (`admin/schemas.py`)
 - **Removed: `run_in_executor` helper**: Unused — no production code called it. TaskIQ natively supports CPU-bound work via `--use-process-pool` with sync task functions.

## 17-03-26 → 19-03-26 — Admin Panel
 - **Added: Admin panel** (`admin/`): Django-like admin with React frontend served by FastAPI. Self-contained — opt out by deleting `admin/` and removing the route from `urls.py`.
   - **Model registry**: `admin.site.register(Model, "App")` and `@site.register(Model)` decorator. SQLAlchemy column introspection for field types, editability, and required status. Supports `list_display`, `search_fields`, `field_options`, `exclude_fields`. Zero-config models default `list_display` to PK column(s).
   - **Generic CRUD API**: Schema-driven endpoints — `GET /admin/schema/`, list/detail/create/update/delete per model, bulk delete (capped at 500), admin password change for `AbstractBaseUser` subclasses. All endpoints (except `/admin/config/`) require `is_staff` or `is_superuser`. Ordering validated against registered fields. LIKE wildcards escaped in search. `IntegrityError` returns generic 409.
   - **React frontend**: Login (adapts to django/email auth mode), sidebar from schema, paginated list with server-side search/sort, detail form with field-level rendering, admin password change, own password change via top-bar menu. Session restore via refresh cookie on reload. Empty numeric fields send `null` instead of `0`.
   - **Zero-config for cloners**: Built `dist/` committed to repo, served at `/admin/`. Works after `git clone` + `docker compose up`.
   - **PK-agnostic CRUD**: All CRUD uses `entry.pk_field_names` from mapper introspection — handles renamed PKs, non-`id` PKs, composite PKs.
   - **Column introspection**: Shared `ColumnMeta` dataclass and `Model.columns_meta()` classmethod — single source of column metadata for both `get_schema()` and admin `_introspect_fields()`.
 - **Added: `setup_app()` hook**: Auto-discovered app initialization. Define `setup_app(app: FastAPI)` in any app's `__init__.py` — called during `create_app()`. Admin uses this to self-mount.
 - **Added: `SPAStaticFiles` utility** (`djast/utils/staticfiles.py`): `StaticFiles` subclass with `index.html` fallback for SPA routing. Path-traversal safe.
 - **Added: `createsuperuser` command**: `python manage.py createsuperuser`. Prompts based on `AUTH_USER_MODEL_TYPE`. Validates password strength.
 - **Added: SPA documentation** (`docs/building_an_spa.md`).
 - **Improved: `authenticate_user` returns the User object**: Avoids redundant DB queries by callers needing user attributes.
 - **Refactored: Centralised `LoginForm` in `auth/forms.py`**: Single export for both `auth/views.py` and `admin/views.py`.
 - **Changed: `is_staff` and `is_superuser` moved to `AbstractBaseUser`**: Both user types now inherit these fields — no privilege hierarchy, both mean "has admin access".
 - **Security Fix: Admin login leaked user existence** — staff check now runs after credential validation.
 - **Security Fix: Admin password reset now revokes all refresh tokens** via `logout_user_all_devices()`.
 - **Security Fix: Admin user creation requires password** — prevents bypassing `create_user()` and password hashing.
 - **Security Fix: Path traversal in admin SPA** — replaced `FileResponse` with `StaticFiles`.

## 15-03-26
 - **Changed: CSRF protection switched to opt-in**: Endpoints using Bearer token auth (immune to CSRF) no longer need `@csrf_exempt`. Cookie-authenticated endpoints opt in via `Depends(csrf_protect)`. Removed `CSRF_ENABLED` setting. Configurable via `CSRF_COOKIE_NAME`, `CSRF_HEADER_NAME`, `CSRF_TOKEN_LENGTH`.

## 13-03-26 — CLI & ORM Improvements
 - **Improved: ORM**: `Manager.exists()` uses `SELECT EXISTS(...)` subquery. Type hints on `Model.objects()`.
 - **Improved: `makemigrations`**: Refactored rename detection into focused functions with `MigrationOperations` dataclass. Column rename heuristic — only prompts on exactly 1 drop + 1 add. Fixed `op.rename_table()` indentation bug. Removed dead Python <3.12 compat code.
 - **Improved: `migrate`**: Checks `migrations/` directory exists. Catches `CommandError` cleanly.
 - **Improved: `startapp`**: Validates Python identifiers. Scaffolds `tests/` directory (with async `test_views.py`) and `utils/` directory.
 - **Improved: `shell`**: Added `auto_session` context manager to namespace. Fixed model discovery to use `glob("*/models.py")`.
 - **Improved: `manage.py`**: Displays command descriptions from module docstrings.
 - **Improved: Alembic env template**: Fixed model discovery bugs.

## 12-03-26 — Email Verification & Password Reset
 - **Added: Email verification**: Configurable via `EMAIL_VERIFICATION` setting (`"mandatory"`, `"optional"`, `"none"`). `EmailAddress` model (django-allauth pattern) tracks verification status independently of User. HMAC tokens (no DB storage) auto-invalidate on state change. Endpoints: `POST /verify-email`, `POST /resend-verification`. OAuth users auto-verified. 5-minute cooldown. Login gate in mandatory mode.
 - **Added: Password reset**: `POST /forgot-password` (anti-enumeration — always same response), `POST /reset-password` (HMAC token, password strength check, all sessions revoked). 5-minute cooldown.
 - **Added: HMAC token generator** (`auth/utils/tokens.py`): URL-safe, time-limited, self-invalidating tokens for verification and password reset. No DB storage.
 - **Added: Email templates**: `verify_email.html`, `reset_password.html` in `templates/email/`.
 - **Added: Settings**: `EMAIL_VERIFICATION`, `EMAIL_VERIFICATION_TOKEN_EXPIRE_SECONDS`, `PASSWORD_RESET_TOKEN_EXPIRE_SECONDS`, `EMAIL_COOLDOWN_SECONDS`, `EMAIL_VERIFICATION_URL`, `PASSWORD_RESET_URL`.
 - **Fixed: `change_password` returns 400 on weak password** (was 500).
 - **Fixed: OAuth errors no longer leak internal details**.

## 11-03-26 — Task Queue & Email Backend
 - **Added: Task queue (TaskIQ)**: Redis-backed `ListQueueBroker` with `SmartRetryMiddleware` (exponential backoff + jitter) and cron scheduling via `TaskiqScheduler`. Email dispatch via `EMAIL_USE_TASKIQ` setting (attachments not supported through TaskIQ). Worker and scheduler in `docker-compose.yaml`. `tasks.py` in `startapp` scaffold. CPU-bound work: use sync `def` tasks with `--use-process-pool` flag. See `docs/taskiq.md`.
 - **Added: Email backend**: Pluggable async email. `ConsoleEmailBackend` (dev default), `SMTPEmailBackend` (production, wraps fastapi-mail). Swappable via `EMAIL_BACKEND` setting. Jinja2 template rendering, file attachments, `send_email()` / `send_template_email()`.
 - **Security: OAuth authorization code exchange**: Tokens stored behind one-time Redis code (`OAUTH_CODE_TTL`). Frontend exchanges via `POST /auth/oauth/token`.
 - **Security: Auth hardening**: Credentials exception factory (no cross-request leakage), token blacklist clock-skew buffer, timing leak fix on `authenticate()`, OAuth callback input validation (`max_length`), username validation matching Django's `UnicodeUsernameValidator`, configurable lockout fail-open (`ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN`).

## 10-03-26 — OAuth & Auth Security
 - **Added: OAuth2 social login** (Google, GitHub): Toggled via `OAUTH_GOOGLE_ENABLED` / `OAUTH_GITHUB_ENABLED` (disabled by default). Endpoints: `GET /auth/oauth/{provider}/authorize`, `GET /auth/oauth/{provider}/callback`, `POST /auth/oauth/token`, `DELETE /auth/oauth/{provider}/link`, `POST /auth/set-password`. `OAuthAccount` model links social identities to users (auto-links by email). OAuth-only users can set password later (`OAUTH_ALLOW_SET_PASSWORD`). Authlib for OIDC. Redis-backed state tokens.
 - **Added: `expires_in` in token responses** per RFC 6749 §5.1.
 - **Security: Refresh token cookie path** restricted to `{APP_PREFIX}/auth`.
 - **Security: Per-account brute force protection**: Redis-backed counter (`ACCOUNT_LOGIN_MAX_ATTEMPTS`, `ACCOUNT_LOGIN_LOCKOUT_SECONDS`). Fails open if Redis unavailable.
 - **Security: Password regex expanded** to all printable ASCII. `max_length=100` enforced at schema boundary.
 - **Security: `CORS_ALLOW_CREDENTIALS`** defaults to `True` in DEBUG, `False` in production.
 - **Changed: `/revoke` → `/logout`, `/revoke-all` → `/logout-all`**, `/users/me/` → `/users/me`.
 - **Refactored: Auth internals**: Extracted `set_refresh_cookie()`, `get_current_user` dependency, `_encode_replacement_jwt()`, `normalize_email()` to `AbstractBaseUser`. Replaced N+1 token revocation with bulk SQL update. Return type annotations on all auth views.

## 08-01-26
 - **Added: FastAPI + SQLAlchemy async boilerplate** with Django-style layout.
 - **Added: `Model` / `Manager` ORM layer**, `TimestampMixin`, pluggable engine (SQLite / PostgreSQL).
 - **Added: Pydantic `BaseSettings`**, CLI with `startapp` / `makemigrations` / `migrate` / `shell`.
 - **Added: Central `APIRouter` aggregation**, `get_async_session` dependency with auto-commit/rollback.
 - **Added: Switchable user models** via `AUTH_USER_MODEL_TYPE` (`"django"` / `"email"`).
 - **Added: Django-compatible async `pbkdf2_sha256` password hashing**.
 - **Added: JWT access + refresh tokens** with rotation, replay detection, and grace period.
 - **Added: Redis-backed token blacklist** with configurable fallback.
 - **Added: Auth endpoints**: signup, login, refresh, logout (single/all devices), change password, deactivate, user info.
 - **Added: Rate limiting** (SlowAPI + Redis) on all auth endpoints.
 - **Added: Comprehensive test suite** (65 tests).
