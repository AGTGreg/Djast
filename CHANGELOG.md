# Changelog

## 17-03-26
 - **Security Fix: Admin login endpoint leaked user existence and staff status** (`admin/views.py`): The `/admin/login/` endpoint checked `is_staff` before calling `authenticate_user()`, causing non-staff users to receive 403 regardless of password correctness (leaking account existence) and bypassing the timing-attack protection built into the auth backend. Staff check now runs after credential validation.
 - **Security Fix: Admin create endpoint exposed internal error details** (`admin/views.py`): Bare `except Exception` on the create endpoint returned raw exception messages (including SQLAlchemy `IntegrityError` with table/column names) as 400 responses. Now catches `IntegrityError` specifically with a generic 409 message; unexpected errors propagate as 500.
 - **Fixed: Admin search treated `%` and `_` as SQL wildcards** (`admin/utils/crud.py`): The `ilike()` search did not escape LIKE pattern characters in user input. Searching for `%` matched all records; `_` matched any single character. Now escapes `%`, `_`, and `\` before wrapping in wildcards.
 - **Added: `list_display` support in admin schema** (`admin/utils/registry.py`, `admin/schemas.py`, `admin/frontend/`): `ModelAdmin.list_display` was accepted but never included in the schema output — the frontend showed all fields regardless. Now `get_schema()` includes `list_display` in the response and the frontend `ListScreen` filters columns accordingly. When `list_display` is `null`, all fields are shown (backwards compatible).
 - **Improved: `authenticate_user` returns the authenticated user** (`auth/utils/auth_backend.py`): Return type changed from `Tuple[str, str]` to `Tuple[str, str, User]`. The user object is already loaded during authentication — returning it avoids redundant database queries by callers that need user attributes (e.g., admin login checking `is_staff`). Both callers (`auth/views.py`, `admin/views.py`) updated.
 - **Fixed: Admin SPA tests broke on every frontend rebuild** (`admin/tests/test_spa.py`): JS and CSS asset tests hardcoded Vite content-hashed filenames (`index-CkeRXl7g.js`, `index-DA3DO9Tp.css`). Now globs `dist/assets/` at runtime for `*.js` and `*.css` files.
 - **Refactored: Centralised `LoginForm` in `auth/forms.py`**: Both `auth/views.py` and `admin/views.py` independently resolved the login form class based on `AUTH_USER_MODEL_TYPE`. Moved the resolution to `auth/forms.py` as a single `LoginForm` export. Both modules now import from one place — adding a new auth form type no longer requires updating admin separately.
 - **Added: `setup_app()` hook**: Auto-discovered app initialization hook. Define `setup_app(app: FastAPI)` in any app's `__init__.py` and it will be called during `create_app()`. No configuration needed — the app factory discovers hooks by scanning app directories. Useful for app-level setup like mounting static files or adding middleware.
 - **Added: `SPAStaticFiles` utility** (`djast/utils/staticfiles.py`): Reusable `StaticFiles` subclass that falls back to `index.html` for SPA client-side routing. Inherits all Starlette `StaticFiles` features: etag/304 support, content-length, MIME type detection, and path traversal protection.
 - **Added: SPA documentation** (`docs/building_an_spa.md`): Developer guide for serving SPAs from Djast app modules, including URL architecture, step-by-step setup, gotchas (no endpoints under SPA prefix, WebSocket/SSE constraints, NGINX production config), and the admin panel as reference implementation.
 - **Added: `createsuperuser` command**: New management command (`python manage.py createsuperuser`) that creates a user with `is_superuser=True` and `is_staff=True`. Prompts for username/email/password based on `AUTH_USER_MODEL_TYPE` setting. Validates password strength and confirms password entry. 10 new tests.
 - **Added: Admin panel**: Django-like admin panel with React frontend served by FastAPI. Self-contained in `admin/` — opt out by deleting the folder and removing the route from `urls.py`. Features:
   - **Model registry** (`admin/registry.py`): Django-like `admin.site.register(Model, "App")` and `@admin.register(Model)` decorator. SQLAlchemy column introspection for field types, editability, and required status. Supports `list_display`, `search_fields`, `field_options`, and `exclude_fields`.
   - **Generic CRUD API**: Schema-driven endpoints — `GET /admin/schema/`, list/detail/create/update/delete per model, bulk delete, admin password change for `AbstractBaseUser` subclasses. All endpoints (except `/admin/config/`) require `is_staff` or `is_superuser`.
   - **React frontend**: Login (adapts to django/email auth mode), sidebar from schema, paginated list with server-side search/sort, detail form with field-level rendering, admin password change (replaces password field for user models), own password change via top-bar menu.
   - **Zero-config for cloners**: Built `dist/` committed to repo and served by FastAPI at `/admin/`. Works after `git clone` + `docker compose up` — no Node.js or extra servers needed. Vite dev proxy available for frontend development.
   - **JWT authentication**: Real login via `/auth/token`, session restore via refresh cookie, automatic token refresh on 401.
   - User model registered under "Auth" by default with password auto-excluded and `has_password_change` flag. 66 new tests (22 registry + 44 views).
 - **Improved: Admin SPA self-contained**: The admin SPA mount moved from `main.py` to `admin/__init__.py` via the new `setup_app()` hook. No admin-specific code remains in `main.py`. Opting out requires only deleting `admin/` and removing the router from `urls.py`.
 - **Changed: `is_staff` and `is_superuser` moved to `AbstractBaseUser`**: Both user types now inherit these fields.
 - **Security Fix: Path traversal vulnerability in admin SPA serving**: The previous `FileResponse(admin_dist / path)` approach did not sanitise percent-encoded path components (`..%2F`). Replaced with Starlette's `StaticFiles` which validates all resolved paths against the configured directory root.

## 15-03-26
 - **Security: CSRF protection switched to opt-in**: Switched from global opt-out (`@csrf_exempt`) to opt-in (`csrf_protect` dependency) pattern. CSRF is no longer enforced on all state-changing endpoints by default — endpoints that authenticate via cookies can opt in by adding `Depends(csrf_protect)`. This is the correct pattern for an API framework using Bearer token auth (immune to CSRF). Removed `CSRF_ENABLED` setting. Cookie/header name and token length remain configurable via `CSRF_COOKIE_NAME`, `CSRF_HEADER_NAME`, `CSRF_TOKEN_LENGTH`.

## 13-03-26
 - **Improved: `db/engine.py`**: Removed dead `future=True` parameter from `SqliteConfig` and `PostgresConfig` engine options (no-op in SQLAlchemy 2.0+).
 - **Improved: `db/models.py`**: `Manager.exists()` now uses `SELECT EXISTS(...)` subquery instead of fetching the full row. Removed redundant local `func` import in `count()` (uses module-level import). Added type hints to `Model.objects()` (`session: AsyncSession`, return `Manager[Self]`).
 - **Improved: `makemigrations` command**: Refactored monolithic `detect_and_handle_renames` (330 lines) into focused module-level functions with type hints and a `MigrationOperations` dataclass. Fixed indentation bug in generated `op.rename_table()` code (unused `indent` variable). Removed dead Python <3.12 compatibility code (`ast.Str`, `hasattr(ast, "get_source_segment")`). Column rename detection now uses a heuristic — only prompts when a table has exactly 1 drop + 1 add (avoids N*M false-positive prompts). Warns if `alembic.ini` file template configuration fails silently. Removed unused `Path` import and redundant loop guard.
 - **Improved: `migrate` command**: Added `migrations/` directory existence check. Catches `CommandError` for cleaner error messages. Prints success message after applying migrations.
 - **Improved: Alembic env template**: Fixed `rglob`/`startswith` model discovery bugs (same fixes applied to `shell` command earlier).
 - **Improved: `startapp` command**: Validates module names are valid Python identifiers (rejects `my-app`, `class`, `123app`, etc.). Replaces interactive retry loop with simple error on name collision (standard CLI behavior). Removes redundant `__init__.py` creation logic.
 - **Improved: `startapp` templates**: Scaffolded apps now include `tests/` directory (with `__init__.py` and async `test_views.py` using `httpx.AsyncClient`) instead of flat `tests.py`. Added `utils/` directory and `__init__.py` to match expected app structure.
 - **Improved: `shell` command**: Added `auto_session` async context manager to namespace (auto-commits on success, rolls back on error — mirrors `get_async_session`). Model discovery now uses `glob("*/models.py")` instead of `rglob` to avoid matching nested files. Fixed fragile `startswith("djast")` path check. Removed unused imports. Narrowed cleanup error handling.
 - **Improved: `manage.py` help text**: `python manage.py` now displays command descriptions from module docstrings alongside command names.

## 12-03-26
 - **Added: Email verification**: Configurable email verification flow via `EMAIL_VERIFICATION` setting (`"mandatory"`, `"optional"`, `"none"`). New `EmailAddress` model (django-allauth pattern) tracks email addresses and verification status independently of the User model, preserving Django compatibility. HMAC-based tokens (no DB storage) auto-invalidate on state change. New endpoints: `POST /verify-email`, `POST /resend-verification`. OAuth-created users are automatically marked as verified. 5-minute cooldown between resend requests. Login gate blocks unverified users in mandatory mode.
 - **Added: Forgot password / password reset**: Secure password reset flow via email. New endpoints: `POST /forgot-password` (anti-enumeration — always returns same response), `POST /reset-password` (HMAC token validation, password strength check, all sessions revoked). Works for both EmailUser and DjangoUser. 5-minute cooldown between reset requests.
 - **Added: `EmailAddress` model**: Tracks email addresses with verification status per user. Follows django-allauth pattern. Supports future multi-email and email-change flows. Created automatically on signup and OAuth login.
 - **Added: HMAC token generator** (`auth/utils/tokens.py`): Django-style token generator for email verification and password reset. Tokens are URL-safe, time-limited, and self-invalidating when user state changes (password, login, verification). No database storage required.
 - **Added: Email templates**: HTML templates for verification (`verify_email.html`) and password reset (`reset_password.html`) emails in `templates/email/`.
 - **Added: New email/password settings**: `EMAIL_VERIFICATION`, `EMAIL_VERIFICATION_TOKEN_EXPIRE_SECONDS`, `PASSWORD_RESET_TOKEN_EXPIRE_SECONDS`, `EMAIL_COOLDOWN_SECONDS`, `EMAIL_VERIFICATION_URL`, `PASSWORD_RESET_URL`, and rate limit settings for new endpoints. 55 new tests.
 - **Fixed: `change_password` endpoint**: Now catches `PasswordIsWeak` exception and returns HTTP 400 (was returning HTTP 500). Consistent with `signup`, `reset_password`, and `set_password` endpoints.
 - **Fixed: OAuth error message leakage**: OAuth code exchange and profile fetch errors no longer expose raw exception details to the user. Internal details are logged server-side; the user receives a generic "OAuth authentication failed." message.
 - **Fixed: `send_email_task` logging**: Use lazy `%s` formatting in `logger.exception` instead of f-string, consistent with SMTP backend logging style.

## 11-03-26
 - **Added: Task queue (Taskiq)**: Async-native task queue backed by Redis. Includes `ListQueueBroker` with result backend, `SmartRetryMiddleware` (exponential backoff + jitter), built-in cron scheduling via `TaskiqScheduler`, and `run_in_executor` utility for CPU-bound work. Email sending can be routed through the task queue via `EMAIL_USE_TASKIQ` setting (attachments not supported through Taskiq — raises `ValueError`; console backend always sends directly). Worker and scheduler services added to `docker-compose.yaml`. New `tasks.py` included in `startapp` scaffold template. See `docs/taskiq.md`.
 - **Added: Email backend**: Django-like pluggable email backend with async support. Ships with `ConsoleEmailBackend` (prints to stdout, default for dev) and `SMTPEmailBackend` (wraps fastapi-mail for production SMTP). Swappable via `EMAIL_BACKEND` dotted path in settings. Includes Jinja2 template rendering for HTML emails, file attachments, and convenience functions `send_email()` / `send_template_email()`. 22 new tests.
 - **Security: OAuth authorization code exchange**: OAuth callback no longer exposes tokens in redirect URL. Tokens are stored behind a one-time authorization code (Redis, configurable TTL via `OAUTH_CODE_TTL`). Frontend exchanges the code via `POST /auth/oauth/token`.
 - **Security: Credentials exception factory**: Replace shared mutable `CREDENTIALS_EXCEPTION` singleton with `credentials_exception()` factory to prevent cross-request state leakage.
 - **Security: Token blacklist clock-skew buffer**: Blacklist TTL now includes a 10-second buffer to account for clock skew between servers.
 - **Security: Timing leak fix**: Consolidated `authenticate()` return paths so inactive users and wrong passwords take the same code path (no `last_login` DB write difference).
 - **Security: OAuth callback input validation**: `code` and `state` query parameters now have `max_length` constraints (2048 and 256 respectively).
 - **Security: Username validation** (Django mode): `min_length=1`, `max_length=150`, and `pattern=r"^[\w.@+\-]+$"` matching Django's `UnicodeUsernameValidator`.
 - **Security: Lockout fail-open configurable**: New `ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN` setting (default `true`). When `false`, login is blocked if Redis lockout check fails.

## 10-03-26
 - **Added: OAuth2 social login**: Optional Google and GitHub sign-up/sign-in flows, toggled via `OAUTH_GOOGLE_ENABLED` / `OAUTH_GITHUB_ENABLED` settings (disabled by default).
   - New endpoints: `GET /auth/oauth/{provider}/authorize`, `GET /auth/oauth/{provider}/callback`, `POST /auth/oauth/token`, `DELETE /auth/oauth/{provider}/link`, `POST /auth/set-password`.
   - `OAuthAccount` model links social identities to users. Auto-links by email if a matching user exists.
   - OAuth users receive the same JWT access + refresh tokens as password users (unified flow).
   - OAuth-only users can set a password later (configurable via `OAUTH_ALLOW_SET_PASSWORD`, default `True`).
   - Uses Authlib for OAuth2/OIDC protocol handling. CSRF protection via Redis-backed state tokens.
   - 46 new tests covering both `django` and `email` auth modes (including CSRF, OAuth code exchange, lockout fail-open, username validation).
 - **Added: `expires_in` field in token responses**: Per OAuth 2.0 RFC 6749 §5.1. Returns access token lifetime in seconds.
 - **Security: Restrict refresh token cookie path**: Cookie path restricted to `{APP_PREFIX}/auth` — cookie no longer sent on every request.
 - **Security: Per-account brute force protection**: Redis-backed failed login counter with configurable max attempts and lockout duration (`ACCOUNT_LOGIN_MAX_ATTEMPTS`, `ACCOUNT_LOGIN_LOCKOUT_SECONDS`). Fails open if Redis is unavailable.
 - **Security: `/logout-all` clears refresh token cookie**: Cookie now cleared from the browser on logout-all.
 - **Security: Password regex expanded**: Now allows all printable ASCII characters (was limited to `@$!%*?&`).
 - **Security: `max_length=100` on password fields**: Enforced at the schema boundary (Pydantic, Form, and defense-in-depth in `authenticate_user`).
 - **Security: `CORS_ALLOW_CREDENTIALS` defaults**: Now defaults to `True` in DEBUG, `False` in production (was always `True`).
 - **Changed: Rename `/revoke` → `/logout`, `/revoke-all` → `/logout-all`**: For standard JWT library compatibility.
 - **Changed: Remove trailing slash from `/users/me/` → `/users/me`**.
 - **Refactored: Extract `set_refresh_cookie()` helper**: Single source for cookie config.
 - **Refactored: Extract `get_current_user` FastAPI dependency**: Replaces duplicated token-to-user logic in views.
 - **Refactored: Extract `_encode_replacement_jwt()` helper**: Removes duplicated replacement-token encoding.
 - **Refactored: Move `normalize_email()` to `AbstractBaseUser`**: Eliminates duplicate across subclasses.
 - **Refactored: Replace N+1 token revocation loop with bulk SQL update** in `logout_user_all_devices`.
 - **Refactored: Add return type annotations** to all auth views.
 - **Fixed: Typo in `password_validators.py` docstring**.

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
