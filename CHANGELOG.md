# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security
- **CSRF protection**: Double-submit cookie pattern for all state-changing authenticated endpoints. Login/refresh set a `csrf_token` cookie; protected endpoints require matching `X-CSRF-Token` header. Configurable via `CSRF_ENABLED`, `CSRF_COOKIE_NAME`, `CSRF_HEADER_NAME`, `CSRF_TOKEN_LENGTH`.
- **OAuth authorization code exchange**: OAuth callback no longer exposes tokens in redirect URL. Tokens are stored behind a one-time authorization code (Redis, configurable TTL via `OAUTH_CODE_TTL`). Frontend exchanges the code via `POST /auth/oauth/token`.
- **Credentials exception factory**: Replace shared mutable `CREDENTIALS_EXCEPTION` singleton with `credentials_exception()` factory to prevent cross-request state leakage.
- **Token blacklist clock-skew buffer**: Blacklist TTL now includes a 10-second buffer to account for clock skew between servers.
- **Timing leak fix**: Consolidated `authenticate()` return paths so inactive users and wrong passwords take the same code path (no `last_login` DB write difference).
- **OAuth callback input validation**: `code` and `state` query parameters now have `max_length` constraints (2048 and 256 respectively).
- **Username validation** (Django mode): `min_length=1`, `max_length=150`, and `pattern=r"^[\w.@+\-]+$"` matching Django's `UnicodeUsernameValidator`.
- **Lockout fail-open configurable**: New `ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN` setting (default `true`). When `false`, login is blocked if Redis lockout check fails.
- Restrict refresh token cookie path to `{APP_PREFIX}/auth` — cookie no longer sent on every request.
- Per-account brute force protection: Redis-backed failed login counter with configurable max attempts and lockout duration (`ACCOUNT_LOGIN_MAX_ATTEMPTS`, `ACCOUNT_LOGIN_LOCKOUT_SECONDS`). Fails open if Redis is unavailable.
- `/logout-all` now clears the refresh token cookie from the browser.
- Password regex expanded to allow all printable ASCII characters (was limited to `@$!%*?&`).
- `max_length=100` enforced on all password fields at the schema boundary (Pydantic, Form, and defense-in-depth in `authenticate_user`).
- `CORS_ALLOW_CREDENTIALS` now defaults to `True` in DEBUG, `False` in production (was always `True`).

### Added
- **Email backend**: Django-like pluggable email backend with async support. Ships with `ConsoleEmailBackend` (prints to stdout, default for dev) and `SMTPEmailBackend` (wraps fastapi-mail for production SMTP). Swappable via `EMAIL_BACKEND` dotted path in settings. Includes Jinja2 template rendering for HTML emails, file attachments, and convenience functions `send_email()` / `send_template_email()`. 22 new tests.
- **OAuth2 social login**: Optional Google and GitHub sign-up/sign-in flows, toggled via `OAUTH_GOOGLE_ENABLED` / `OAUTH_GITHUB_ENABLED` settings (disabled by default).
  - New endpoints: `GET /auth/oauth/{provider}/authorize`, `GET /auth/oauth/{provider}/callback`, `POST /auth/oauth/token`, `DELETE /auth/oauth/{provider}/link`, `POST /auth/set-password`.
  - `OAuthAccount` model links social identities to users. Auto-links by email if a matching user exists.
  - OAuth users receive the same JWT access + refresh tokens as password users (unified flow).
  - OAuth-only users can set a password later (configurable via `OAUTH_ALLOW_SET_PASSWORD`, default `True`).
  - Uses Authlib for OAuth2/OIDC protocol handling. CSRF protection via Redis-backed state tokens.
  - 46 new tests covering both `django` and `email` auth modes (including CSRF, OAuth code exchange, lockout fail-open, username validation).
- `expires_in` field in token responses (login, refresh) per OAuth 2.0 RFC 6749 §5.1. Returns access token lifetime in seconds.

### Changed
- Rename `/revoke` → `/logout`, `/revoke-all` → `/logout-all` for standard JWT library compatibility.
- Remove trailing slash from `/users/me/` → `/users/me`.

### Refactored
- Extract `set_refresh_cookie()` helper — single source for cookie config.
- Extract `get_current_user` FastAPI dependency — replaces duplicated token-to-user logic in views.
- Extract `_encode_replacement_jwt()` helper — removes duplicated replacement-token encoding.
- Move `normalize_email()` up to `AbstractBaseUser` — eliminates duplicate across subclasses.
- Replace N+1 token revocation loop with bulk SQL update in `logout_user_all_devices`.
- Add return type annotations to all auth views.

### Fixed
- Typo in `password_validators.py` docstring.

## [0.1.0] - Initial Release

### Core
- FastAPI + SQLAlchemy async boilerplate with Django-style layout.
- `Model` / `Manager` ORM layer, `TimestampMixin`, pluggable engine (SQLite / PostgreSQL).
- Pydantic `BaseSettings`, CLI with `startapp` / `makemigrations` / `migrate` / `shell`.
- Central `APIRouter` aggregation, `get_async_session` dependency with auto-commit/rollback.

### Auth
- Switchable user models via `AUTH_USER_MODEL_TYPE` (`"django"` / `"email"`).
- Django-compatible async `pbkdf2_sha256` password hashing.
- JWT access + refresh tokens with rotation, replay detection, and grace period.
- Redis-backed token blacklist with configurable fallback.
- Endpoints: signup, login, refresh, logout (single/all devices), change password, deactivate, user info.
- Rate limiting (SlowAPI + Redis) on all auth endpoints.
- Comprehensive test suite (65 tests).
