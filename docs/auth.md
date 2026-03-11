**Auth Module**

This document explains how to use and configure the built-in auth module. It covers user model selection, authentication endpoints, protecting your own routes, token lifecycle, security features, and configuration.

**Files:** `app/auth/models.py`, `app/auth/views.py`, `app/auth/schemas.py`, `app/auth/utils/`, `app/djast/settings.py`

**Quick summary:**
- JWT access tokens + rotating refresh tokens stored in HTTP-only cookies.
- Two user model types: Django-style (username) or email-based — controlled by a single setting.
- Optional OAuth2 social login (Google, GitHub) — toggled on/off via settings, disabled by default.
- Configurable email verification (`"mandatory"`, `"optional"`, `"none"`) with HMAC-based tokens.
- Forgot password / password reset flow with secure one-time tokens.
- Endpoints for signup, login, token refresh, logout, password change, account deactivation, email verification, password reset, and OAuth flows.
- Security layers: PBKDF2 password hashing, token blacklisting via Redis, brute force protection, rate limiting.

---

**Choosing a user model**

Set `AUTH_USER_MODEL_TYPE` in your environment (or `dev.env`) to pick the user model:

| Value | User model | USERNAME_FIELD | Extra fields |
|-------|-----------|---------------|--------------|
| `"django"` (default) | `AbstractDjangoUser` | `username` | `email`, `first_name`, `last_name`, `is_staff`, `is_superuser` |
| `"email"` | `AbstractEmailUser` | `email` | (none) |

Both models share a common base (`AbstractBaseUser`) that provides `password`, `is_active`, `date_joined`, and `last_login`.

The choice affects which fields are required at signup, which field is used for login, and the shape of the `UserRead` response schema. Switch this **before running your first migration** — changing it later requires a migration to alter the `auth_user` table.

```python
# dev.env
AUTH_USER_MODEL_TYPE=email   # or "django"
```

---

**Endpoints**

All endpoints are mounted at `{APP_PREFIX}/auth` (default: `/api/v1/auth`). Every endpoint is rate-limited.

| Method | Path | Auth required | Description |
|--------|------|:---:|-------------|
| POST | `/signup` | No | Create a new user |
| POST | `/token` | No | Login (returns access token + sets refresh cookie) |
| POST | `/refresh` | No | Rotate refresh token and get a new access token |
| POST | `/change-password` | Yes | Change password (revokes all sessions) |
| POST | `/set-password` | Yes | Set password for OAuth-only users |
| POST | `/logout` | Yes | Logout current device |
| POST | `/logout-all` | Yes | Logout all devices |
| POST | `/deactivate` | Yes | Deactivate account and revoke all sessions |
| GET | `/users/me` | Yes | Get current user info |
| POST | `/verify-email` | No | Verify email address with HMAC token |
| POST | `/resend-verification` | Yes | Resend verification email (5-min cooldown) |
| POST | `/forgot-password` | No | Request a password reset email |
| POST | `/reset-password` | No | Reset password with HMAC token |
| GET | `/oauth/{provider}/authorize` | No | Redirect to OAuth provider consent screen |
| GET | `/oauth/{provider}/callback` | No | Handle OAuth callback (redirects with one-time code) |
| POST | `/oauth/token` | No | Exchange one-time OAuth code for tokens |
| DELETE | `/oauth/{provider}/link` | Yes | Unlink a social account |

**Signup**
```bash
# Django mode
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "Secret1!xx", "email": "alice@example.com"}'

# Email mode
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "Secret1!xx"}'
```
Response (201):
```json
{"user_id": 1}
```
Signup can be disabled entirely by setting `ALLOW_SIGNUP=false`.

**Login**
```bash
# Django mode (OAuth2 form)
curl -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=alice&password=Secret1!xx"

# Email mode
curl -X POST http://localhost:8000/api/v1/auth/token \
  -d "email=alice@example.com&password=Secret1!xx"
```
Response (200):
```json
{"access_token": "eyJ...", "token_type": "bearer", "expires_in": 1800}
```
`expires_in` is the access token lifetime in seconds (default: 1800 = 30 minutes). Clients can use this to proactively refresh before expiration instead of waiting for a 401.

The response also sets a `refresh_token` HTTP-only cookie scoped to the auth path. Clients don't need to manage refresh tokens manually — the browser handles it.

**Refresh**
```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  --cookie "refresh_token=eyJ..."
```
Returns a new access token and rotates the refresh cookie. Old refresh tokens are single-use — reusing one outside the grace period revokes all sessions for that user (replay detection).

**Logout**
```bash
# Single device
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer eyJ..." \
  -H "X-CSRF-Token: <csrf_token_cookie_value>" \
  --cookie "refresh_token=eyJ...; csrf_token=..."

# All devices
curl -X POST http://localhost:8000/api/v1/auth/logout-all \
  -H "Authorization: Bearer eyJ..." \
  -H "X-CSRF-Token: <csrf_token_cookie_value>" \
  --cookie "csrf_token=..."
```

**Change password**
```bash
curl -X POST http://localhost:8000/api/v1/auth/change-password \
  -H "Authorization: Bearer eyJ..." \
  -H "X-CSRF-Token: <csrf_token_cookie_value>" \
  -H "Content-Type: application/json" \
  --cookie "csrf_token=..." \
  -d '{"old_password": "Secret1!xx", "new_password": "NewPass1!yy"}'
```
This revokes all sessions across all devices after changing the password.

**Current user**
```bash
curl http://localhost:8000/api/v1/auth/users/me \
  -H "Authorization: Bearer eyJ..."
```

---

**Email verification**

Email verification is controlled by the `EMAIL_VERIFICATION` setting:

| Value | Behavior |
|-------|----------|
| `"none"` (default) | No verification emails sent. Users can log in immediately. |
| `"optional"` | Verification email sent on signup, but login is allowed without verification. |
| `"mandatory"` | Verification email sent on signup. Users **cannot log in** until their email is verified. Login returns 403. |

```bash
# dev.env
EMAIL_VERIFICATION=mandatory
```

**How it works:**

Verification status is tracked in the `EmailAddress` model (table: `auth_email_address`), separate from the User model. This follows the django-allauth pattern and keeps `AbstractDjangoUser` fully Django-compatible.

- On signup, if the user provides an email, an `EmailAddress` record is created with `verified=False`.
- If `EMAIL_VERIFICATION` is not `"none"`, a verification email is sent automatically.
- OAuth users are automatically marked as verified (the provider already verified their email).

Verification tokens are HMAC-based (no database storage). They encode the user ID and a timestamp, signed with a hash of the user's current state (password, login timestamp, verification status). This means tokens:
- Auto-invalidate when the user's state changes (e.g., password change).
- Are single-use — once the email is verified, the token's HMAC no longer matches.
- Expire after `EMAIL_VERIFICATION_TOKEN_EXPIRE_SECONDS` (default: 24 hours).

**Verify email**
```bash
curl -X POST http://localhost:8000/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{"token": "the-token-from-email"}'
```
Response (200):
```json
{"message": "Email verified successfully."}
```

**Resend verification email**
```bash
curl -X POST http://localhost:8000/api/v1/auth/resend-verification \
  -H "Authorization: Bearer eyJ..." \
  -H "X-CSRF-Token: <csrf_token_cookie_value>" \
  --cookie "csrf_token=..."
```
Response (200):
```json
{"message": "Verification email sent."}
```

Returns 400 if the email is already verified or the user has no email address. Returns 429 if a verification email was sent within the last 5 minutes (configurable via `EMAIL_COOLDOWN_SECONDS`).

**Mandatory verification and login:**

When `EMAIL_VERIFICATION=mandatory`, the login endpoint (`POST /token`) returns 403 if the user's primary email is unverified:
```json
{"detail": "Email verification required."}
```

For DjangoUser accounts without an email address, the verification gate is bypassed — there's nothing to verify. This keeps username-only workflows functional.

---

**Forgot password / password reset**

The password reset flow allows users to reset their password via email. It works for both EmailUser and DjangoUser (as long as the user has an email address with an `EmailAddress` record).

**Request a password reset:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'
```
Response (200) — always the same, regardless of whether the email exists:
```json
{"message": "If an account with that email exists, a reset link has been sent."}
```

This prevents user enumeration — the response does not reveal whether an account exists for the given email. A 5-minute cooldown between reset emails is enforced silently (no error returned to avoid leaking information).

**Reset the password:**
```bash
curl -X POST http://localhost:8000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "the-token-from-email", "new_password": "NewSecure1!xx"}'
```
Response (200):
```json
{"message": "Password reset successfully."}
```

After a successful reset:
- The new password must meet the same strength requirements as signup.
- All existing sessions are revoked (the user is logged out everywhere).
- The reset token becomes invalid (the password hash changed, so the HMAC no longer matches).

Reset tokens expire after `PASSWORD_RESET_TOKEN_EXPIRE_SECONDS` (default: 1 hour).

**Email templates:**

Both verification and reset emails use Jinja2 HTML templates located in `app/templates/email/`:
- `verify_email.html` — contains a verification button/link, project name, and expiry notice.
- `reset_password.html` — contains a reset button/link, project name, expiry notice, and security warning.

The templates directory is configured via `EMAIL_TEMPLATE_DIR` (defaults to `app/templates/email/`). Override it to use custom templates.

**Frontend integration:**

The email links point to frontend URLs configured in settings:
- `EMAIL_VERIFICATION_URL` (default: `http://localhost:3000/auth/verify-email`) — the token is appended as `?token=...`
- `PASSWORD_RESET_URL` (default: `http://localhost:3000/auth/reset-password`) — the token is appended as `?token=...`

Your frontend should extract the token from the URL and POST it to the corresponding backend endpoint.

---

**OAuth2 social login (Google / GitHub)**

OAuth is disabled by default. Enable a provider by setting its credentials in your environment:

```bash
# dev.env
OAUTH_GOOGLE_ENABLED=true
OAUTH_GOOGLE_CLIENT_ID=your-google-client-id
OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret

OAUTH_GITHUB_ENABLED=true
OAUTH_GITHUB_CLIENT_ID=your-github-client-id
OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret
```

When disabled, the OAuth endpoints return 404. Existing password auth is completely unaffected.

**How the flow works:**

1. Frontend directs the user to `GET /api/v1/auth/oauth/google/authorize` (or `github`).
2. Backend generates a CSRF state token (stored in Redis, 5-minute TTL), then redirects to the provider's consent screen.
3. After the user approves, the provider redirects to `GET /api/v1/auth/oauth/google/callback` with an authorization code.
4. Backend exchanges the code for an access token, fetches the user's profile (email, name), and either:
   - Finds an existing `OAuthAccount` link → returns that user.
   - Finds an existing user with the same email → auto-links the OAuth identity to that account.
   - Creates a new user with an unusable password + a new `OAuthAccount` record.
5. Backend issues JWT tokens and stores them behind a one-time authorization code in Redis (TTL: `OAUTH_CODE_TTL`, default 60 seconds).
6. Backend redirects to `OAUTH_LOGIN_REDIRECT_URL?code={one-time-code}`. No tokens appear in the URL.
7. Frontend POSTs the code to `POST /api/v1/auth/oauth/token` to receive the access token and refresh cookie.

```bash
# Step 7: Exchange the one-time code for tokens
curl -X POST http://localhost:8000/api/v1/auth/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"code": "the-one-time-code"}'
```
Response (200):
```json
{"access_token": "eyJ...", "token_type": "bearer", "expires_in": 1800}
```

The response also sets the `refresh_token` HTTP-only cookie and `csrf_token` cookie, identical to password-based login. The authorization code is single-use — replaying it returns 400.

**Account linking:**

OAuth auto-links by email. If a user signed up with `alice@example.com` via password, and later signs in with Google using the same email, the Google identity is linked to the existing account. The user can then log in with either method.

A user can have multiple OAuth providers linked. Each provider is tracked in the `OAuthAccount` model (table: `auth_o_auth_account`).

**Setting a password for OAuth-only users:**

Users who signed up via OAuth have no password. They can set one to enable password-based login:

```bash
curl -X POST http://localhost:8000/api/v1/auth/set-password \
  -H "Authorization: Bearer eyJ..." \
  -H "X-CSRF-Token: <csrf_token_cookie_value>" \
  -H "Content-Type: application/json" \
  --cookie "csrf_token=..." \
  -d '{"new_password": "MyNewPass1!"}'
```

This is controlled by `OAUTH_ALLOW_SET_PASSWORD` (default: `true`). Users who already have a password get a 400 — they should use `/change-password` instead.

**Unlinking a provider:**

```bash
curl -X DELETE http://localhost:8000/api/v1/auth/oauth/google/link \
  -H "Authorization: Bearer eyJ..." \
  -H "X-CSRF-Token: <csrf_token_cookie_value>" \
  --cookie "csrf_token=..."
```

Users cannot unlink their only authentication method. If an OAuth-only user with a single provider tries to unlink, they get a 400. They must either set a password or link another provider first.

**Username generation (Django mode):**

In `django` mode, OAuth users need a username. The system auto-generates one from the email prefix (e.g., `alice` from `alice@example.com`), sanitizing non-alphanumeric characters and appending a numeric suffix if taken (`alice1`, `alice2`, etc.).

---

**Protecting your own routes**

Use the `get_current_user` dependency to require authentication on any endpoint:

```python
from auth.utils.auth_backend import get_current_user
from auth.models import User

@router.get("/my-endpoint")
async def my_endpoint(user: User = Depends(get_current_user)):
    return {"message": f"Hello, {user.id}"}
```

`get_current_user` validates the access token, checks the blacklist, and returns the active `User` instance. It raises a 401 if the token is invalid, expired, blacklisted, or the user is inactive.

If you only need the token data (e.g., `user_id`, `jti`) without hitting the database, use `validate_access_token` instead:

```python
from auth.utils.auth_backend import validate_access_token
from auth.schemas import TokenData

@router.get("/lightweight")
async def lightweight(token_data: TokenData = Depends(validate_access_token)):
    return {"user_id": token_data.sub}
```

---

**Token lifecycle**

The auth module uses a two-token system:

1. **Access token** — Short-lived JWT (default: 30 minutes). Sent in the `Authorization: Bearer` header. Stateless validation with Redis-backed blacklisting for revocation.

2. **Refresh token** — Longer-lived JWT (default: 7 days). Stored in an HTTP-only, secure cookie. Backed by a database record (`RefreshToken` model) for rotation and replay detection.

**Token rotation flow:**
```
Login
  -> Access token (JWT) returned in response body
  -> Refresh token (JWT) set as HTTP-only cookie
  -> RefreshToken record created in DB

Refresh
  -> Old refresh token marked as "used" in DB
  -> New refresh token created, linked to old via replaced_by_key
  -> New access token returned
  -> New refresh cookie set

Logout
  -> Access token blacklisted in Redis (TTL = remaining lifetime)
  -> Refresh token revoked in DB
```

**Replay detection:** If a refresh token is reused after it has already been rotated:
- Within the grace period (default: 5 seconds) — the previously issued replacement is returned. This handles concurrent requests from the same client.
- Outside the grace period — all sessions for the user are revoked. This indicates the token was likely stolen.

---

**Password requirements**

Passwords are validated against `PASSWORD_VALIDATION_REGEX`. The default regex requires:
- 8 to 100 characters
- At least one lowercase letter
- At least one uppercase letter
- At least one digit
- At least one special character
- Only printable ASCII characters (space through tilde)

Override the regex in settings to customize strength requirements:
```python
# dev.env — example: minimum 12 chars, no special char requirement
PASSWORD_VALIDATION_REGEX='^.{12,100}$'
```

Passwords are hashed with PBKDF2-SHA256 (1,200,000 iterations) and automatically rehashed on login if the iteration count has increased since the hash was stored.

---

**Security features**

**CSRF protection** — All state-changing requests (POST, PUT, PATCH, DELETE) are automatically checked via a global CSRF dependency, similar to Django's `CsrfViewMiddleware`. On login and token refresh, the server sets a `csrf_token` cookie (non-HttpOnly, readable by JavaScript). The frontend must read the cookie and send its value in the `X-CSRF-Token` header. The server compares the two using constant-time comparison. Requests without a matching header receive 403. Endpoints that don't need CSRF (signup, login, refresh, OAuth token exchange) are marked with `@csrf_exempt`. CSRF can be disabled globally by setting `CSRF_ENABLED=false`.

To exempt your own endpoints from CSRF, use the `@csrf_exempt` decorator (place it between `@router` and any other decorators like `@limiter.limit`):

```python
from djast.utils.csrf import csrf_exempt

@router.post("/my-webhook")
@csrf_exempt
@limiter.limit("10/minute")
async def my_webhook(request: Request):
    ...
```

**Brute force protection** — After `ACCOUNT_LOGIN_MAX_ATTEMPTS` (default: 5) failed login attempts, the account is locked for `ACCOUNT_LOGIN_LOCKOUT_SECONDS` (default: 300). Tracked per-username in Redis. Set `ACCOUNT_LOGIN_MAX_ATTEMPTS=0` to disable. If Redis is unavailable, `ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN` (default: `true`) determines whether login is allowed (fail-open) or blocked (fail-closed).

**Token blacklisting** — Redis-backed. Single-device logout blacklists the specific access token JTI. All-device logout sets a `min_iat` timestamp — any access token issued before that time is rejected. If Redis is unavailable, `FALLBACK_IS_BLACKLISTED` (default: `true`) determines whether tokens are treated as blacklisted (fail-secure) or valid (fail-open).

**Rate limiting** — All auth endpoints are rate-limited via SlowAPI with Redis storage. Limits are per IP address. See the configuration table below for defaults.

**Refresh cookie security** — The refresh token cookie is:
- `HttpOnly` — not accessible to JavaScript
- `Secure` — sent only over HTTPS (unless `DEBUG=true`)
- `SameSite=lax` — mitigates CSRF
- Path-scoped to `{APP_PREFIX}/auth` — not sent to other endpoints

**Expired token cleanup** — Stale `RefreshToken` records are cleaned up opportunistically during authentication. A per-worker cooldown (30 seconds) and a Redis-backed global lock (default: 3600 seconds) prevent excessive cleanup runs. No cron job needed.

---

**Configuration reference**

All settings are in `app/djast/settings.py` and can be overridden via environment variables.

| Setting | Default | Description |
|---------|---------|-------------|
| `AUTH_USER_MODEL_TYPE` | `"django"` | User model type: `"django"` or `"email"` |
| `SECRET_KEY` | — | JWT signing key (set in environment) |
| `JWT_ALGORITHM` | `"HS256"` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime in minutes |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime in days |
| `REFRESH_TOKEN_REUSE_GRACE_SECONDS` | `5` | Grace period for concurrent refresh requests |
| `ALLOW_SIGNUP` | `true` | Enable/disable public registration |
| `PASSWORD_HASHER` | `"pbkdf2_sha256"` | Password hashing algorithm |
| `PASSWORD_VALIDATION_REGEX` | *(see above)* | Regex for password strength validation |
| `ACCOUNT_LOGIN_MAX_ATTEMPTS` | `5` | Failed logins before lockout (0 = disabled) |
| `ACCOUNT_LOGIN_LOCKOUT_SECONDS` | `300` | Lockout duration in seconds |
| `ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN` | `true` | Allow login when Redis lockout check fails |
| `FALLBACK_IS_BLACKLISTED` | `true` | Treat tokens as blacklisted when Redis is down |
| `CSRF_ENABLED` | `true` | Enable CSRF double-submit cookie protection |
| `CSRF_COOKIE_NAME` | `"csrf_token"` | Name of the CSRF cookie |
| `CSRF_HEADER_NAME` | `"X-CSRF-Token"` | Header name for CSRF token |
| `CSRF_TOKEN_LENGTH` | `32` | Length of generated CSRF tokens |
| `OAUTH_GOOGLE_ENABLED` | `false` | Enable Google OAuth login |
| `OAUTH_GOOGLE_CLIENT_ID` | `""` | Google OAuth client ID |
| `OAUTH_GOOGLE_CLIENT_SECRET` | `""` | Google OAuth client secret |
| `OAUTH_GITHUB_ENABLED` | `false` | Enable GitHub OAuth login |
| `OAUTH_GITHUB_CLIENT_ID` | `""` | GitHub OAuth client ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | `""` | GitHub OAuth client secret |
| `OAUTH_LOGIN_REDIRECT_URL` | `"http://localhost:3000/auth/callback"` | Frontend URL to redirect to after OAuth callback |
| `OAUTH_ALLOW_SET_PASSWORD` | `true` | Allow OAuth-only users to set a password |
| `OAUTH_CODE_TTL` | `60` | One-time OAuth authorization code TTL in seconds |
| `EMAIL_VERIFICATION` | `"none"` | Email verification mode: `"mandatory"`, `"optional"`, or `"none"` |
| `EMAIL_VERIFICATION_TOKEN_EXPIRE_SECONDS` | `86400` | Verification token lifetime (default: 24 hours) |
| `PASSWORD_RESET_TOKEN_EXPIRE_SECONDS` | `3600` | Password reset token lifetime (default: 1 hour) |
| `EMAIL_COOLDOWN_SECONDS` | `300` | Minimum time between resending verification/reset emails |
| `EMAIL_VERIFICATION_URL` | `"http://localhost:3000/auth/verify-email"` | Frontend URL for email verification links |
| `PASSWORD_RESET_URL` | `"http://localhost:3000/auth/reset-password"` | Frontend URL for password reset links |

**Rate limit settings:**

| Setting | Default |
|---------|---------|
| `AUTH_RATE_LIMIT_SIGNUP` | `"5/minute"` |
| `AUTH_RATE_LIMIT_LOGIN` | `"5/minute"` |
| `AUTH_RATE_LIMIT_REFRESH` | `"20/minute"` |
| `AUTH_RATE_LIMIT_CHANGE_PASSWORD` | `"3/minute"` |
| `AUTH_RATE_LIMIT_REVOKE` | `"20/minute"` |
| `AUTH_RATE_LIMIT_USER_ME` | `"100/minute"` |
| `AUTH_RATE_LIMIT_OAUTH` | `"10/minute"` |
| `AUTH_RATE_LIMIT_VERIFY_EMAIL` | `"5/minute"` |
| `AUTH_RATE_LIMIT_RESEND_VERIFICATION` | `"3/minute"` |
| `AUTH_RATE_LIMIT_PASSWORD_RESET_REQUEST` | `"3/minute"` |
| `AUTH_RATE_LIMIT_PASSWORD_RESET_CONFIRM` | `"5/minute"` |

---

**Extending the User model**

The `User` model is defined dynamically based on `AUTH_USER_MODEL_TYPE`, but you can extend the abstract base classes for custom fields. Add fields to `AbstractDjangoUser` or `AbstractEmailUser` in `auth/models.py`, then generate a migration:

```bash
cd app
python manage.py makemigrations "add custom user fields"
python manage.py migrate
```

If you need to add relationships from other apps to the User model, import it from `auth.models`:

```python
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from djast.db.models import Model
from auth.models import User

class Post(Model):
    author_id: Mapped[int] = mapped_column(ForeignKey("auth_user.id"))
    author: Mapped[User] = relationship()
```

The table name is always `auth_user` regardless of model type.

---

**Testing**

Auth tests live in `app/auth/tests/` and use pytest-asyncio with in-memory SQLite. The test suite provides useful patterns you can reuse:

```python
import pytest
from httpx import ASGITransport, AsyncClient
from main import create_app

@pytest.fixture
async def client(db_session):
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

@pytest.mark.asyncio
async def test_protected_endpoint(client):
    # Signup + login to get a token
    await client.post("/api/v1/auth/signup", json={
        "username": "testuser",
        "password": "TestPass1!"
    })
    resp = await client.post("/api/v1/auth/token", data={
        "username": "testuser",
        "password": "TestPass1!"
    })
    token = resp.json()["access_token"]

    # Use the token
    resp = await client.get(
        "/api/v1/auth/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
```

See `app/auth/tests/test_views.py` for comprehensive examples covering success cases, auth failures, invalid input, and edge cases like token replay detection.
