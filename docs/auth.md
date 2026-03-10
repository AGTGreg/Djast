**Auth Module**

This document explains how to use and configure the built-in auth module. It covers user model selection, authentication endpoints, protecting your own routes, token lifecycle, security features, and configuration.

**Files:** `app/auth/models.py`, `app/auth/views.py`, `app/auth/schemas.py`, `app/auth/utils/`, `app/djast/settings.py`

**Quick summary:**
- JWT access tokens + rotating refresh tokens stored in HTTP-only cookies.
- Two user model types: Django-style (username) or email-based — controlled by a single setting.
- Endpoints for signup, login, token refresh, logout, password change, and account deactivation.
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
| POST | `/logout` | Yes | Logout current device |
| POST | `/logout-all` | Yes | Logout all devices |
| POST | `/deactivate` | Yes | Deactivate account and revoke all sessions |
| GET | `/users/me` | Yes | Get current user info |

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
  --cookie "refresh_token=eyJ..."

# All devices
curl -X POST http://localhost:8000/api/v1/auth/logout-all \
  -H "Authorization: Bearer eyJ..."
```

**Change password**
```bash
curl -X POST http://localhost:8000/api/v1/auth/change-password \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"old_password": "Secret1!xx", "new_password": "NewPass1!yy"}'
```
This revokes all sessions across all devices after changing the password.

**Current user**
```bash
curl http://localhost:8000/api/v1/auth/users/me \
  -H "Authorization: Bearer eyJ..."
```

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

**Brute force protection** — After `ACCOUNT_LOGIN_MAX_ATTEMPTS` (default: 5) failed login attempts, the account is locked for `ACCOUNT_LOGIN_LOCKOUT_SECONDS` (default: 300). Tracked per-username in Redis. Set `ACCOUNT_LOGIN_MAX_ATTEMPTS=0` to disable.

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
| `FALLBACK_IS_BLACKLISTED` | `true` | Treat tokens as blacklisted when Redis is down |

**Rate limit settings:**

| Setting | Default |
|---------|---------|
| `AUTH_RATE_LIMIT_SIGNUP` | `"5/minute"` |
| `AUTH_RATE_LIMIT_LOGIN` | `"5/minute"` |
| `AUTH_RATE_LIMIT_REFRESH` | `"20/minute"` |
| `AUTH_RATE_LIMIT_CHANGE_PASSWORD` | `"3/minute"` |
| `AUTH_RATE_LIMIT_REVOKE` | `"20/minute"` |
| `AUTH_RATE_LIMIT_USER_ME` | `"100/minute"` |

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
