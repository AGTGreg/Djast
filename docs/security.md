**Security**

This document covers Djast's security architecture, the differences between development and production modes, and best practices for deployment.

**Files:** `app/djast/settings.py`, `app/djast/utils/csrf.py`, `app/auth/utils/auth_backend.py`, `app/auth/utils/hashers.py`, `app/main.py`

---

**Development vs production mode**

Security behavior is controlled by the `DEBUG` setting. Set `DEBUG=false` in production — this single flag tightens multiple layers at once.

| Behavior | `DEBUG=true` (development) | `DEBUG=false` (production) |
|----------|---------------------------|----------------------------|
| Cookie `Secure` flag | Off (works over HTTP) | On (HTTPS only) |
| CORS origins | Localhost variants auto-populated | Empty list (must be configured explicitly) |
| CORS credentials | Allowed | Disabled (unless explicitly enabled) |
| Database query logging | Enabled (`echo=True`) | Disabled |
| CSRF cookie | Sent over HTTP | Sent only over HTTPS |

**What you must configure for production:**

```bash
# Required — security-critical
DEBUG=false
SECRET_KEY="<generate a unique 50+ char random string>"

# Required — set to your actual frontend domain(s)
CORS_ALLOW_ORIGINS='["https://yourdomain.com"]'

# Required — switch from SQLite to PostgreSQL
DB_ENGINE=postgresql
DB_HOST=your-db-host
DB_PORT=5432
DB_NAME=your_db
DB_USER=your_user
DB_PASSWORD=your_password

# Required if using OAuth
OAUTH_LOGIN_REDIRECT_URL=https://yourdomain.com/auth/callback
```

Generate a strong `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

---

**Authentication security**

Djast uses a two-token JWT system with multiple defense layers.

**Access tokens** (short-lived, stateless):
- Algorithm: HMAC-SHA256 (`HS256`)
- Default lifetime: 30 minutes
- Sent in the `Authorization: Bearer` header
- Blacklist-checked on every request via Redis
- Contains: user ID (`sub`), token type, expiry, unique JTI (ULID), issued-at timestamp

**Refresh tokens** (long-lived, stateful):
- Default lifetime: 7 days
- Stored in an HTTP-only, `Secure`, `SameSite=lax` cookie
- Path-scoped to `{APP_PREFIX}/auth` (not sent on other endpoints)
- Backed by database records for rotation tracking and replay detection
- **Single-use with rotation**: Each refresh produces a new token; the old one is marked as consumed

**Token blacklisting** (Redis-backed):
- Single-device logout: Blacklists the specific access token JTI
- All-device logout: Sets a `min_iat` timestamp — all tokens issued before this time are rejected
- TTL includes a 10-second buffer for clock skew between servers
- If Redis is unavailable, `FALLBACK_IS_BLACKLISTED` (default: `true`) determines behavior:
  - `true` (fail-closed): Tokens are treated as blacklisted, users must re-authenticate
  - `false` (fail-open): Tokens are assumed valid, prioritizing availability

**Replay detection**:
- If a refresh token is reused after rotation:
  - Within the grace period (default: 5 seconds): The same replacement token is returned (handles concurrent requests)
  - Outside the grace period: All sessions for the user are revoked immediately (stolen token assumed)
- Tokens track `used_at`, `revoked_at`, and `replaced_by_key` for full audit trails

---

**Password security**

**Hashing**: PBKDF2-HMAC-SHA256 with 1,200,000 iterations. Salt is 128-bit minimum entropy. Format: `pbkdf2_sha256$<iterations>$<salt>$<hash>`. Compatible with Django's password hashing.

**Async execution**: Password hashing runs in a thread pool (`asyncio.to_thread`) to avoid blocking the event loop.

**Auto-rehashing**: On login, if a password was hashed with fewer iterations than the current setting, it is transparently rehashed with the current iteration count.

**Strength validation**: Passwords are validated against `PASSWORD_VALIDATION_REGEX` before hashing. The default requires:
- 8 to 100 characters
- At least one lowercase letter, one uppercase letter, one digit, and one special character
- Only printable ASCII characters (space through tilde)

Override the regex to customize:

```bash
# Example: minimum 12 chars, no special char requirement
PASSWORD_VALIDATION_REGEX='^[\x20-\x7E]{12,100}$'
```

**Input length defense**: Passwords longer than 100 characters are rejected at the schema boundary before hashing. This prevents denial-of-service via extremely long passwords that would be expensive to hash.

**Unusable passwords**: Users created via OAuth have a password value prefixed with `!` followed by 40 random characters. This value never matches any hash, so these users cannot log in with a password until they explicitly set one via `/auth/set-password`.

---

**CSRF protection**

Djast uses the **double-submit cookie** pattern, enforced globally via a FastAPI dependency — similar to Django's `CsrfViewMiddleware`.

**How it works:**
1. On login and token refresh, the server sets a `csrf_token` cookie (`httponly=False`, readable by JavaScript).
2. For every state-changing request (POST, PUT, PATCH, DELETE), the server checks that the `X-CSRF-Token` header matches the cookie value.
3. Comparison uses `secrets.compare_digest()` (constant-time) to prevent timing attacks.
4. Mismatched or missing tokens return 403.

**Safe methods** (GET, HEAD, OPTIONS, TRACE) are never checked.

**Exempting endpoints**: Use the `@csrf_exempt` decorator for endpoints that don't need CSRF (e.g., login, signup, webhooks, API endpoints consumed by non-browser clients):

```python
from djast.utils.csrf import csrf_exempt

@router.post("/my-webhook")
@csrf_exempt
@limiter.limit("10/minute")
async def my_webhook(request: Request):
    ...
```

`@csrf_exempt` must be placed between `@router` and any other decorators (like `@limiter.limit`). This ensures the registered route endpoint matches the exempt registry.

**Frontend integration**: After login, read the `csrf_token` cookie and include it as the `X-CSRF-Token` header on all non-GET requests:

```javascript
// Example with fetch
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('csrf_token='))
  ?.split('=')[1];

fetch('/api/v1/auth/logout', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'X-CSRF-Token': csrfToken,
  },
});
```

**Disabling CSRF**: Set `CSRF_ENABLED=false`. Only recommended for development or API-only backends consumed exclusively by non-browser clients.

---

**Brute force protection**

Failed login attempts are tracked per-account in Redis. After `ACCOUNT_LOGIN_MAX_ATTEMPTS` (default: 5) failures, the account is locked for `ACCOUNT_LOGIN_LOCKOUT_SECONDS` (default: 300 seconds).

- Tracking key: `login_attempts:{username}` (case-insensitive)
- Counter auto-expires after the lockout period
- Cleared on successful login
- Set `ACCOUNT_LOGIN_MAX_ATTEMPTS=0` to disable entirely

**Redis failure behavior** (`ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN`):
- `true` (default): Login proceeds normally if Redis is unavailable. Prioritizes availability — users can still log in, but brute force protection is temporarily disabled.
- `false`: Login is blocked with a 429 response. Prioritizes security — no login allowed if the lockout check cannot be performed.

Choose based on your threat model:

```bash
# High-availability (e-commerce, SaaS):
ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN=true

# High-security (banking, healthcare):
ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN=false
```

---

**Timing attack mitigation**

Authentication is designed to prevent user enumeration via timing differences:

- **User not found**: A dummy password hash is still verified, making the response time indistinguishable from a valid user with a wrong password.
- **Inactive user**: The same code path as an incorrect password — no database write difference (no `last_login` update) to leak status.
- **Credentials response**: All authentication failures return the same generic 401 response: `"Invalid credentials."` — no distinction between wrong username, wrong password, or inactive account.

---

**Rate limiting**

All auth endpoints are rate-limited via SlowAPI with Redis storage. Limits are per-IP using `X-Forwarded-For` (proxy-aware).

| Endpoint | Default limit |
|----------|--------------|
| Signup | 5/minute |
| Login | 5/minute |
| Refresh | 20/minute |
| Change password | 3/minute |
| Logout / Revoke | 20/minute |
| User info | 100/minute |
| OAuth endpoints | 10/minute |

Adjust limits in settings based on your traffic patterns. Rate limiting uses a separate Redis database (`RATE_LIMIT_REDIS_URL`, default: `redis://redis:6379/2`) to isolate it from session/token storage.

---

**CORS configuration**

CORS is configured in `settings.py` and applied as middleware in `main.py`.

| Setting | Dev default | Prod default | Notes |
|---------|-----------|-------------|-------|
| `CORS_ALLOW_ORIGINS` | `["http://localhost:3000", "http://localhost:5173", ...]` | `[]` (empty) | Must be explicitly configured for production |
| `CORS_ALLOW_CREDENTIALS` | `true` | `false` | Enable only if your frontend needs cookies |
| `CORS_ALLOW_METHODS` | All standard methods | Same | |
| `CORS_ALLOW_HEADERS` | `Authorization`, `Content-Type`, `Accept`, `Origin`, `X-CSRF-Token` | Same | `X-CSRF-Token` is required for CSRF |

In development, if `CORS_ALLOW_ORIGINS` is not set and `DEBUG=true`, common localhost origins are automatically added. In production, you must set origins explicitly — an empty list blocks all cross-origin requests.

Djast validates that `CORS_ALLOW_ORIGINS=["*"]` cannot be combined with `CORS_ALLOW_CREDENTIALS=true` (this is insecure and browsers reject it).

---

**OAuth security**

OAuth providers (Google, GitHub) are disabled by default. Each provider requires explicit opt-in via settings.

**State token CSRF protection**: Every authorization request generates a 32-byte cryptographic state token, stored in Redis with a 5-minute TTL. The callback validates and consumes this token (single-use) to prevent CSRF and replay attacks.

**Authorization code exchange**: After the OAuth callback, tokens are not placed in the redirect URL. Instead:
1. Tokens are stored behind a one-time authorization code in Redis (TTL: `OAUTH_CODE_TTL`, default 60 seconds)
2. The redirect URL contains only the code: `?code={one-time-code}`
3. The frontend exchanges the code via `POST /auth/oauth/token`
4. The code is deleted from Redis after use (single-use)

This prevents token leakage via browser history, referrer headers, or server logs.

**Auto-linking by email**: If a user signs up with `alice@example.com` via password, and later signs in with Google using the same email, the accounts are automatically linked. This is convenient but means you trust the email verified by the OAuth provider. A future email verification feature will add an additional confirmation step.

---

**Database security**

- All queries use SQLAlchemy ORM with parameterized statements (prevents SQL injection)
- Session lifecycle is managed by the `get_async_session` dependency (auto-commit on success, auto-rollback on exception)
- Connection pooling for PostgreSQL: 20 connections + 10 overflow, with pre-ping health checks
- Database credentials are read from environment variables, never hardcoded

---

**Security configuration reference**

All settings are in `app/djast/settings.py`, overridable via environment variables.

| Setting | Default | Description |
|---------|---------|-------------|
| `DEBUG` | `true` | Development mode — controls cookies, CORS, logging |
| `SECRET_KEY` | *(hardcoded dev value)* | JWT signing key. **Must be unique and secret in production** |
| `CSRF_ENABLED` | `true` | Enable CSRF double-submit cookie protection |
| `CSRF_COOKIE_NAME` | `"csrf_token"` | Name of the CSRF cookie |
| `CSRF_HEADER_NAME` | `"X-CSRF-Token"` | Expected header name for CSRF token |
| `CSRF_TOKEN_LENGTH` | `32` | Byte length of generated CSRF tokens |
| `ACCOUNT_LOGIN_MAX_ATTEMPTS` | `5` | Failed logins before lockout (0 = disabled) |
| `ACCOUNT_LOGIN_LOCKOUT_SECONDS` | `300` | Lockout duration in seconds |
| `ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN` | `true` | Allow login when Redis is unavailable |
| `FALLBACK_IS_BLACKLISTED` | `true` | Treat tokens as blacklisted when Redis is down |
| `PASSWORD_VALIDATION_REGEX` | *(8-100 chars, mixed case, digit, special)* | Password strength regex |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `REFRESH_TOKEN_REUSE_GRACE_SECONDS` | `5` | Grace period for concurrent refresh requests |
| `OAUTH_CODE_TTL` | `60` | One-time OAuth authorization code TTL (seconds) |

---

**Production checklist**

Before deploying to production, verify the following:

- [ ] `DEBUG=false`
- [ ] `SECRET_KEY` is a unique, randomly generated string (50+ characters)
- [ ] `CORS_ALLOW_ORIGINS` is set to your specific frontend domain(s)
- [ ] `CORS_ALLOW_CREDENTIALS` is set appropriately (`true` only if frontend sends cookies)
- [ ] Database is PostgreSQL (not SQLite)
- [ ] Redis is running and accessible (required for rate limiting, token blacklist, brute force protection)
- [ ] HTTPS is configured (required for `Secure` cookies)
- [ ] `OAUTH_LOGIN_REDIRECT_URL` points to your production frontend (if using OAuth)
- [ ] OAuth client secrets are set via environment variables (never committed to source)
- [ ] Rate limits are adjusted for expected traffic
- [ ] `ACCOUNT_LOGIN_LOCKOUT_FAIL_OPEN` matches your availability vs security priority
- [ ] `FALLBACK_IS_BLACKLISTED` matches your availability vs security priority
