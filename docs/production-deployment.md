# Production Deployment

Djast ships with a production-ready Docker Compose setup: Granian ASGI server, Nginx reverse proxy with SSL, PostgreSQL, Redis, and TaskIQ workers. Everything runs with a single `docker compose up`.

**Files:** `docker-compose.prod.yml`, `prod.env.example`, `nginx/nginx.conf`, `nginx/Dockerfile`, `app/Dockerfile`, `app/djast/health.py`

---

## Architecture

```text
                    Internet
                       |
                  [ Nginx :443 ]
                  SSL termination
                  Static files
                  Security headers
                       |
               [ Granian :8000 ]
               FastAPI application
              /        |        \
    [ PostgreSQL ]  [ Redis ]  [ TaskIQ Workers ]
       Database     Sessions     Background jobs
                    Rate limits
                    Task broker
```

| Service | Role | Image |
|---------|------|-------|
| **nginx** | Reverse proxy, SSL, static/media files | `nginx:1.27-alpine` |
| **app** | FastAPI via Granian | Built from `app/Dockerfile` |
| **postgres** | Database | `postgres:17-alpine` |
| **redis** | Sessions, rate limiting, task broker, results | `redis:8.0-alpine` |
| **taskiq-worker** | Background task processing | Built from `app/Dockerfile` |
| **taskiq-scheduler** | Cron-scheduled tasks | Built from `app/Dockerfile` |

---

## Quick Start

### 1. Create your environment file

```bash
cp prod.env.example prod.env
```

Edit `prod.env` and fill in:
- `SECRET_KEY` — generate one: `python -c "import secrets; print(secrets.token_urlsafe(64))"`
- `DB_PASSWORD` and `POSTGRES_PASSWORD` — same value, strong password
- `CORS_ALLOW_ORIGINS` — your frontend domain(s)
- Email settings if using SMTP

### 2. Add SSL certificates

Place your certificates in the `nginx/ssl/` directory:

```bash
mkdir -p nginx/ssl
cp /path/to/your/cert.pem nginx/ssl/cert.pem
cp /path/to/your/key.pem nginx/ssl/key.pem
```

The Nginx config expects `cert.pem` and `key.pem` at these exact paths. Use certificates from Let's Encrypt (Certbot), Cloudflare Origin, or any other provider.

### 3. Build and start

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### 4. Run migrations

```bash
docker compose -f docker-compose.prod.yml exec app python manage.py migrate
```

### 5. Create an admin user (optional)

```bash
docker compose -f docker-compose.prod.yml exec app python manage.py createsuperuser
```

### 6. Verify

```bash
# Health check (via Nginx)
curl -k https://localhost/health

# Readiness check (database + Redis)
curl -k https://localhost/health/ready
```

---

## Health Checks

Two endpoints are mounted at the root level (outside `/api/v1` and rate limiting):

| Endpoint | Purpose | Checks | Success | Failure |
|----------|---------|--------|---------|---------|
| `GET /health` | Liveness probe | App is responding | 200 `{"status": "ok"}` | N/A (if app is down, no response) |
| `GET /health/ready` | Readiness probe | App + Database + Redis | 200 `{"status": "ok", "database": "ok", "redis": "ok"}` | 503 with per-service status |

Docker Compose uses the liveness endpoint to determine when the app is ready before Nginx starts accepting traffic. The readiness endpoint is available for external monitoring systems.

---

## Services

### Granian (ASGI Server)

The app runs on [Granian](https://github.com/emmett-framework/granian), a Rust-based ASGI server. It was chosen over Uvicorn and Gunicorn for production because:

- **Worker management** — automatic crash recovery with crash loop detection, memory-based recycling (`--workers-max-rss`), lifetime-based recycling (`--workers-lifetime`), and configurable kill timeout for hung workers.
- **WebSocket/SSE performance** — ~1.7x Uvicorn's throughput for WebSocket workloads. Stays stable at high concurrency.
- **Backpressure** — built-in mechanism that stops accepting new connections when the app can't keep up, preventing overload cascades.
- **Low overhead** — ~15MB per worker vs ~20MB for Uvicorn, ~30MB for Gunicorn.

The default Dockerfile command runs 2 workers with uvloop:

```dockerfile
CMD ["granian", "main:app", "--interface", "asgi", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--loop", "uvloop"]
```

Adjust `--workers` based on your CPU cores. A good starting point is 1 worker per core.

#### Testing with Granian locally

The dev `docker-compose.yaml` includes a commented Granian command. Uncomment it to test with the production server:

```yaml
# command: ["granian", "main:app", "--interface", "asgi", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

### Nginx

Handles SSL termination, static file serving, reverse proxying, and security headers.

**SSL/TLS:**
- TLS 1.2 and 1.3 with modern cipher suite
- Certificates mounted from `nginx/ssl/` (bind mount, read-only)
- HTTP (port 80) redirects to HTTPS (port 443)

**Static and media files:**
- `/static/` served directly from the shared volume with 30-day cache and `immutable` header
- `/media/` served directly with 7-day cache
- Files never touch the Python app — Nginx serves them from disk

**Proxying:**
- WebSocket support via `Upgrade` header detection
- SSE support via `proxy_buffering off` (events stream immediately)
- `proxy_read_timeout 86400s` for long-lived connections

**Security headers:**
- `Strict-Transport-Security` (HSTS, 1 year)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`

**Gzip compression** is enabled for text, CSS, JSON, and JavaScript. SSE (`text/event-stream`) is not compressed — compression breaks event streaming.

### PostgreSQL

Production database. Credentials are set in `prod.env` — both `DB_*` variables (for the app) and `POSTGRES_*` variables (for the container) must match. Data is persisted in the `postgres_data` named volume.

### Redis

Used for four purposes, each on a separate database:

| DB | Purpose | Setting |
|----|---------|---------|
| 1 | Sessions, token blacklist, brute-force tracking | `REDIS_URL` |
| 2 | Rate limit counters | `RATE_LIMIT_REDIS_URL` |
| 3 | TaskIQ broker (task queue) | `TASKIQ_BROKER_URL` |
| 4 | TaskIQ result backend | `TASKIQ_RESULT_BACKEND_URL` |

Redis runs with append-only persistence and a 256MB memory limit with LRU eviction. Data is persisted in the `redis_data` named volume.

---

## Proxy Headers

Granian does not automatically trust `X-Forwarded-For` / `X-Forwarded-Proto` headers. In production mode (`DEBUG=false`), the app wraps itself with Granian's proxy headers middleware:

```python
# main.py (applied automatically)
from granian.utils.proxies import wrap_asgi_with_proxy_headers
app = wrap_asgi_with_proxy_headers(app, trusted_hosts=settings.PROXY_TRUSTED_HOSTS)
```

The default `PROXY_TRUSTED_HOSTS="*"` is safe because port 8000 is only exposed internally (Nginx is the only service that can reach it). If you expose the app port directly, restrict this to your proxy's IP or CIDR.

---

## Scaling

Scale the app horizontally with Docker Compose replicas:

```bash
docker compose -f docker-compose.prod.yml up --scale app=4 -d
```

Nginx automatically load-balances across all app replicas. Each replica runs its own Granian workers, so with `--workers 2` and 4 replicas you get 8 total workers.

TaskIQ workers can also be scaled independently:

```bash
docker compose -f docker-compose.prod.yml up --scale taskiq-worker=3 -d
```

---

## Resource Limits

Default memory limits per service:

| Service | Memory |
|---------|--------|
| app | 512 MB |
| postgres | 512 MB |
| redis | 512 MB |
| taskiq-worker | 512 MB |
| taskiq-scheduler | 256 MB |
| nginx | 128 MB |

Adjust in `docker-compose.prod.yml` under `deploy.resources.limits`.

---

## Volumes

| Volume | Purpose | Shared with |
|--------|---------|-------------|
| `postgres_data` | PostgreSQL data | postgres only |
| `redis_data` | Redis AOF persistence | redis only |
| `app_static` | Static files (`/vol/app/static/`) | app, nginx (read-only) |
| `app_media` | Uploaded media (`/vol/app/media/`) | app, nginx (read-only) |
| `app_logs` | Application logs (`/vol/app/logs/`) | app, workers |

---

## Environment Reference

See `prod.env.example` for the full list with comments. Key settings:

| Setting | Required | Description |
|---------|----------|-------------|
| `SECRET_KEY` | Yes | JWT signing key (50+ random characters) |
| `DB_PASSWORD` / `POSTGRES_PASSWORD` | Yes | Database password (must match) |
| `CORS_ALLOW_ORIGINS` | Yes | Frontend domain(s) as JSON list |
| `EMAIL_BACKEND` | If sending email | SMTP backend path |
| `EMAIL_HOST` / `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD` | If sending email | SMTP credentials |
| `PROXY_TRUSTED_HOSTS` | No (default: `"*"`) | Restrict proxy header trust |

For the full security checklist, see [Security: Production Checklist](security.md#production-checklist).

---

## Differences from Development

| Aspect | Development (`docker-compose.yaml`) | Production (`docker-compose.prod.yml`) |
|--------|--------------------------------------|----------------------------------------|
| ASGI server | `fastapi dev` (Uvicorn with hot-reload) | Granian (2 workers, uvloop) |
| Database | SQLite (file-based) | PostgreSQL |
| Code delivery | Volume mount (`./app:/app`) | Baked into Docker image (`COPY`) |
| Reverse proxy | None (direct access on port 8001) | Nginx with SSL |
| Static files | Served by FastAPI | Served by Nginx |
| TaskIQ workers | `--reload` flag | No reload |
| Restart policy | None | `unless-stopped` on all services |
| Health checks | None | All services have health checks |
| SSL | None | TLS 1.2+1.3 |
