# Building an SPA with Djast

Djast supports serving single-page applications (React, Vue, Svelte, etc.) directly from app modules. The admin panel is the reference implementation of this pattern.

## URL Architecture

Djast separates API routes from frontend assets by URL prefix:

- **API routes** live under `APP_PREFIX` (default `/api/v1/`) — registered via routers in `djast/urls.py`
- **SPA frontends** are mounted at their own top-level prefix (e.g., `/admin`) — registered via `setup_app()` in the app's `__init__.py`

These are separate URL namespaces and do not conflict. A request to `/api/v1/admin/schema/` hits the API router. A request to `/admin/` hits the SPA mount.

## How to Serve an SPA from Your App

### 1. Build the SPA

Configure your build tool's base path to match the mount prefix. For example, with Vite:

```js
// vite.config.ts
export default defineConfig({
  base: '/myapp/',
  // ...
})
```

Place the built output in your app directory (e.g., `myapp/frontend/dist/`). The dist directory should contain at minimum an `index.html` file.

### 2. Define `setup_app()` in your app's `__init__.py`

```python
# myapp/__init__.py
from pathlib import Path
from fastapi import FastAPI


def setup_app(app: FastAPI) -> None:
    """Mount the SPA frontend."""
    dist_dir = Path(__file__).parent / "frontend" / "dist"
    if not dist_dir.exists():
        return

    from djast.utils.staticfiles import SPAStaticFiles

    app.mount(
        "/myapp",
        SPAStaticFiles(directory=str(dist_dir), html=True),
        name="myapp-spa",
    )
```

The `setup_app()` hook is auto-discovered by the app factory during startup — no manual registration in `main.py` needed.

### 3. Register your API router as normal

```python
# djast/urls.py
from myapp.views import router as myapp_router

api_router.include_router(myapp_router, prefix="/myapp", tags=["myapp"])
```

API routes go under `APP_PREFIX` (e.g., `/api/v1/myapp/`). The SPA is at `/myapp/`. No conflict.

## How It Works

`SPAStaticFiles` extends Starlette's `StaticFiles` with an SPA fallback:

1. If the requested path matches a real file (JS, CSS, images, fonts), serve it directly
2. If no file matches, return `index.html` for client-side routing

It inherits all `StaticFiles` features:
- **Etag headers** and **304 Not Modified** — browsers skip re-downloading unchanged assets
- **Content-length** and **MIME type detection** — correct headers for all file types
- **Path traversal protection** — resolved paths are validated against the directory root

The `setup_app()` hook gives apps access to the `FastAPI` app instance for operations that require it (like `app.mount()`). Hooks are discovered by scanning app directories for a `setup_app` callable in `__init__.py`.

## Gotchas and Constraints

### 1. No API endpoints under the SPA prefix

The SPA mount claims its entire prefix. You **cannot** have API endpoints, WebSocket connections, or SSE streams at paths under the SPA mount prefix.

If your SPA is mounted at `/myapp`, a request to `/myapp/anything` will be handled by the SPA mount — not by any API route. All API routes must go under `APP_PREFIX` via routers in `urls.py`.

```
/myapp/              → SPA mount serves index.html
/myapp/dashboard     → SPA mount serves index.html (client-side route)
/myapp/assets/app.js → SPA mount serves the JS file
/api/v1/myapp/data   → API router handles this
```

### 2. WebSockets and SSE must use `APP_PREFIX`

`StaticFiles` only handles GET and HEAD requests. A WebSocket upgrade request to a path under the SPA mount will fail. An SSE endpoint under the SPA mount will return `index.html` instead of the event stream.

Define WebSocket and SSE endpoints on your API router under `APP_PREFIX`:

```python
# myapp/views.py
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    ...  # Available at /api/v1/myapp/ws
```

### 3. User uploads and media files need a separate mount

File uploads go through API endpoints (under `APP_PREFIX`). To serve uploaded files, mount a separate `StaticFiles` at a different prefix. Your `setup_app()` hook can mount both:

```python
def setup_app(app: FastAPI) -> None:
    from starlette.staticfiles import StaticFiles
    from djast.utils.staticfiles import SPAStaticFiles

    # SPA frontend
    dist_dir = Path(__file__).parent / "frontend" / "dist"
    if dist_dir.exists():
        app.mount("/myapp", SPAStaticFiles(directory=str(dist_dir), html=True))

    # Uploaded files
    media_dir = Path(__file__).parent / "media"
    if media_dir.exists():
        app.mount("/media/myapp", StaticFiles(directory=str(media_dir)))
```

### 4. The SPA mount prefix must not overlap with `APP_PREFIX`

If `APP_PREFIX` is `/api/v1`, do not mount an SPA at `/api` — the mount could interfere with API routes. SPA mounts should use their own top-level prefix that does not share a path segment with `APP_PREFIX`.

### 5. Multiple SPAs are supported

Each app can mount its own SPA at a different prefix. Prefixes must not overlap with each other or with `APP_PREFIX`:

```
/admin   → admin SPA
/myapp   → myapp SPA
/api/v1/ → all API routes
```

### 6. Production deployment behind NGINX

In production, NGINX should serve static assets directly from the dist directory, bypassing Python entirely. The Python-level SPA serving is a development convenience so the app works out of the box with `fastapi dev main.py`.

Example NGINX config:

```nginx
# Serve SPA static assets directly
location /admin/assets/ {
    alias /path/to/app/admin/frontend/dist/assets/;
    expires 1y;
    add_header Cache-Control "public, immutable";
}

# SPA fallback — serve index.html for client-side routes
location /admin/ {
    try_files $uri /path/to/app/admin/frontend/dist/index.html;
}

# Proxy API requests to Djast
location /api/ {
    proxy_pass http://127.0.0.1:8000;
}
```

## Opting Out

To remove an SPA app: delete the app directory and remove its router from `djast/urls.py`. The `setup_app()` hook is discovered automatically — no other files reference it.

## Reference

The admin panel is the reference implementation:
- `admin/__init__.py` — `setup_app()` hook that mounts `SPAStaticFiles`
- `admin/frontend/` — React + Vite + Tailwind SPA source and built dist
- `admin/views.py` — API endpoints registered under `APP_PREFIX`
