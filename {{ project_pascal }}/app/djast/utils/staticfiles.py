"""SPA-aware static file serving."""
from starlette.exceptions import HTTPException
from starlette.staticfiles import StaticFiles


class SPAStaticFiles(StaticFiles):
    """StaticFiles subclass that falls back to index.html for unknown paths.

    Inherits all StaticFiles features: etag, 304 Not Modified, content-length,
    path traversal protection.

    Example::

        app.mount("/admin", SPAStaticFiles(directory="admin/frontend/build_output", html=True))
    """

    async def get_response(self, path: str, scope) -> object:
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise
