"""Admin panel — schema-driven back office for staff users."""
from pathlib import Path

from fastapi import FastAPI


def setup_app(app: FastAPI) -> None:
    """Mount the admin SPA frontend."""
    dist_dir = Path(__file__).parent / "frontend" / "dist"
    if not dist_dir.exists():
        return

    from djast.utils.staticfiles import SPAStaticFiles

    app.mount(
        "/admin",
        SPAStaticFiles(directory=str(dist_dir), html=True),
        name="admin-spa",
    )
