"""Auto-discovery of app-level hooks."""
from __future__ import annotations

import importlib
import logging
from collections.abc import Callable

from djast.settings import ROOT_DIR

logger = logging.getLogger(__name__)

SKIP_DIRS = {"djast", "__pycache__", "migrations", "templates"}


def discover_setup_hooks() -> list[Callable[..., None]]:
    """Scan app directories for setup_app() hooks.

    Looks for a ``setup_app`` callable in each top-level package's
    ``__init__.py``. Packages listed in ``SKIP_DIRS`` are ignored.
    """
    hooks: list[Callable[..., None]] = []
    for init_file in sorted(ROOT_DIR.glob("*/__init__.py")):
        package_name = init_file.parent.name
        if package_name in SKIP_DIRS:
            continue
        try:
            module = importlib.import_module(package_name)
        except Exception:
            logger.warning(
                "Failed to import %s for setup_app discovery",
                package_name, exc_info=True,
            )
            continue
        hook = getattr(module, "setup_app", None)
        if callable(hook):
            hooks.append(hook)
    return hooks
