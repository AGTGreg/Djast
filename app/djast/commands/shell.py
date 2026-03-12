"""Launch interactive Python shell with auto-imports."""

import asyncio
import importlib
from contextlib import asynccontextmanager
from typing import Any

from djast.settings import settings, ROOT_DIR
from djast.database import async_session_factory, engine
from djast.db import models


@asynccontextmanager
async def auto_session():
    """Async context manager that auto-commits on success, rolls back on error."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def discover_apps() -> dict[str, Any]:
    """
    Auto-discover all apps with models.py files in the project.

    Scans the app directory for top-level models.py files (excluding djast/),
    imports the models module for each app, and returns a dictionary mapping
    app names to their models module.

    Returns:
        A dictionary mapping app names to their models module.
    """
    discovered_apps: dict[str, Any] = {}
    app_dir = ROOT_DIR

    for models_file in app_dir.glob("*/models.py"):
        relative_path = models_file.relative_to(app_dir)

        if relative_path.parts[0] == "djast":
            continue

        module_parts = list(relative_path.with_suffix("").parts)
        module_name = ".".join(module_parts)

        try:
            module = importlib.import_module(module_name)

            if len(module_parts) >= 2:
                app_name = module_parts[-2]
                discovered_apps[app_name] = module

        except Exception as e:
            print(f"Warning: Could not import {module_name}: {e}")

    return discovered_apps


def print_banner(
    namespace: dict[str, Any], apps_dict: dict[str, Any]
) -> None:
    """Print a startup banner showing available imports."""
    print("\n" + "=" * 60)
    print("Djast Interactive Shell")
    print("=" * 60)

    print("\nAvailable imports:")
    print("-" * 40)

    # Apps
    if apps_dict:
        app_names = ", ".join(sorted(apps_dict.keys()))
        print(f"  Apps:          {app_names}")
    else:
        print("  Apps:         (none discovered)")

    # Core utilities
    print("  Session:       session (async session)")
    print("  Auto session:  auto_session (auto-commit context manager)")
    print("  Engine:        engine (SQLAlchemy async engine)")
    print("  Settings:      settings")
    print("  Base:          models.Model, models.Base")

    print("-" * 40)

    # Usage hints
    print("\nUsage examples:")
    print("  # Using auto_session (auto-commits on success):")
    print("  async with auto_session() as s:")
    print("      post = await myapp.Post.objects(s).create(title='Test')")
    print("")
    print("  # Using session (manual commit):")
    print("  posts = await myapp.Post.objects(session).all()")
    print("  await session.commit()")

    print("=" * 60 + "\n")


def start_ipython_shell(namespace: dict[str, Any]) -> None:
    """Start an IPython shell with the given namespace."""
    try:
        from IPython import start_ipython
        from traitlets.config import Config

        config = Config()
        config.InteractiveShellApp.exec_lines = [
            "%autoawait asyncio",
        ]
        config.TerminalInteractiveShell.banner1 = ""
        config.TerminalInteractiveShell.banner2 = ""

        start_ipython(argv=[], user_ns=namespace, config=config)

    except ImportError:
        print("Error: IPython is required for the shell command.")
        print("Install it with: pip install ipython")
        raise SystemExit(1)


def run() -> None:
    """
    Main entry point for the shell command.

    Discovers apps, sets up the namespace with useful imports,
    and launches an interactive IPython shell.
    """
    discovered_apps = discover_apps()

    session = async_session_factory()

    namespace: dict[str, Any] = {
        "session": session,
        "auto_session": auto_session,
        "async_session_factory": async_session_factory,
        "engine": engine,
        "settings": settings,
        "models": models,
        "asyncio": asyncio,
    }

    namespace.update(discovered_apps)

    print_banner(namespace, discovered_apps)

    try:
        start_ipython_shell(namespace)
    finally:
        async def cleanup():
            await session.close()
            await engine.dispose()

        try:
            asyncio.run(cleanup())
        except RuntimeError:
            pass
