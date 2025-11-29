#!/usr/bin/env python
"""
Django-like interactive shell for FastAPI Boilerplate.

Provides an interactive Python shell with pre-loaded models, database session,
and settings. Supports async operations via IPython's %autoawait.

Usage:
    python manage.py shell

Requires:
    ipython
"""
import asyncio
import importlib
import inspect
from pathlib import Path
from typing import Any

from djast.settings import settings, ROOT_DIR
from djast.database import async_session_factory, engine
from djast.db import models


def discover_apps() -> dict[str, Any]:
    """
    Auto-discover all apps with models.py files in the project.

    Scans the app directory for models.py files (excluding djast/),
    imports the models module for each app, and returns a dictionary mapping
    app names to their models module.

    Returns:
        A dictionary mapping app names to their models module.
    """
    discovered_apps: dict[str, Any] = {}
    app_dir = ROOT_DIR

    # Find all models.py files, excluding djast/
    for models_file in app_dir.rglob("models.py"):
        # Skip djast/ directory (base models, not user models)
        relative_path = models_file.relative_to(app_dir)
        if str(relative_path).startswith("djast"):
            continue

        # Convert file path to module path
        # e.g., app/core/models.py -> core.models
        module_parts = list(relative_path.with_suffix("").parts)
        module_name = ".".join(module_parts)

        try:
            module = importlib.import_module(module_name)

            # Use the directory name as the app name
            # e.g. core/models.py -> core
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
    print("  Engine:        engine (SQLAlchemy async engine)")
    print("  Settings:      settings")
    print("  Base:          models.Model, models.Base")

    print("-" * 40)

    # Usage hints
    print("\nUsage examples:")
    print("  # Create a new post")
    print("  post = await myapp.Post.objects(session).create(title='Test')")
    print("")
    print("  # Get all posts (assuming 'myapp' app has 'Post' model)")
    print("  posts = await myapp.Post.objects(session).all()")
    print("")
    print("")
    print("  # Don't forget to commit if needed")
    print("  await session.commit()")

    print("=" * 60 + "\n")


def start_ipython_shell(namespace: dict[str, Any]) -> None:
    """Start an IPython shell with the given namespace."""
    try:
        from IPython import start_ipython
        from traitlets.config import Config

        # Configure IPython for async support
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
    # Discover all apps from the project
    discovered_apps = discover_apps()

    # Create an async session for convenience
    session = async_session_factory()

    # Build the namespace for the shell
    namespace: dict[str, Any] = {
        # Database utilities
        "session": session,
        "async_session_factory": async_session_factory,
        "engine": engine,
        # Settings
        "settings": settings,
        # Base model classes
        "models": models,
        # Async helpers
        "asyncio": asyncio,
    }

    # Add discovered apps to namespace
    namespace.update(discovered_apps)

    # Print the startup banner
    print_banner(namespace, discovered_apps)

    # Launch IPython shell
    try:
        start_ipython_shell(namespace)
    finally:
        # Clean up: close the session
        async def cleanup():
            await session.close()
            await engine.dispose()

        try:
            asyncio.run(cleanup())
        except RuntimeError:
            # Event loop may already be closed
            pass
        except Exception as e:
            print(f"Warning: Cleanup error: {e}")
