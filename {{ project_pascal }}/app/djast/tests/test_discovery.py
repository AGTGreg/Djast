"""Tests for setup_app() hook discovery."""
from __future__ import annotations

import types
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from djast.utils.discovery import discover_setup_hooks, SKIP_DIRS


def _fake_init(name: str) -> Path:
    """Create a fake __init__.py path for testing."""
    return Path(f"/fake/{name}/__init__.py")


def test_discovers_setup_app_hook():
    """Modules with a setup_app callable are discovered."""
    hook_fn = MagicMock()
    module = types.ModuleType("myapp")
    module.setup_app = hook_fn

    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        mock_root.glob.return_value = [_fake_init("myapp")]
        with patch("djast.utils.discovery.importlib.import_module", return_value=module):
            hooks = discover_setup_hooks()

    assert hooks == [hook_fn]


def test_skips_module_without_setup_app():
    """Modules without setup_app are silently skipped."""
    module = types.ModuleType("myapp")

    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        mock_root.glob.return_value = [_fake_init("myapp")]
        with patch("djast.utils.discovery.importlib.import_module", return_value=module):
            hooks = discover_setup_hooks()

    assert hooks == []


def test_skips_djast_directory():
    """The djast package itself is excluded from discovery."""
    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        mock_root.glob.return_value = [_fake_init("djast")]
        with patch("djast.utils.discovery.importlib.import_module") as mock_import:
            hooks = discover_setup_hooks()

    assert hooks == []
    mock_import.assert_not_called()


def test_skips_all_skip_dirs():
    """All directories in SKIP_DIRS are excluded."""
    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        mock_root.glob.return_value = [_fake_init(d) for d in SKIP_DIRS]
        with patch("djast.utils.discovery.importlib.import_module") as mock_import:
            hooks = discover_setup_hooks()

    assert hooks == []
    mock_import.assert_not_called()


def test_handles_import_error_gracefully():
    """Import errors are logged and skipped, not raised."""
    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        mock_root.glob.return_value = [_fake_init("broken_app")]
        with patch(
            "djast.utils.discovery.importlib.import_module",
            side_effect=ImportError("no module"),
        ):
            hooks = discover_setup_hooks()

    assert hooks == []


def test_discovers_multiple_hooks_in_order():
    """Multiple hooks are returned in sorted directory order."""
    hook_a = MagicMock()
    hook_b = MagicMock()

    module_a = types.ModuleType("alpha")
    module_a.setup_app = hook_a
    module_b = types.ModuleType("beta")
    module_b.setup_app = hook_b

    def import_side_effect(name):
        return {"alpha": module_a, "beta": module_b}[name]

    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        # Deliberately unsorted to verify sorted() is applied
        mock_root.glob.return_value = [_fake_init("beta"), _fake_init("alpha")]
        with patch(
            "djast.utils.discovery.importlib.import_module",
            side_effect=import_side_effect,
        ):
            hooks = discover_setup_hooks()

    assert hooks == [hook_a, hook_b]


def test_skips_non_callable_setup_app():
    """A setup_app attribute that isn't callable is ignored."""
    module = types.ModuleType("myapp")
    module.setup_app = "not a function"

    with patch("djast.utils.discovery.ROOT_DIR") as mock_root:
        mock_root.glob.return_value = [_fake_init("myapp")]
        with patch("djast.utils.discovery.importlib.import_module", return_value=module):
            hooks = discover_setup_hooks()

    assert hooks == []
