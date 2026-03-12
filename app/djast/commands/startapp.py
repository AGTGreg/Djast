"""Scaffold a new app module."""

import keyword
import shutil

from djast.settings import ROOT_DIR


def _is_valid_module_name(name: str) -> bool:
    """Check if the name is a valid Python module name."""
    return name.isidentifier() and not keyword.iskeyword(name)


def run(module_name: str) -> None:
    if not module_name:
        print("Error: Module name is required.")
        return

    if not _is_valid_module_name(module_name):
        print(f"Error: '{module_name}' is not a valid Python module name.")
        print("Must be a valid identifier and not a reserved keyword.")
        return

    app_dir = ROOT_DIR
    template_dir = app_dir / "djast" / "templates" / "module"

    if (app_dir / module_name).exists():
        print(f"Error: Module '{module_name}' already exists.")
        return

    new_module_dir = app_dir / module_name

    print(f"Creating module '{module_name}'...")

    try:
        shutil.copytree(template_dir, new_module_dir)
        print(f"Module '{module_name}' created successfully.")
        print("Don't forget to register your new router in djast/urls.py!")
    except Exception as e:
        print(f"Error creating module: {e}")
