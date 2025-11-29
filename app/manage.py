#!/usr/bin/env python
import sys
import importlib
import pkgutil
from pathlib import Path

# Add the project root to python path
sys.path.append(str(Path(__file__).resolve().parent.parent))


def get_available_commands():
    helpers_path = Path(__file__).resolve().parent / "djast" / "commands"
    commands = []
    if helpers_path.exists():
        for _, name, _ in pkgutil.iter_modules([str(helpers_path)]):
            commands.append(name)
    return sorted(commands)


def main():
    available_commands = get_available_commands()

    if len(sys.argv) < 2:
        print("Usage: python manage.py <command> [options]")
        print("Available commands:")
        for cmd in available_commands:
            print(f"  {cmd}")
        sys.exit(1)

    command_name = sys.argv[1]
    args = sys.argv[2:]

    if command_name not in available_commands:
        print(f"Unknown command: '{command_name}'")
        print("Available commands:")
        for cmd in available_commands:
            print(f"  {cmd}")
        sys.exit(1)

    try:
        # Dynamically import the module
        module = importlib.import_module(f"djast.commands.{command_name}")

        # Check if the module has a 'run' function
        if hasattr(module, "run"):
            module.run(*args)
        else:
            print(f"Error: Module 'djast.commands.{command_name}' does not have a 'run' function.")
            sys.exit(1)

    except TypeError as e:
        # This catches arguments mismatch for the run function
        print(f"Error executing command '{command_name}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while running command '{command_name}': {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
