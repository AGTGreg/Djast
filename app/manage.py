#!/usr/bin/env python
import sys
import importlib
import pkgutil
from pathlib import Path

# Add the project root to python path
sys.path.append(str(Path(__file__).resolve().parent.parent))


def get_available_commands() -> dict[str, str]:
    """Return a dict mapping command names to their help text (module docstring)."""
    helpers_path = Path(__file__).resolve().parent / "djast" / "commands"
    commands: dict[str, str] = {}
    if helpers_path.exists():
        for _, name, _ in pkgutil.iter_modules([str(helpers_path)]):
            try:
                module = importlib.import_module(f"djast.commands.{name}")
                commands[name] = (module.__doc__ or "").strip()
            except Exception:
                commands[name] = ""
    return dict(sorted(commands.items()))


def print_help(commands: dict[str, str]) -> None:
    print("Usage: python manage.py <command> [options]")
    print("Available commands:")
    max_name_len = max((len(name) for name in commands), default=0)
    for name, description in commands.items():
        padding = " " * (max_name_len - len(name) + 2)
        if description:
            print(f"  {name}{padding}{description}")
        else:
            print(f"  {name}")


def main():
    available_commands = get_available_commands()

    if len(sys.argv) < 2:
        print_help(available_commands)
        sys.exit(1)

    command_name = sys.argv[1]
    args = sys.argv[2:]

    if command_name not in available_commands:
        print(f"Unknown command: '{command_name}'")
        print_help(available_commands)
        sys.exit(1)

    try:
        module = importlib.import_module(f"djast.commands.{command_name}")

        if hasattr(module, "run"):
            module.run(*args)
        else:
            print(f"Error: Module 'djast.commands.{command_name}' does not have a 'run' function.")
            sys.exit(1)

    except TypeError as e:
        print(f"Error executing command '{command_name}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while running command '{command_name}': {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
