"""Apply pending database migrations."""

from alembic.config import Config
from alembic import command
from alembic.util.exc import CommandError

from djast.settings import ROOT_DIR


def run() -> None:
    alembic_ini = ROOT_DIR / "alembic.ini"
    migrations_dir = ROOT_DIR / "migrations"

    # These must raise, not return. A bare return exits 0, which tells every
    # caller -- entrypoint script, deploy gate, CI step -- that the migration
    # succeeded, and the app then boots against an unmigrated database.
    if not alembic_ini.exists():
        raise SystemExit(
            "Alembic is not initialized: alembic.ini not found.\n"
            "In a container this usually means it was excluded from the image "
            "(check .dockerignore).\n"
            "In a new project, run `python manage.py makemigrations` first."
        )

    if not migrations_dir.exists():
        raise SystemExit(
            "migrations/ directory not found.\n"
            "In a container this usually means it was excluded from the image "
            "(check .dockerignore) or never committed (check .gitignore).\n"
            "In a new project, run `python manage.py makemigrations` first."
        )

    print("Running migrations...")
    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("script_location", str(migrations_dir))

    try:
        command.upgrade(alembic_cfg, "head")
    except CommandError as e:
        print(f"Migration failed: {e}")
        raise SystemExit(1)

    print("Migrations applied successfully.")
