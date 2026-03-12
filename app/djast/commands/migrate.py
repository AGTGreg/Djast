"""Apply pending database migrations."""

from alembic.config import Config
from alembic import command
from alembic.util.exc import CommandError

from djast.settings import ROOT_DIR


def run() -> None:
    alembic_ini = ROOT_DIR / "alembic.ini"
    migrations_dir = ROOT_DIR / "migrations"

    if not alembic_ini.exists():
        print("Alembic not initialized. Run makemigrations first.")
        return

    if not migrations_dir.exists():
        print("Error: migrations/ directory not found. Run makemigrations first.")
        return

    print("Running migrations...")
    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("script_location", str(migrations_dir))

    try:
        command.upgrade(alembic_cfg, "head")
    except CommandError as e:
        print(f"Migration failed: {e}")
        raise SystemExit(1)

    print("Migrations applied successfully.")
