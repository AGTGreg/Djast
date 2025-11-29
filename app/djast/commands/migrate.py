from alembic.config import Config
from alembic import command

from djast.settings import ROOT_DIR


def run():
    alembic_ini = ROOT_DIR / "alembic.ini"
    migrations_dir = ROOT_DIR / "migrations"

    if not alembic_ini.exists():
        print("Alembic not initialized. Run makemigrations first.")
        return

    print("Running migrations...")
    alembic_cfg = Config(str(alembic_ini))
    alembic_cfg.set_main_option("script_location", str(migrations_dir))

    command.upgrade(alembic_cfg, "head")
