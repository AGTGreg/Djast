import asyncio
from logging.config import fileConfig
import sys
import importlib

from sqlalchemy.engine import Connection
from alembic import context

from djast.settings import settings, ROOT_DIR
from djast.db.models import Base
from djast.db.engine import ENGINES

# Ensure app dir is in path
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import all models
def load_models():
    for models_file in ROOT_DIR.rglob("models.py"):
        relative_path = models_file.relative_to(ROOT_DIR)
        if str(relative_path).startswith("djast"):
            continue
        module_parts = list(relative_path.with_suffix("").parts)
        module_name = ".".join(module_parts)
        try:
            importlib.import_module(module_name)
        except Exception as e:
            print(f"Failed to import {module_name}: {e}")

load_models()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

def get_url():
    db_config = settings.DATABASES["default"]
    engine_type = db_config.get("ENGINE")
    if engine_type in ENGINES:
        return str(ENGINES[engine_type].get_url(db_config))
    return ""

def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=url.startswith("sqlite"),
    )

    with context.begin_transaction():
        context.run_migrations()

async def run_migrations_online() -> None:
    from djast.db.engine import build_engine

    connectable = build_engine(settings.DATABASES["default"])

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()

def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
    )

    with context.begin_transaction():
        context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())