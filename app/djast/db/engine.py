from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from djast.settings import ROOT_DIR


class DatabaseConfig:
    def get_url(self, config: dict[str, Any]) -> str | URL:
        raise NotImplementedError

    def get_engine_options(self, config: dict[str, Any]) -> dict[str, Any]:
        return {}


class SqliteConfig(DatabaseConfig):
    def get_url(self, config: dict[str, Any]) -> str | URL:
        path = config.get("NAME")
        if not path:
            raise ValueError("SQLite database name (path) is required")

        if isinstance(path, str):
            path = Path(path)

        if not path.is_absolute():
            path = ROOT_DIR / path

        # Ensure directory exists
        path.parent.mkdir(parents=True, exist_ok=True)

        return f"sqlite+aiosqlite:///{path}"

    def get_engine_options(self, config: dict[str, Any]) -> dict[str, Any]:
        # Note: aiosqlite uses NullPool by default, which doesn't support
        # pool_size or max_overflow. NullPool opens/closes connections per
        # operation, which is appropriate for SQLite's file-locking model.
        return {"future": True}


class PostgresConfig(DatabaseConfig):
    def get_url(self, config: dict[str, Any]) -> str | URL:
        return URL.create(
            drivername="postgresql+asyncpg",
            username=config.get("USER"),
            password=config.get("PASSWORD"),
            host=config.get("HOST"),
            port=config.get("PORT"),
            database=config.get("NAME"),
        )

    def get_engine_options(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "future": True,
            "pool_pre_ping": True,
            "pool_size": config.get("POOL_SIZE", 20),
            "max_overflow": config.get("MAX_OVERFLOW", 10)
        }


ENGINES = {
    "sqlite": SqliteConfig(),
    "postgres": PostgresConfig(),
    "postgresql": PostgresConfig(),
}


def build_engine(db_config: dict[str, Any], echo: bool = False) -> AsyncEngine:
    engine_type = db_config.get("ENGINE")
    if engine_type not in ENGINES:
        raise ValueError(f"Unsupported engine: {engine_type}")

    config_handler = ENGINES[engine_type]
    url = config_handler.get_url(db_config)
    options = config_handler.get_engine_options(db_config)
    options["echo"] = echo

    if "OPTIONS" in db_config:
        options.update(db_config["OPTIONS"])

    return create_async_engine(url, **options)
