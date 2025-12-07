from __future__ import annotations

import os

from pathlib import Path

from pydantic_settings import BaseSettings


ROOT_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    PROJECT_NAME: str = "Djast"
    VERSION: str = "0.1.0"
    APP_PREFIX: str = "/api/v1"

    DEBUG: bool = True
    TIME_ZONE: str = "UTC"

    # Auth & Security settings
    PASSWORD_HASHER: str = "pbkdf2_sha256"
    SECRET_KEY: str = "change_me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Edit this in production to restrict CORS origins
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True

    DATABASES: dict = {
        "default": {
            "ENGINE": os.getenv("DB_ENGINE", "sqlite"),
            "HOST": os.getenv("DB_HOST", None),
            "PORT": os.getenv("DB_PORT", None),
            "NAME": os.getenv("DB_NAME", "db.sqlite3"),
            "USER": os.getenv("DB_USER", None),
            "PASSWORD": os.getenv("DB_PASSWORD", None),
        }
    }

settings = Settings()
