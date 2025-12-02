from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings


ROOT_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    PROJECT_NAME: str = "Djast"
    VERSION: str = "0.1.0"
    APP_PREFIX: str = "/api/v1"

    SECRET_KEY: str = "your-secret-key"

    DEBUG: bool = True
    TIME_ZONE: str = "UTC"

    # Edit this in production to restrict CORS origins
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True

    # PostgreSQL example
    # DATABASES: dict = {
    #     "default": {
    #         "ENGINE": "postgresql+asyncpg",
    #         "HOST": "localhost",
    #         "PORT": 5432,
    #         "NAME": "mydatabase",
    #         "USER": "myuser",
    #         "PASSWORD": "mypassword",
    #     }
    # }
    DATABASES: dict = {
        "default": {
            "ENGINE": "sqlite",
            "NAME": ROOT_DIR / "data.db",
        }
    }

    # Password hashing: 'pbkdf2_sha256', 'pbkdf2_sha1', or 'argon2'
    PASSWORD_HASHER: str = "pbkdf2_sha256"


settings = Settings()
