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

    REDIS_URL: str = "redis://redis:6379/1"
    RATE_LIMIT_REDIS_URL: str = "redis://redis:6379/2"

    # Auth & Security settings ================================================
    PASSWORD_HASHER: str = "pbkdf2_sha256"
    SECRET_KEY: str = "2+^*y!+gh)!w_ef$bn#*hal2tr#1+e_&iho)&c$fjs-u1n3=j6"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    # Allow a short window where a refresh token that was just rotated may be
    # presented again (e.g., concurrent requests / retries). Within this
    # window, the server treats it as a duplicate and returns the replacement
    # refresh token.
    REFRESH_TOKEN_REUSE_GRACE_SECONDS: int = 5
    # What is_blacklisted should return if the blacklist system is down.
    FALLBACK_IS_BLACKLISTED: bool = True
    ALLOW_SIGNUP: bool = True

    # Regex for password strength validation:
    # At least 8 characters and up to 100, one uppercase, one lowercase,
    # one number and one special character
    PASSWORD_VALIDATION_REGEX: str = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,100}$"

    # Choose between 'django' and 'email' user models. Default is 'django'
    # which is compatible with Django's default users uses username for
    # authentication.
    # !! IMPORTANT !! This setting will change the table for the User model.
    AUTH_USER_MODEL_TYPE: str = "django"  # or "email"

    # CORS defaults
    # - Developer-friendly in DEBUG (permits common localhost front-ends (see model_post_init))
    # - Locked down in production unless explicitly configured
    CORS_ALLOW_ORIGINS: list[str] = []
    CORS_ALLOW_METHODS: list[str] = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ]
    CORS_ALLOW_HEADERS: list[str] = [
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
    ]
    CORS_ALLOW_CREDENTIALS: bool = True
    # /Auth & Security settings ===============================================

    # Auth Rate Limits
    AUTH_RATE_LIMIT_SIGNUP: str = "5/minute"
    AUTH_RATE_LIMIT_LOGIN: str = "5/minute"
    AUTH_RATE_LIMIT_REFRESH: str = "20/minute"
    AUTH_RATE_LIMIT_CHANGE_PASSWORD: str = "3/minute"
    AUTH_RATE_LIMIT_REVOKE: str = "20/minute"
    AUTH_RATE_LIMIT_USER_ME: str = "100/minute"

    def model_post_init(self, __context) -> None:
        # If the user didn't explicitly configure origins, provide safe defaults.
        if "CORS_ALLOW_ORIGINS" not in getattr(self, "model_fields_set", set()):
            if self.DEBUG:
                self.CORS_ALLOW_ORIGINS = [
                    "http://localhost",
                    "http://localhost:3000",
                    "http://localhost:5173",
                    "http://127.0.0.1",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:5173",
                    "https://localhost",
                    "https://localhost:3000",
                    "https://localhost:5173",
                    "https://127.0.0.1",
                    "https://127.0.0.1:3000",
                    "https://127.0.0.1:5173",
                ]
            else:
                self.CORS_ALLOW_ORIGINS = []

        if self.CORS_ALLOW_CREDENTIALS and any(origin == "*" for origin in self.CORS_ALLOW_ORIGINS):
            raise ValueError(
                "Invalid CORS config: CORS_ALLOW_ORIGINS cannot contain '*' when CORS_ALLOW_CREDENTIALS is True."
            )

settings = Settings()
