"""Create a superuser with is_superuser=True and is_staff=True."""

import asyncio
import getpass

from djast.settings import settings
from djast.database import async_session_factory, engine


def _prompt_django_fields() -> dict:
    """Prompt for Django user fields (username, email, password)."""
    username = input("Username: ").strip()
    if not username:
        print("Error: Username cannot be blank.")
        raise SystemExit(1)

    email = input("Email (optional): ").strip()

    password = getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Password (again): ")

    if password != password_confirm:
        print("Error: Passwords do not match.")
        raise SystemExit(1)

    fields = {"username": username}
    if email:
        fields["email"] = email
    return {**fields, "password": password}


def _prompt_email_fields() -> dict:
    """Prompt for Email user fields (email, password)."""
    email = input("Email: ").strip()
    if not email:
        print("Error: Email cannot be blank.")
        raise SystemExit(1)

    password = getpass.getpass("Password: ")
    password_confirm = getpass.getpass("Password (again): ")

    if password != password_confirm:
        print("Error: Passwords do not match.")
        raise SystemExit(1)

    return {"email": email, "password": password}


async def _create_superuser(fields: dict) -> None:
    """Create a superuser in the database."""
    from auth.models import User

    password = fields.pop("password")

    try:
        async with async_session_factory() as session:
            try:
                user = await User.create_user(
                    session,
                    password=password,
                    is_superuser=True,
                    is_staff=True,
                    **fields,
                )
                await session.commit()
                identifier = getattr(user, User.USERNAME_FIELD)
                print(f"Superuser '{identifier}' created successfully.")
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    finally:
        await engine.dispose()


def run() -> None:
    if settings.AUTH_USER_MODEL_TYPE == "email":
        fields = _prompt_email_fields()
    else:
        fields = _prompt_django_fields()

    try:
        asyncio.run(_create_superuser(fields))
    except Exception as e:
        print(f"Error: {e}")
        raise SystemExit(1)
