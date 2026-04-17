"""Admin-specific FastAPI dependencies."""
from __future__ import annotations

from fastapi import Depends, HTTPException

from auth.models import User
from auth.utils.auth_backend import get_current_user


async def get_admin_user(
    user: User = Depends(get_current_user),
) -> User:
    """Require an authenticated staff or superuser."""
    if not (user.is_staff or user.is_superuser):
        raise HTTPException(403, "Admin access required.")
    return user
