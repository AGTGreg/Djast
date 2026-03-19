"""Generic CRUD operations for any registered admin model."""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from sqlalchemy import delete as sa_delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin.utils.registry import ModelAdminEntry


# ---------------------------------------------------------------------------
# PK helpers
# ---------------------------------------------------------------------------

def _get_pk_col(entry: ModelAdminEntry) -> Any:
    """Return the SQLAlchemy column attribute for the model's primary key."""
    pk_name = entry.pk_field_names[0]
    return getattr(entry.model_class, pk_name)


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def serialize_record(record: Any, entry: ModelAdminEntry) -> dict[str, Any]:
    """Convert a model instance to a dict using the field metadata.

    Always includes the PK value (even if excluded from visible fields)
    so the frontend can identify the record.
    """
    pk_name = entry.pk_field_names[0]
    result: dict[str, Any] = {pk_name: getattr(record, pk_name)}
    for f in entry.fields:
        value = getattr(record, f.name, None)
        if isinstance(value, datetime):
            value = value.isoformat()
        result[f.name] = value
    return result


# ---------------------------------------------------------------------------
# List / Detail
# ---------------------------------------------------------------------------

async def list_records(
    session: AsyncSession,
    entry: ModelAdminEntry,
    *,
    page: int = 1,
    page_size: int = 100,
    search: str | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    """Return a paginated, searchable, sortable list of records."""
    model = entry.model_class

    base = select(model)

    # Search — escape LIKE wildcards so user input is treated literally.
    if search and entry.search_field_names:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        term = f"%{escaped}%"
        conditions = []
        for fname in entry.search_field_names:
            col = getattr(model, fname, None)
            if col is not None:
                conditions.append(col.ilike(term, escape="\\"))
        if conditions:
            base = base.where(or_(*conditions))

    # Count
    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await session.scalar(count_stmt)) or 0

    # Ordering — validate against registered fields to prevent access to
    # excluded columns (e.g. password) or non-column attributes.
    if ordering:
        desc = ordering.startswith("-")
        field_name = ordering.lstrip("-")
        allowed = {f.name for f in entry.fields}
        if field_name in allowed:
            col = getattr(model, field_name, None)
            if col is not None:
                base = base.order_by(col.desc() if desc else col.asc())
        # Invalid ordering is silently ignored — falls through to PK default.
        else:
            base = base.order_by(_get_pk_col(entry).asc())
    else:
        base = base.order_by(_get_pk_col(entry).asc())

    # Pagination
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size
    stmt = base.offset(offset).limit(page_size)

    result = await session.scalars(stmt)
    records = result.all()

    return {
        "count": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "results": [serialize_record(r, entry) for r in records],
    }


async def get_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: str,
) -> dict[str, Any] | None:
    """Fetch a single record by primary key."""
    model = entry.model_class
    pk_col = _get_pk_col(entry)
    stmt = select(model).where(pk_col == record_id)
    record = await session.scalar(stmt)
    if record is None:
        return None
    return serialize_record(record, entry)


# ---------------------------------------------------------------------------
# Create / Update / Delete
# ---------------------------------------------------------------------------

async def create_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Validate and create a new record."""
    model = entry.model_class
    validated = entry.write_schema.model_validate(data)
    clean = validated.model_dump(exclude_unset=True)

    if entry.is_user_model:
        password = clean.pop("password")
        record = await model.create_user(
            session, password=password, **clean,
        )
    else:
        record = await model.objects(session).create(**clean)

    return serialize_record(record, entry)


async def update_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: str,
    data: dict[str, Any],
) -> dict[str, Any] | None:
    """Validate and update a record."""
    model = entry.model_class
    pk_col = _get_pk_col(entry)
    stmt = select(model).where(pk_col == record_id)
    record = await session.scalar(stmt)
    if record is None:
        return None

    validated = entry.update_schema.model_validate(data)
    clean = validated.model_dump(exclude_unset=True)

    if clean:
        for key, value in clean.items():
            setattr(record, key, value)
        session.add(record)
        await session.flush()
        await session.refresh(record)

    return serialize_record(record, entry)


async def delete_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: str,
) -> bool:
    """Delete a record by primary key. Returns True if found and deleted."""
    model = entry.model_class
    pk_col = _get_pk_col(entry)
    stmt = select(model).where(pk_col == record_id)
    record = await session.scalar(stmt)
    if record is None:
        return False
    await session.delete(record)
    await session.flush()
    return True


async def bulk_delete_records(
    session: AsyncSession,
    entry: ModelAdminEntry,
    ids: list[int | str],
) -> int:
    """Delete multiple records by primary key. Returns count deleted."""
    if not ids:
        return 0
    model = entry.model_class
    pk_col = _get_pk_col(entry)
    stmt = sa_delete(model).where(pk_col.in_(ids))
    result = await session.execute(stmt)
    await session.flush()
    return result.rowcount


# ---------------------------------------------------------------------------
# Admin password change
# ---------------------------------------------------------------------------

async def admin_set_password(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: str,
    new_password: str,
) -> None:
    """Set password for a user model record (admin privilege, no old password).

    Raises:
        ValueError: If the model is not a user model.
        LookupError: If the record is not found.
    """
    if not entry.is_user_model:
        raise ValueError("Password change not supported for this model.")

    model = entry.model_class
    pk_col = _get_pk_col(entry)
    stmt = select(model).where(pk_col == record_id)
    user = await session.scalar(stmt)
    if user is None:
        raise LookupError("User not found.")

    await user.set_password(new_password)
    await user.save(session)

    # Revoke all refresh tokens — the primary reason for an admin password
    # reset is account compromise, so existing sessions must be invalidated.
    from auth.utils.auth_backend import logout_user_all_devices
    await logout_user_all_devices(session=session, user_id=user.id)
