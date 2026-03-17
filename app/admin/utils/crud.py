"""Generic CRUD operations for any registered admin model."""
from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from sqlalchemy import delete as sa_delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin.utils.registry import ModelAdminEntry, FieldMeta


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

def serialize_record(record: Any, fields: list[FieldMeta]) -> dict[str, Any]:
    """Convert a model instance to a dict using the field metadata."""
    result: dict[str, Any] = {"id": record.id}
    for f in fields:
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

    # Ordering
    if ordering:
        desc = ordering.startswith("-")
        field_name = ordering.lstrip("-")
        col = getattr(model, field_name, None)
        if col is not None:
            base = base.order_by(col.desc() if desc else col.asc())
    else:
        base = base.order_by(model.id.asc())

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
        "results": [serialize_record(r, entry.fields) for r in records],
    }


async def get_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: int,
) -> dict[str, Any] | None:
    """Fetch a single record by id."""
    model = entry.model_class
    record = await model.objects(session).get(id=record_id)
    if record is None:
        return None
    return serialize_record(record, entry.fields)


# ---------------------------------------------------------------------------
# Create / Update / Delete
# ---------------------------------------------------------------------------

def _editable_fields(entry: ModelAdminEntry) -> set[str]:
    """Return the set of editable field names."""
    return {f.name for f in entry.fields if f.editable}


async def create_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Create a new record, filtering to editable fields only."""
    model = entry.model_class
    editable = _editable_fields(entry)
    filtered = {k: v for k, v in data.items() if k in editable}

    if entry.is_user_model and "password" in data:
        password = data["password"]
        record = await model.create_user(session, password=password, **filtered)
    else:
        record = await model.objects(session).create(**filtered)

    return serialize_record(record, entry.fields)


async def update_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: int,
    data: dict[str, Any],
) -> dict[str, Any] | None:
    """Update a record with only editable field values."""
    model = entry.model_class
    record = await model.objects(session).get(id=record_id)
    if record is None:
        return None

    editable = _editable_fields(entry)
    filtered = {k: v for k, v in data.items() if k in editable}

    if filtered:
        await record.update(session, **filtered)

    return serialize_record(record, entry.fields)


async def delete_record(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: int,
) -> bool:
    """Delete a record by id. Returns True if found and deleted."""
    model = entry.model_class
    record = await model.objects(session).get(id=record_id)
    if record is None:
        return False
    await record.delete(session)
    return True


async def bulk_delete_records(
    session: AsyncSession,
    entry: ModelAdminEntry,
    ids: list[int],
) -> int:
    """Delete multiple records by id. Returns count deleted."""
    if not ids:
        return 0
    model = entry.model_class
    stmt = sa_delete(model).where(model.id.in_(ids))
    result = await session.execute(stmt)
    await session.flush()
    return result.rowcount


# ---------------------------------------------------------------------------
# Admin password change
# ---------------------------------------------------------------------------

async def admin_set_password(
    session: AsyncSession,
    entry: ModelAdminEntry,
    record_id: int,
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
    user = await model.objects(session).get(id=record_id)
    if user is None:
        raise LookupError("User not found.")

    await user.set_password(new_password)
    await user.save(session)
