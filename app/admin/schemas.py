"""Pydantic schemas for admin API request/response models."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FieldSchema(BaseModel):
    name: str
    type: str
    editable: bool
    required: bool
    default: Any = None
    options: list[str] | None = None


class ModelSchema(BaseModel):
    label: str
    pk_field: str
    has_password_change: bool
    list_display: list[str] | None = None
    search_fields: list[str] | None = None
    fields: list[FieldSchema]


class AppSchema(BaseModel):
    label: str
    models: dict[str, ModelSchema]


class SchemaResponse(BaseModel):
    apps: dict[str, AppSchema]


class AdminConfigResponse(BaseModel):
    auth_type: str


class PaginatedResponse(BaseModel):
    count: int
    page: int
    page_size: int
    total_pages: int
    results: list[dict[str, Any]]


class BulkDeleteRequest(BaseModel):
    ids: list[int | str] = Field(min_length=1, max_length=500)


class BulkDeleteResponse(BaseModel):
    deleted: int


class AdminChangePasswordRequest(BaseModel):
    new_password: str = Field(min_length=1, max_length=100)
