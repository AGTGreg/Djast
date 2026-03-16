"""Tests for admin model registry."""
from __future__ import annotations

import pytest
import pytest_asyncio
import importlib
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Mapped, mapped_column, clear_mappers
from sqlalchemy.sql import func

from djast.db.models import Base, Model
from djast.settings import settings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    yield eng
    await eng.dispose()


@pytest.fixture
def fresh_registry():
    """Return a fresh AdminSite for isolation."""
    from admin.registry import AdminSite
    return AdminSite()


# ---------------------------------------------------------------------------
# Test model (non-user)
# ---------------------------------------------------------------------------

class _TestItem(Model):
    __tablename__ = "test_item"

    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True, default=None
    )
    price: Mapped[float] = mapped_column(default=0.0)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now,
        server_default=func.now(),
    )


# ---------------------------------------------------------------------------
# Zero-config registration
# ---------------------------------------------------------------------------

def test_zero_config_register(fresh_registry):
    """Register a model with zero-config mode."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    assert entry is not None
    assert entry.model_class is _TestItem
    assert entry.admin_config.app_name == "TestApp"


def test_zero_config_fields_introspected(fresh_registry):
    """Fields are introspected from the model."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    field_names = [f.name for f in entry.fields]
    assert "id" in field_names
    assert "name" in field_names
    assert "price" in field_names


def test_unregistered_model_returns_none(fresh_registry):
    """get_model_entry returns None for unregistered models."""
    assert fresh_registry.get_model_entry("NoApp", "NoModel") is None


# ---------------------------------------------------------------------------
# Field type mapping
# ---------------------------------------------------------------------------

def test_field_type_integer(fresh_registry):
    """Integer PK maps to 'integer'."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    id_field = next(f for f in entry.fields if f.name == "id")
    assert id_field.type == "integer"


def test_field_type_string(fresh_registry):
    """String column maps to 'string'."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    name_field = next(f for f in entry.fields if f.name == "name")
    assert name_field.type == "string"


def test_field_type_boolean(fresh_registry):
    """Boolean column maps to 'boolean'."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    active_field = next(f for f in entry.fields if f.name == "is_active")
    assert active_field.type == "boolean"


def test_field_type_decimal(fresh_registry):
    """Float column maps to 'decimal'."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    price_field = next(f for f in entry.fields if f.name == "price")
    assert price_field.type == "decimal"


def test_field_type_datetime(fresh_registry):
    """DateTime column maps to 'datetime'."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    created_field = next(f for f in entry.fields if f.name == "created_at")
    assert created_field.type == "datetime"


# ---------------------------------------------------------------------------
# Editable / required detection
# ---------------------------------------------------------------------------

def test_pk_not_editable(fresh_registry):
    """Primary key is not editable."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    id_field = next(f for f in entry.fields if f.name == "id")
    assert id_field.editable is False


def test_pk_not_required(fresh_registry):
    """Primary key is not required (auto-generated)."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    id_field = next(f for f in entry.fields if f.name == "id")
    assert id_field.required is False


def test_name_field_required(fresh_registry):
    """Non-nullable field without default is required."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    name_field = next(f for f in entry.fields if f.name == "name")
    assert name_field.required is True
    assert name_field.editable is True


def test_nullable_field_not_required(fresh_registry):
    """Nullable field is not required."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    desc_field = next(f for f in entry.fields if f.name == "description")
    assert desc_field.required is False


def test_server_default_not_editable(fresh_registry):
    """Non-nullable column with server_default is not editable."""
    fresh_registry.register(_TestItem, "TestApp")
    entry = fresh_registry.get_model_entry("TestApp", "_TestItem")
    created_field = next(f for f in entry.fields if f.name == "created_at")
    assert created_field.editable is False


# ---------------------------------------------------------------------------
# Extended mode (decorator)
# ---------------------------------------------------------------------------

def test_extended_registration(fresh_registry):
    """Extended mode via decorator-like config."""
    from admin.registry import ModelAdmin

    class ItemAdmin(ModelAdmin):
        app_name = "Shop"
        list_display = ("id", "name", "price")
        search_fields = ("name", "description")

    fresh_registry.register(_TestItem, "Shop", admin_class=ItemAdmin)
    entry = fresh_registry.get_model_entry("Shop", "_TestItem")
    assert entry is not None
    assert entry.admin_config.list_display == ("id", "name", "price")
    assert entry.search_field_names == ["name", "description"]


# ---------------------------------------------------------------------------
# Exclude fields
# ---------------------------------------------------------------------------

def test_exclude_fields(fresh_registry):
    """Excluded fields do not appear in field list."""
    from admin.registry import ModelAdmin

    class ItemAdmin(ModelAdmin):
        app_name = "Shop"
        exclude_fields = {"price", "description"}

    fresh_registry.register(_TestItem, "Shop", admin_class=ItemAdmin)
    entry = fresh_registry.get_model_entry("Shop", "_TestItem")
    field_names = [f.name for f in entry.fields]
    assert "price" not in field_names
    assert "description" not in field_names
    assert "name" in field_names


# ---------------------------------------------------------------------------
# Field options (select type)
# ---------------------------------------------------------------------------

def test_field_options_select_type(fresh_registry):
    """Field with options maps to 'select' type."""
    from admin.registry import ModelAdmin

    class ItemAdmin(ModelAdmin):
        app_name = "Shop"
        field_options = {"name": ["Option A", "Option B"]}

    fresh_registry.register(_TestItem, "Shop", admin_class=ItemAdmin)
    entry = fresh_registry.get_model_entry("Shop", "_TestItem")
    name_field = next(f for f in entry.fields if f.name == "name")
    assert name_field.type == "select"
    assert name_field.options == ["Option A", "Option B"]


# ---------------------------------------------------------------------------
# get_schema() output
# ---------------------------------------------------------------------------

def test_get_schema_structure(fresh_registry):
    """get_schema returns correct nested structure."""
    fresh_registry.register(_TestItem, "TestApp")
    schema = fresh_registry.get_schema()

    assert "apps" in schema
    assert "TestApp" in schema["apps"]
    app = schema["apps"]["TestApp"]
    assert app["label"] == "TestApp"
    assert "_TestItem" in app["models"]
    model = app["models"]["_TestItem"]
    assert model["label"] == "_TestItem"
    assert isinstance(model["fields"], list)
    assert model["has_password_change"] is False


# ---------------------------------------------------------------------------
# User model detection
# ---------------------------------------------------------------------------

def test_user_model_detected():
    """AbstractBaseUser subclass sets is_user_model=True."""
    from admin.registry import AdminSite
    from auth.models import User

    reg = AdminSite()
    reg.register(User, "Auth")
    entry = reg.get_model_entry("Auth", "User")
    assert entry.is_user_model is True


def test_user_model_password_excluded():
    """Password field auto-excluded for user models."""
    from admin.registry import AdminSite
    from auth.models import User

    reg = AdminSite()
    reg.register(User, "Auth")
    entry = reg.get_model_entry("Auth", "User")
    field_names = [f.name for f in entry.fields]
    assert "password" not in field_names


def test_user_model_has_password_change_in_schema():
    """User model schema has has_password_change=True."""
    from admin.registry import AdminSite
    from auth.models import User

    reg = AdminSite()
    reg.register(User, "Auth")
    schema = reg.get_schema()
    model_schema = schema["apps"]["Auth"]["models"]["User"]
    assert model_schema["has_password_change"] is True


def test_non_user_model_no_password_change(fresh_registry):
    """Non-user model has has_password_change=False."""
    fresh_registry.register(_TestItem, "TestApp")
    schema = fresh_registry.get_schema()
    model_schema = schema["apps"]["TestApp"]["models"]["_TestItem"]
    assert model_schema["has_password_change"] is False


# ---------------------------------------------------------------------------
# Default registration
# ---------------------------------------------------------------------------

def test_default_user_registered():
    """The singleton site has the User model registered under Auth."""
    from admin.registry import site
    entry = site.get_model_entry("Auth", "User")
    assert entry is not None
    assert entry.is_user_model is True
