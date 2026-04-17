"""
Admin registry infrastructure.

Provides the AdminSite, ModelAdmin config class, field introspection,
and the decorator API for registering models with the admin panel.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field, create_model
from sqlalchemy import inspect as sa_inspect

from djast.db.models import ColumnMeta


# ---------------------------------------------------------------------------
# Field metadata
# ---------------------------------------------------------------------------

@dataclass
class FieldMeta:
    """Metadata for a single model field, derived from SQLAlchemy column."""
    name: str
    type: str  # integer, string, email, boolean, datetime, decimal, select
    editable: bool
    required: bool
    default: Any = None
    options: list[str] | None = None


# ---------------------------------------------------------------------------
# ModelAdmin — config class devs can subclass
# ---------------------------------------------------------------------------

class ModelAdmin:
    """Configuration class for admin model display and behaviour."""
    app_name: str = ""
    list_display: tuple[str, ...] | None = None
    search_fields: tuple[str, ...] | None = None
    field_options: dict[str, list[str]] | None = None
    exclude_fields: set[str] | None = None


# ---------------------------------------------------------------------------
# Internal entry
# ---------------------------------------------------------------------------

@dataclass
class ModelAdminEntry:
    """Internal registry entry for a registered model."""
    model_class: type
    admin_config: ModelAdmin
    pk_field_names: tuple[str, ...] = ()
    fields: list[FieldMeta] = field(default_factory=list)
    search_field_names: list[str] = field(default_factory=list)
    is_user_model: bool = False
    write_schema: type | None = None
    update_schema: type | None = None


# ---------------------------------------------------------------------------
# Type mapping & introspection
# ---------------------------------------------------------------------------

_PYTHON_TYPE_MAP: dict[type, str] = {
    int: "integer",
    str: "string",
    bool: "boolean",
    float: "decimal",
}


def _resolve_admin_type(col: ColumnMeta, admin_config: ModelAdmin) -> str:
    """Map a ColumnMeta to an admin field type string."""
    if admin_config.field_options and col.name in admin_config.field_options:
        return "select"

    from datetime import datetime as dt_cls
    if col.python_type is dt_cls:
        return "datetime"

    if col.name == "email" and col.python_type is str:
        return "email"

    return _PYTHON_TYPE_MAP.get(col.python_type, "string")


def _get_pk_names(model_class: type) -> tuple[str, ...]:
    """Return primary-key column names for a model.

    Works with single, renamed, and composite primary keys.
    """
    mapper = sa_inspect(model_class)
    return tuple(col.name for col in mapper.primary_key)


def _introspect_fields(
    model_class: type,
    admin_config: ModelAdmin,
) -> list[FieldMeta]:
    """Build field metadata list from model column introspection."""
    exclude = admin_config.exclude_fields or set()
    fields: list[FieldMeta] = []

    for col in model_class.columns_meta(exclude):
        editable = not (
            col.primary_key
            or (col.has_server_default and not col.nullable)
            or col.has_onupdate
        )
        fields.append(FieldMeta(
            name=col.name,
            type=_resolve_admin_type(col, admin_config),
            editable=editable,
            required=not col.primary_key and not col.nullable,
            default=col.default_value,
            options=(admin_config.field_options or {}).get(col.name),
        ))

    return fields


# ---------------------------------------------------------------------------
# AdminSite — registry
# ---------------------------------------------------------------------------

class AdminSite:
    """Central registry for admin-visible models."""

    def __init__(self) -> None:
        # app_name -> model_name -> ModelAdminEntry
        self._registry: dict[str, dict[str, ModelAdminEntry]] = {}

    def register(
        self,
        model_class: type,
        app_name: str | None = None,
        admin_class: type[ModelAdmin] | None = None,
    ) -> Callable[[type[ModelAdmin]], type[ModelAdmin]] | None:
        """Register a model for the admin panel.

        Can be used as a direct call (zero-config) or as a decorator:

            # Zero-config:
            site.register(MyModel, "MyApp")

            # Decorator:
            @site.register(MyModel)
            class MyModelAdmin(ModelAdmin):
                app_name = "MyApp"
                list_display = ("id", "name")

        Args:
            model_class: The SQLAlchemy model class.
            app_name: Display name for the app grouping (zero-config mode).
            admin_class: Optional ModelAdmin subclass (zero-config mode).
        """
        if app_name is not None:
            config = admin_class() if admin_class else ModelAdmin()
            config.app_name = app_name
            self._register_entry(model_class, config)
            return None

        def decorator(cls: type[ModelAdmin]) -> type[ModelAdmin]:
            config = cls()
            self._register_entry(model_class, config)
            return cls

        return decorator

    def _register_entry(
        self,
        model_class: type,
        config: ModelAdmin,
    ) -> None:
        """Build and store a ModelAdminEntry."""
        from auth.models import AbstractBaseUser

        is_user = issubclass(model_class, AbstractBaseUser)

        if is_user:
            config.exclude_fields = (config.exclude_fields or set()) | {"password"}

        pk_names = _get_pk_names(model_class)
        if not pk_names:
            raise ValueError(
                f"{model_class.__name__} has no primary key"
                f" and cannot be registered with admin."
            )

        fields = _introspect_fields(model_class, config)

        # Default list_display to primary key columns (filtered by visible fields).
        if config.list_display is None:
            visible = {f.name for f in fields}
            config.list_display = tuple(
                n for n in pk_names if n in visible
            )

        search_field_names: list[str] = []
        if config.search_fields:
            field_names = {f.name for f in fields}
            search_field_names = [
                f for f in config.search_fields if f in field_names
            ]

        # Build write schema from get_schema(), excluding
        # non-editable fields (PKs, server_defaults, onupdate).
        non_editable = {
            f.name for f in fields if not f.editable
        }
        schema_exclude = (
            (config.exclude_fields or set()) | non_editable
        )
        base_schema = model_class.get_schema(
            exclude=schema_exclude,
        )
        if is_user:
            write_schema = create_model(
                f"{model_class.__name__}AdminWrite",
                __base__=base_schema,
                password=(
                    str,
                    Field(min_length=1, max_length=100),
                ),
            )
        else:
            write_schema = base_schema

        entry = ModelAdminEntry(
            model_class=model_class,
            admin_config=config,
            pk_field_names=pk_names,
            fields=fields,
            search_field_names=search_field_names,
            is_user_model=is_user,
            write_schema=write_schema,
            update_schema=base_schema,
        )

        app_name = config.app_name
        model_name = model_class.__name__

        if app_name not in self._registry:
            self._registry[app_name] = {}
        self._registry[app_name][model_name] = entry

    def get_model_entry(
        self, app_name: str, model_name: str
    ) -> ModelAdminEntry | None:
        """Look up a registered model by app and model name."""
        return self._registry.get(app_name, {}).get(model_name)

    def get_schema(self) -> dict:
        """Return the full registry schema for the schema endpoint.

        Returns:
            {
                "apps": {
                    "AppName": {
                        "label": "AppName",
                        "models": {
                            "ModelName": {
                                "label": "ModelName",
                                "has_password_change": bool,
                                "search_fields": list | null,
                                "fields": [
                                    {
                                        "name": str,
                                        "type": str,
                                        "editable": bool,
                                        "required": bool,
                                        "default": value | null,
                                        "options": list | null,
                                    },
                                    ...
                                ]
                            }
                        }
                    }
                }
            }
        """
        apps: dict[str, dict] = {}

        for app_name, models in self._registry.items():
            models_schema: dict[str, dict] = {}
            for model_name, entry in models.items():
                ld = entry.admin_config.list_display
                models_schema[model_name] = {
                    "label": model_name,
                    "pk_field": entry.pk_field_names[0],
                    "has_password_change": entry.is_user_model,
                    "list_display": list(ld) if ld else None,
                    "search_fields": entry.search_field_names or None,
                    "fields": [
                        {
                            "name": f.name,
                            "type": f.type,
                            "editable": f.editable,
                            "required": f.required,
                            "default": f.default,
                            "options": f.options,
                        }
                        for f in entry.fields
                    ],
                }
            apps[app_name] = {
                "label": app_name,
                "models": models_schema,
            }

        return {"apps": apps}
