"""
Admin registry infrastructure.

Provides the AdminSite, ModelAdmin config class, field introspection,
and the decorator API for registering models with the admin panel.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import inspect as sa_inspect


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


# ---------------------------------------------------------------------------
# Type mapping & introspection
# ---------------------------------------------------------------------------

_PYTHON_TYPE_MAP: dict[type, str] = {
    int: "integer",
    str: "string",
    bool: "boolean",
    float: "decimal",
}


def _resolve_field_type(
    column: Any,
    admin_config: ModelAdmin,
) -> str:
    """Map a SQLAlchemy column to an admin field type string."""
    if admin_config.field_options and column.name in admin_config.field_options:
        return "select"

    try:
        from datetime import datetime as dt_cls
        python_type = column.type.python_type
        if python_type is dt_cls:
            return "datetime"
    except NotImplementedError:
        return "string"

    if column.name == "email" and python_type is str:
        return "email"

    return _PYTHON_TYPE_MAP.get(python_type, "string")


def _is_editable(column: Any) -> bool:
    """A column is not editable if it's a PK, has server_default+not nullable,
    or has onupdate."""
    if column.primary_key:
        return False
    if column.server_default is not None and not column.nullable:
        return False
    if getattr(column, "onupdate", None) is not None:
        return False
    return True


def _is_required(column: Any) -> bool:
    """A column is required if it's not PK, not nullable, no default,
    and no server_default."""
    if column.primary_key:
        return False
    if column.nullable:
        return False
    if column.default is not None:
        return False
    if column.server_default is not None:
        return False
    return True


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
    """Introspect SQLAlchemy columns to build field metadata list."""
    mapper = sa_inspect(model_class)
    exclude = admin_config.exclude_fields or set()
    fields: list[FieldMeta] = []

    for column in mapper.columns:
        if column.name in exclude:
            continue
        fields.append(FieldMeta(
            name=column.name,
            type=_resolve_field_type(column, admin_config),
            editable=_is_editable(column),
            required=_is_required(column),
            options=(admin_config.field_options or {}).get(column.name),
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

        fields = _introspect_fields(model_class, config)

        # Default list_display to primary key columns (filtered by visible fields).
        if config.list_display is None:
            visible = {f.name for f in fields}
            config.list_display = tuple(
                n for n in _get_pk_names(model_class) if n in visible
            )

        search_field_names: list[str] = []
        if config.search_fields:
            field_names = {f.name for f in fields}
            search_field_names = [
                f for f in config.search_fields if f in field_names
            ]

        entry = ModelAdminEntry(
            model_class=model_class,
            admin_config=config,
            pk_field_names=_get_pk_names(model_class),
            fields=fields,
            search_field_names=search_field_names,
            is_user_model=is_user,
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
