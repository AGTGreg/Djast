"""
Admin model registry.

Register your app's models here for the admin panel.

Zero-config:
    admin.site.register(MyModel, "MyApp")

Extended:
    @admin.register(MyModel)
    class MyModelAdmin(admin.ModelAdmin):
        app_name = "MyApp"
        list_display = ("id", "name")
        search_fields = ("name",)
"""
from admin.utils.registry import AdminSite, ModelAdmin  # noqa: F401
from auth.models import User
from djast.settings import settings

# ---------------------------------------------------------------------------
# Site (singleton)
# ---------------------------------------------------------------------------

site = AdminSite()


# ---------------------------------------------------------------------------
# Decorator API (extended mode)
# ---------------------------------------------------------------------------

def register(model_class: type):
    """Decorator for extended registration with a ModelAdmin subclass."""
    def decorator(admin_cls: type[ModelAdmin]) -> type[ModelAdmin]:
        config = admin_cls()
        site._register_entry(model_class, config)
        return admin_cls
    return decorator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@register(User)
class UserAdmin(ModelAdmin):
    app_name = "Auth"
    exclude_fields = {"last_login"}
    search_fields = (
        ("username", "email") if settings.AUTH_USER_MODEL_TYPE == "django"
        else ("email",)
    )
    list_display = (
        ("id", "username", "email", "is_active", "is_staff", "date_joined")
        if settings.AUTH_USER_MODEL_TYPE == "django"
        else ("id", "email", "is_active", "is_staff", "date_joined")
    )
