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
from admin.utils.registry import AdminSite, ModelAdmin
from auth.models import User, RefreshToken, EmailAddress, OAuthAccount
from djast.settings import settings


site = AdminSite()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@site.register(User)
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


@site.register(RefreshToken)
class RefreshTokenAdmin(ModelAdmin):
    app_name = "Auth"
    list_display = ("key", "id", "user_id", "created", "expires_at", "revoked_at")
    search_fields = ("key",)


site.register(EmailAddress, "Auth")
site.register(OAuthAccount, "Auth")
