# Admin Panel

The admin panel is Djast’s built-in back office for staff users. It gives you a browser UI for registered models with login, list views, search, sorting, pagination, record creation, record editing, single delete, bulk delete, and password management for user models. The interface is schema-driven, so forms and navigation are generated from the models you register in the admin registry. It works with both Djast auth modes and is served out of the box with the framework.

## Using the Admin Panel

Open `/admin` in the browser and sign in with a user that has `is_staff=True` or `is_superuser=True`. The login form automatically uses either username or email depending on `AUTH_USER_MODEL_TYPE`. After signing in, choose a model from the sidebar to open its list view, search with the model’s configured search fields, sort columns, edit records from the detail screen, create new records with the `Add new` button, and delete one or many records as needed. You can create an admin account with the `createsuperuser` command:

```bash
python manage.py createsuperuser
```

## Registering Models

Register models in `app/admin/registry.py`. The simplest option is zero-config registration, which adds the model under a sidebar app label:

```python
from admin.registry import site
from blog.models import Article

site.register(Article, "Blog")
```

If you need more control over search behavior, field visibility, or select-style fields, use a `ModelAdmin` subclass with the `@register` decorator:

```python
from admin.registry import ModelAdmin, register
from myapp.models import Article

@register(Article)
class ArticleAdmin(ModelAdmin):
    app_name = "Blog"
    list_display = ("id", "title", "status", "created_at")
    search_fields = ("title", "status")
    exclude_fields = {"internal_notes"}
    field_options = {
        "status": ["draft", "published", "archived"],
    }
```

The registry accepts `app_name`, `list_display`, `search_fields`, `exclude_fields`, and `field_options`. In the current UI, `search_fields`, `exclude_fields`, and `field_options` directly affect behavior, while `list_display` is available in the registry for future list customization. User models are handled specially: the password field is hidden automatically, the detail screen exposes a password-change action instead, and creation uses the model’s `create_user()` flow so passwords are hashed correctly.

## Opting Out

The admin module is self-contained. If you do not want it in your project, delete `app/admin/` and remove the admin router import and registration from `app/djast/urls.py`. The admin SPA is mounted via `setup_app()` in `admin/__init__.py` and auto-discovered at startup — deleting the directory removes both the API routes and the frontend mount automatically. See [Building an SPA](building_an_spa.md) for details on the SPA pattern.

## Extending It

Start by extending `ModelAdmin`, because most customization is meant to happen through registry configuration. If you need behavior beyond field visibility, search, list columns, or select options, the next extension points are the generic CRUD layer in `app/admin/utils/crud.py`, schema generation in `app/admin/utils/registry.py`, and the React frontend in `app/admin/frontend/`. That keeps simple changes declarative and deeper changes isolated to the admin app.
