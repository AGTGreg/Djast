# Admin Panel

The admin panel is a built-in back office for staff users. It provides a browser UI for registered models with login, list views, search, sorting, pagination, record creation, editing, single and bulk delete, and password management for user models. The interface is schema-driven — forms and navigation are generated from the models you register.

**Files:** `app/admin/`, `app/admin/registry.py`, `app/admin/views.py`, `app/admin/frontend/`

---

## Getting Started

1. Create an admin account:

```bash
python manage.py createsuperuser
```

2. Open `/admin` in the browser and sign in with a user that has `is_staff=True` or `is_superuser=True`. The login form adapts automatically to `AUTH_USER_MODEL_TYPE` (username or email).

The admin panel works out of the box — no build step needed. The React frontend is pre-built and committed to the repo.

---

## Registering Models

Register models in `app/admin/registry.py`. The simplest option is zero-config registration:

```python
from admin.registry import site
from blog.models import Article

site.register(Article, "Blog")
```

For more control, use a `ModelAdmin` subclass with the `@site.register` decorator:

```python
from admin.registry import ModelAdmin, site
from myapp.models import Article

@site.register(Article)
class ArticleAdmin(ModelAdmin):
    app_name = "Blog"
    list_display = ("id", "title", "status", "created_at")
    search_fields = ("title", "status")
    exclude_fields = {"internal_notes"}
    field_options = {
        "status": ["draft", "published", "archived"],
    }
```

### ModelAdmin options

| Option | Type | Description |
|--------|------|-------------|
| `app_name` | `str` | Sidebar group label |
| `list_display` | `tuple[str, ...]` | Columns shown in the list view. Defaults to primary key column(s) |
| `search_fields` | `tuple[str, ...]` | Fields searchable from the list view |
| `exclude_fields` | `set[str]` | Fields hidden from the admin entirely |
| `field_options` | `dict[str, list[str]]` | Renders a field as a select dropdown with the given options |

### User model handling

User models (`AbstractBaseUser` subclasses) are handled specially:
- The `password` field is hidden automatically.
- The detail screen shows a password-change action instead.
- Creation uses the model's `create_user()` flow so passwords are hashed correctly.

---

## API Endpoints

The admin API is mounted at `{APP_PREFIX}/admin`. All endpoints except `/admin/config/` require `is_staff` or `is_superuser`.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/login` | Admin login (verifies staff status) |
| GET | `/admin/config/` | Auth mode config for the login form |
| GET | `/admin/schema/` | Full registry schema (apps, models, fields) |
| GET | `/admin/{app}/{model}/` | Paginated list with search and sort |
| GET | `/admin/{app}/{model}/{pk}` | Single record detail |
| POST | `/admin/{app}/{model}/` | Create a record |
| PATCH | `/admin/{app}/{model}/{pk}` | Update a record |
| DELETE | `/admin/{app}/{model}/{pk}` | Delete a record |
| POST | `/admin/{app}/{model}/bulk-delete` | Bulk delete (max 500) |
| POST | `/admin/{app}/{model}/{pk}/set-password` | Change password (user models only) |

---

## Opting Out

The admin module is self-contained. To remove it:

1. Delete `app/admin/`
2. Remove the admin router from `app/djast/urls.py`

The admin SPA is mounted via `setup_app()` in `admin/__init__.py` and auto-discovered at startup — deleting the directory removes both the API routes and the frontend mount. See [Building an SPA](building_an_spa.md) for details on the pattern.

---

## Extending

Start by extending `ModelAdmin` — most customization is meant to happen through registry configuration. If you need behavior beyond field visibility, search, list columns, or select options, the extension points are:

- **CRUD logic** — `app/admin/utils/crud.py`
- **Schema generation** — `app/admin/utils/registry.py`
- **React frontend** — `app/admin/frontend/`

This keeps simple changes declarative and deeper changes isolated to the admin app.
