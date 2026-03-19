# Djast Admin Panel

Minimal Django like admin panel for Djast. The admin panel shows the apps in a sidebar. Under each app theres a list with all the registered models of the app. The admin panel offers CRUD for all registered models. It includes: Login, Change password, List view, Details view. The admin module is a Djast app and devs can opt-out simply by deleting the admin folder and removing the admin route from `urls.py`. No other reference of the admin exists outside the admin folder besides `urls.py`.

## Login
Simple login view. No signup. Uses JWT authedication.

## Change password
Available only to authedicated users from withi the admin panel.

## List view
The user clicks on a model to see the list view: A table of all records of the model. The table is paginated (100 records per page). The user can also sort the records asc/desc on all fields and select/deselect multiple records (via a checkbox on each row). At the top of the list view there is:
 - A searchbar
 - An Add new button
 - A dropdown with group actions for the checked records (currently only one: Delete selected)


## Details view
User clicks on a record from the list view to go to the details view of the record. The details view is a form with all the editable and non-editable fields of the record. When the user clicks the Add new button, the same form appears but with only the editable fields visible and empty.


## Apps and Models registration in the admin
This takes place in a script inside the admin app called `registry.py`. Devs can register their models they want to show up in the admin panel in a Django-like way. They can do this in two ways:

### zero-config:
```python
admin.site.register(MyModel, MyApp)
```

### extended:
```python
@admin.register(MyModel)
class MyModelAdmin(admin.ModelAdmin):
    app_name: "MyApp"
    list_display = ("id", "name", "created_at")
    search_fields = ("message", "traceback")
```

Extended mode supports only: `app_name`, `list_display` and `search_fields` for simplicity.

## Users
Djast includes `is_staff` and `is_superuser` fields in the User model. This is only for keeping the Django user compatible with Django. In Djast both `is_staff` and `is_superuser` have the same priviladges. Only users who are either `is_staff` or `is_superuser` can login to the admin panel.

The admin panel supports both email and Django users and the login screen shows the correcvt fields based on what is in the `AUTH_USER_MODEL_TYPE` setting.
