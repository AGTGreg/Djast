# Testing

Djast ships a pytest suite for its own apps (`auth`, `admin`, `djast`) and the
fixtures your app's tests build on. Config lives in `app/pyproject.toml`
(`asyncio_mode = "auto"`, so `async def test_*` needs no decorator).

```bash
docker compose exec app python -m pytest
docker compose exec app python -m pytest auth/tests -q
docker compose exec app python -m pytest -k signup
```

---

## Shared fixtures

Defined in `app/conftest.py`, available to every test under `app/`:

| Fixture | Scope | What it gives you |
|---------|-------|-------------------|
| `db_engine` | function | An async engine. **No schema.** |
| `db_session` | function | An `AsyncSession` bound to that engine |
| `schema` | function | Creates the whole schema, drops it afterwards |
| `auth_mode` | session | `"django"` or `"email"` — the mode this process runs under |
| `redis_lifecycle` | function, autouse | Reconnects the shared Redis client on the current event loop |

`app/auth/tests/conftest.py` adds `auth_client` (app + `AsyncClient`, yields
`(client, mode, db_session)`) and `redis_cleanup` (autouse, flushes both Redis
DBs).

### `db_engine` manages no schema — on purpose

Every client fixture creates and drops the schema it needs, through the `schema`
fixture. **Do not add `create_all`/`drop_all` to `db_engine`.** Two fixtures both
managing the schema will fight, and the symptom is a foreign-key error in an
unrelated test rather than anything pointing at the cause.

### Release the session before the schema is dropped

A fixture that hands a session to the app via `dependency_overrides` must roll it
back before teardown drops the tables:

```python
app.dependency_overrides.clear()
await db_session.rollback()      # <- required
```

On SQLite this looks optional. On PostgreSQL the session sits idle in a
transaction holding locks, `DROP TABLE` blocks on it, and the suite **hangs with
no traceback**.

---

## Auth mode is a build-time choice

`AUTH_USER_MODEL_TYPE` decides the shape of `User`, and that shape is fixed when
`auth.models` is imported. A process runs under one mode. The suite therefore
runs once per mode:

```bash
docker compose exec app python -m pytest
docker compose exec -e AUTH_USER_MODEL_TYPE=email app python -m pytest
```

Use the `auth_mode` fixture in a test that only makes sense in one mode:

```python
async def test_login_with_username(auth_client, auth_mode):
    if auth_mode != "django":
        pytest.skip("username login only exists in django mode")
```

`auth/tests/helpers.py` has `new_user_payload(mode)` and `signup_and_login(...)`,
which build the right payload for either mode — prefer those over hand-written
username/email dicts.

### Do not switch modes inside a process

Redefining `User` at runtime means `clear_mappers()` and
`Base.metadata.clear()`. **Both are global.** They unmap every model in the
process, including your app's, and nothing restores them:

```
>>> clear_mappers(); Base.metadata.clear()
>>> orgs.models.Organisation.__table__
AttributeError: type object 'Organisation' has no attribute '__table__'
```

From that point the class cannot be constructed, its table is gone from
`Base.metadata` so `create_all` never creates it, and `admin/registry.py` — which
introspects every registered model at import — raises. The framework's fixtures
used to do this; they no longer do, and
`auth/tests/test_model_isolation.py` fails if it comes back.

---

## Running against PostgreSQL

The default test engine is in-memory SQLite: fast, and a fresh database per test.
It is not what you deploy on. Point the suite at the compose PostgreSQL with
`TEST_DATABASE_URL`:

```bash
docker compose exec db psql -U myuser -d mydatabase -c "CREATE DATABASE test_db OWNER myuser;"

docker compose exec \
  -e TEST_DATABASE_URL="postgresql+asyncpg://myuser:$DB_PASSWORD@db:5432/test_db" \
  app python -m pytest
```

Worth doing in CI. A whole class of bug — teardown deadlocks, stale table shapes,
foreign-key ordering — is invisible on per-test in-memory SQLite and certain on a
real database.

---

## What the suite cannot see

Tests run in one process that imports the application itself and uses an
in-memory task broker. Anything whose correctness depends on a **separate
process** is outside their reach:

- **Task registration.** Under test, the task module is always imported, so the
  task is always registered. In deployment the worker is a separate process. See
  [Task Queue](taskiq.md#how-the-worker-finds-your-tasks).
- **Lazy imports in task bodies.** Same reason — the test process has the app
  root on `sys.path`; the worker needs `PYTHONPATH`.
- **What the image contains.** Tests run from a source checkout, so a file
  excluded by `.dockerignore` is still present. `migrations/` is the one that
  bites. See [Production Deployment](production-deployment.md).

For these, check the running container once after adding an app:

```bash
docker compose logs taskiq-worker | grep Importing
docker compose exec app python manage.py migrate
```

---

## Testing your own app

```python
# myapp/tests/test_views.py
from auth.tests.helpers import signup_and_login


async def test_list_requires_auth(auth_client):
    client, _mode, _db = auth_client
    assert (await client.get("/api/v1/myapp/items/")).status_code == 401


async def test_list_returns_items(auth_client):
    client, mode, session = auth_client
    _user_id, token = await signup_and_login(client, mode)

    from myapp.models import Item
    await Item.objects(session).create(name="one")

    resp = await client.get(
        "/api/v1/myapp/items/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert [i["name"] for i in resp.json()] == ["one"]
```

Your models are picked up by the `schema` fixture automatically — anything
importable and mapped on `Base` is created. Nothing to register.

For task tests see [Task Queue → Testing](taskiq.md#testing).
