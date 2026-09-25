"""The framework's own fixtures must not damage application models.

The auth fixtures used to call ``clear_mappers()`` and ``Base.metadata.clear()``
to redefine ``User`` for the auth mode under test. Both are global: they unmap
*every* model in the process, including the application's, and nothing restores
them. An application model afterwards has no ``__table__`` and cannot even be
constructed, so ``admin/registry.py`` -- which introspects every registered model
at import -- raised for any model a project had registered.

These tests fail if that ever comes back.
"""
from sqlalchemy import String, inspect as sa_inspect
from sqlalchemy.orm import Mapped, mapped_column

from djast.db import models


class ProbeThing(models.Model):
    """Stands in for an application model declared outside the auth app."""
    __tablename__ = "tests_probe_thing"

    name: Mapped[str] = mapped_column(String(50), default="")


def _assert_probe_is_usable() -> None:
    assert "tests_probe_thing" in models.Base.metadata.tables
    assert hasattr(ProbeThing, "__table__")
    assert sa_inspect(ProbeThing) is not None
    assert ProbeThing(name="x").name == "x"


async def test_probe_model_usable_before_any_auth_fixture():
    _assert_probe_is_usable()


async def test_probe_model_survives_the_auth_client_fixture(auth_client):
    client, _mode, _db = auth_client
    resp = await client.get("/health")
    assert resp.status_code == 200
    _assert_probe_is_usable()


async def test_probe_table_is_created_with_the_schema(auth_client, db_engine):
    """The schema fixture builds the whole metadata, not just the auth tables."""
    _client, _mode, _db = auth_client

    def _tables(conn):
        return set(sa_inspect(conn).get_table_names())

    async with db_engine.connect() as conn:
        names = await conn.run_sync(_tables)

    assert "tests_probe_thing" in names
    assert "auth_user" in names
