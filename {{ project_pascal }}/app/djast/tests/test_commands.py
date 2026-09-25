"""Tests for the manage.py commands."""
import pytest

from djast.commands import migrate


def test_migrate_fails_when_alembic_ini_is_missing(tmp_path, monkeypatch):
    """A missing alembic.ini must exit non-zero, not print and return 0.

    A bare return exits 0, which tells every caller -- entrypoint script,
    deploy gate, CI step -- that the migration succeeded. The app then boots
    against an unmigrated database with nothing reporting a problem.
    """
    monkeypatch.setattr(migrate, "ROOT_DIR", tmp_path)

    with pytest.raises(SystemExit) as exc:
        migrate.run()

    assert "alembic.ini" in str(exc.value)


def test_migrate_fails_when_migrations_dir_is_missing(tmp_path, monkeypatch):
    """alembic.ini present but migrations/ absent must also exit non-zero."""
    (tmp_path / "alembic.ini").write_text("[alembic]\n")
    monkeypatch.setattr(migrate, "ROOT_DIR", tmp_path)

    with pytest.raises(SystemExit) as exc:
        migrate.run()

    assert "migrations/" in str(exc.value)
