"""The template's own secrets must never reach a running app."""
import pytest

from djast import settings as settings_module
from djast.settings import Settings


def _settings(**overrides):
    """Build a Settings instance with valid secrets, then apply overrides."""
    base = {
        "SECRET_KEY": "a-real-secret-that-is-not-from-the-template",
        "DATABASES": {"default": {"ENGINE": "sqlite", "PASSWORD": None}},
    }
    return Settings(**{**base, **overrides})


def test_valid_secret_is_accepted():
    assert _settings().SECRET_KEY


@pytest.mark.parametrize("key", sorted(settings_module._TEMPLATE_SECRET_KEYS))
def test_template_secret_key_is_rejected(key):
    with pytest.raises(ValueError, match="SECRET_KEY"):
        _settings(SECRET_KEY=key)


@pytest.mark.parametrize("pw", sorted(settings_module._TEMPLATE_DB_PASSWORDS))
def test_template_db_password_is_rejected(pw):
    with pytest.raises(ValueError, match="DB_PASSWORD"):
        _settings(DATABASES={"default": {"ENGINE": "postgresql", "PASSWORD": pw}})


def test_guard_is_not_gated_on_debug():
    """DEBUG defaults to True, so gating on it would skip the check entirely."""
    with pytest.raises(ValueError, match="SECRET_KEY"):
        _settings(SECRET_KEY="CHANGE-ME-generate-a-secret-key", DEBUG=True)
    with pytest.raises(ValueError, match="SECRET_KEY"):
        _settings(SECRET_KEY="CHANGE-ME-generate-a-secret-key", DEBUG=False)
