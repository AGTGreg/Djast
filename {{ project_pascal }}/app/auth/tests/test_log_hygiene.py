"""Failure paths must log enough to diagnose, and no more than that."""
import logging

import pytest

from auth import exceptions as auth_exceptions
from auth.utils import auth_backend, oauth
from auth.schemas import TokenData


class _Boom(Exception):
    """Stands in for an exception whose text a third party chose."""


def test_status_suffix_reports_http_status():
    exc = _Boom()
    exc.response = type("R", (), {"status_code": 401})()
    assert oauth._status_suffix(exc) == " (HTTP 401)"


def test_status_suffix_is_empty_without_a_response():
    assert oauth._status_suffix(_Boom("secret-bearing text")) == ""


async def test_oauth_failure_logs_the_type_not_the_text(caplog, monkeypatch):
    """The provider's own error text must not reach the log line.

    An httpx error's message carries the request URL and an Authlib
    ``OAuthError``'s text is chosen by the provider. Neither belongs in a line
    somebody may paste into a ticket.
    """
    secret = "https://provider/token?client_secret=SHOULD-NOT-BE-LOGGED"

    class _Client:
        async def fetch_token(self, *args, **kwargs):
            raise _Boom(secret)

    async def _ok_state(*args, **kwargs):
        return None

    monkeypatch.setattr(oauth, "validate_provider", lambda provider: None)
    monkeypatch.setattr(oauth, "_validate_state", _ok_state)
    monkeypatch.setattr(oauth, "_create_oauth_client", lambda provider: _Client())

    with caplog.at_level(logging.ERROR):
        with pytest.raises(auth_exceptions.OAuthError):
            await oauth.handle_callback(
                "google", "code", "state", "https://test/cb", None,
            )

    assert secret not in caplog.text
    assert "_Boom" in caplog.text, "the exception type is what we do want logged"


async def test_blacklist_failure_is_logged_before_failing_closed(
    caplog, monkeypatch,
):
    """A Redis outage must not reject tokens silently."""
    class _DeadRedis:
        async def get(self, *args, **kwargs):
            raise ConnectionError("redis is down")

    monkeypatch.setattr(auth_backend, "redis_client", _DeadRedis())
    token = TokenData(sub="1", type="access", exp=0, jti="j", iat=0)

    with caplog.at_level(logging.WARNING):
        result = await auth_backend.token_blacklist.is_blacklisted(token)

    assert result is True, "must still fail closed"
    assert "blacklist" in caplog.text.lower()
