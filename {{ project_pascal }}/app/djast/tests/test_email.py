import io
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from djast.settings import settings
from djast.utils.email import (
    BaseEmailBackend,
    EmailMessage,
    _reset_backend,
    _reset_jinja_env,
    get_email_backend,
    render_email_template,
    send_email,
    send_template_email,
)
from djast.utils.email_backends.console import ConsoleEmailBackend


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset cached backend and Jinja env between tests."""
    _reset_backend()
    _reset_jinja_env()
    yield
    _reset_backend()
    _reset_jinja_env()


@pytest.fixture
def console_backend():
    """Return a ConsoleEmailBackend writing to a StringIO stream."""
    stream = io.StringIO()
    return ConsoleEmailBackend(settings, stream=stream), stream


@pytest.fixture
def template_dir():
    """Create a temporary directory with a sample email template."""
    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "welcome.html")
        with open(template_path, "w") as f:
            f.write("<h1>Hello {{ name }}</h1><p>Welcome to {{ site }}!</p>")
        yield tmpdir


# ---------------------------------------------------------------------------
# EmailMessage
# ---------------------------------------------------------------------------


class TestEmailMessage:
    def test_basic_creation(self):
        msg = EmailMessage(subject="Test", to=["user@example.com"], body="Hello")
        assert msg.subject == "Test"
        assert msg.to == ["user@example.com"]
        assert msg.body == "Hello"
        assert msg.html_body is None
        assert msg.cc == []
        assert msg.bcc == []
        assert msg.reply_to == []
        assert msg.attachments == []

    def test_from_email_defaults_to_setting(self):
        with patch.object(settings, "DEFAULT_FROM_EMAIL", "default@example.com"):
            msg = EmailMessage(subject="Test", to=["user@example.com"])
            assert msg.from_email == "default@example.com"

    def test_from_email_explicit(self):
        msg = EmailMessage(
            subject="Test",
            to=["user@example.com"],
            from_email="custom@example.com",
        )
        assert msg.from_email == "custom@example.com"

    def test_all_fields(self):
        attachment = ("file.txt", b"content", "text/plain")
        msg = EmailMessage(
            subject="Full",
            to=["a@b.com"],
            body="text",
            html_body="<p>html</p>",
            from_email="from@b.com",
            cc=["cc@b.com"],
            bcc=["bcc@b.com"],
            reply_to=["reply@b.com"],
            attachments=[attachment],
        )
        assert msg.cc == ["cc@b.com"]
        assert msg.bcc == ["bcc@b.com"]
        assert msg.reply_to == ["reply@b.com"]
        assert len(msg.attachments) == 1
        assert msg.attachments[0][0] == "file.txt"


# ---------------------------------------------------------------------------
# ConsoleEmailBackend
# ---------------------------------------------------------------------------


class TestConsoleEmailBackend:
    @pytest.mark.asyncio
    async def test_send_message_prints_output(self, console_backend):
        backend, stream = console_backend
        msg = EmailMessage(
            subject="Hello",
            to=["user@example.com"],
            body="Test body",
            from_email="sender@example.com",
        )
        result = await backend.send_message(msg)
        assert result is True
        output = stream.getvalue()
        assert "Hello" in output
        assert "user@example.com" in output
        assert "sender@example.com" in output
        assert "Test body" in output

    @pytest.mark.asyncio
    async def test_send_message_with_html(self, console_backend):
        backend, stream = console_backend
        msg = EmailMessage(
            subject="HTML",
            to=["user@example.com"],
            body="plain",
            html_body="<h1>Rich</h1>",
            from_email="s@e.com",
        )
        await backend.send_message(msg)
        output = stream.getvalue()
        assert "[HTML body:" in output
        assert "<h1>Rich</h1>" in output

    @pytest.mark.asyncio
    async def test_send_message_with_cc_bcc(self, console_backend):
        backend, stream = console_backend
        msg = EmailMessage(
            subject="CC",
            to=["to@e.com"],
            body="body",
            from_email="f@e.com",
            cc=["cc@e.com"],
            bcc=["bcc@e.com"],
        )
        await backend.send_message(msg)
        output = stream.getvalue()
        assert "cc@e.com" in output
        assert "bcc@e.com" in output

    @pytest.mark.asyncio
    async def test_send_message_with_attachments(self, console_backend):
        backend, stream = console_backend
        msg = EmailMessage(
            subject="Attach",
            to=["to@e.com"],
            body="body",
            from_email="f@e.com",
            attachments=[("report.pdf", b"fake-pdf-data", "application/pdf")],
        )
        await backend.send_message(msg)
        output = stream.getvalue()
        assert "report.pdf" in output
        assert "application/pdf" in output

    @pytest.mark.asyncio
    async def test_send_messages_returns_count(self, console_backend):
        backend, _ = console_backend
        messages = [
            EmailMessage(subject=f"Msg {i}", to=["u@e.com"], body="b", from_email="f@e.com")
            for i in range(3)
        ]
        count = await backend.send_messages(messages)
        assert count == 3


# ---------------------------------------------------------------------------
# get_email_backend
# ---------------------------------------------------------------------------


class TestGetEmailBackend:
    def test_loads_console_backend(self):
        with patch.object(
            settings,
            "EMAIL_BACKEND",
            "djast.utils.email_backends.console.ConsoleEmailBackend",
        ):
            backend = get_email_backend()
            assert isinstance(backend, ConsoleEmailBackend)

    def test_caches_singleton(self):
        with patch.object(
            settings,
            "EMAIL_BACKEND",
            "djast.utils.email_backends.console.ConsoleEmailBackend",
        ):
            b1 = get_email_backend()
            b2 = get_email_backend()
            assert b1 is b2

    def test_invalid_path_raises(self):
        with patch.object(settings, "EMAIL_BACKEND", "nonexistent.module.Class"):
            with pytest.raises(ImportError):
                _reset_backend()
                get_email_backend()

    def test_non_backend_class_raises(self):
        with patch.object(settings, "EMAIL_BACKEND", "os.path.join"):
            with pytest.raises(TypeError, match="BaseEmailBackend"):
                _reset_backend()
                get_email_backend()


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------


class TestTemplateRendering:
    def test_render_template(self, template_dir):
        with patch.object(settings, "EMAIL_TEMPLATE_DIR", template_dir):
            html = render_email_template("welcome.html", {"name": "Greg", "site": "Djast"})
            assert "<h1>Hello Greg</h1>" in html
            assert "Welcome to Djast!" in html

    def test_missing_template_dir_raises(self):
        with patch.object(settings, "EMAIL_TEMPLATE_DIR", ""):
            with pytest.raises(ValueError, match="EMAIL_TEMPLATE_DIR"):
                render_email_template("welcome.html", {})

    def test_nonexistent_template_dir_raises(self, tmp_path):
        fake_dir = str(tmp_path / "nonexistent")
        with patch.object(settings, "EMAIL_TEMPLATE_DIR", fake_dir):
            with pytest.raises(FileNotFoundError):
                render_email_template("welcome.html", {})

    def test_autoescape_html(self, template_dir):
        with patch.object(settings, "EMAIL_TEMPLATE_DIR", template_dir):
            html = render_email_template("welcome.html", {"name": "<script>alert(1)</script>", "site": "X"})
            assert "<script>" not in html
            assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


class TestSendEmail:
    @pytest.mark.asyncio
    async def test_send_email(self):
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with patch("djast.utils.email.get_email_backend", return_value=mock_backend):
            result = await send_email(
                subject="Test",
                body="Hello",
                to=["user@example.com"],
            )
            assert result is True
            mock_backend.send_message.assert_called_once()
            msg = mock_backend.send_message.call_args[0][0]
            assert isinstance(msg, EmailMessage)
            assert msg.subject == "Test"
            assert msg.to == ["user@example.com"]

    @pytest.mark.asyncio
    async def test_send_template_email(self, template_dir):
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with (
            patch("djast.utils.email.get_email_backend", return_value=mock_backend),
            patch.object(settings, "EMAIL_TEMPLATE_DIR", template_dir),
        ):
            result = await send_template_email(
                subject="Welcome",
                to=["user@example.com"],
                template_name="welcome.html",
                context={"name": "Greg", "site": "Djast"},
            )
            assert result is True
            msg = mock_backend.send_message.call_args[0][0]
            assert "<h1>Hello Greg</h1>" in msg.html_body


# ---------------------------------------------------------------------------
# SMTPEmailBackend config mapping
# ---------------------------------------------------------------------------


class TestSMTPEmailBackendConfig:
    def test_config_mapping(self):
        mock_settings = MagicMock()
        mock_settings.EMAIL_HOST = "smtp.example.com"
        mock_settings.EMAIL_PORT = 587
        mock_settings.EMAIL_USE_TLS = True
        mock_settings.EMAIL_USE_SSL = False
        mock_settings.EMAIL_HOST_USER = "user@example.com"
        mock_settings.EMAIL_HOST_PASSWORD = "secret"
        mock_settings.DEFAULT_FROM_EMAIL = "noreply@example.com"

        with patch(
            "djast.utils.email_backends.smtp.ConnectionConfig"
        ) as MockConfig, patch(
            "djast.utils.email_backends.smtp.FastMail"
        ):
            from djast.utils.email_backends.smtp import SMTPEmailBackend

            SMTPEmailBackend(mock_settings)

            MockConfig.assert_called_once_with(
                MAIL_USERNAME="user@example.com",
                MAIL_PASSWORD="secret",
                MAIL_FROM="noreply@example.com",
                MAIL_PORT=587,
                MAIL_SERVER="smtp.example.com",
                MAIL_STARTTLS=True,
                MAIL_SSL_TLS=False,
                USE_CREDENTIALS=True,
                VALIDATE_CERTS=True,
            )

    @pytest.mark.asyncio
    async def test_send_message_calls_fastmail(self):
        mock_settings = MagicMock()
        mock_settings.EMAIL_HOST = "smtp.example.com"
        mock_settings.EMAIL_PORT = 587
        mock_settings.EMAIL_USE_TLS = True
        mock_settings.EMAIL_USE_SSL = False
        mock_settings.EMAIL_HOST_USER = "user@example.com"
        mock_settings.EMAIL_HOST_PASSWORD = "secret"
        mock_settings.DEFAULT_FROM_EMAIL = "noreply@example.com"

        mock_fastmail = MagicMock()
        mock_fastmail.send_message = AsyncMock()

        with patch(
            "djast.utils.email_backends.smtp.ConnectionConfig"
        ), patch(
            "djast.utils.email_backends.smtp.FastMail", return_value=mock_fastmail
        ):
            from djast.utils.email_backends.smtp import SMTPEmailBackend

            backend = SMTPEmailBackend(mock_settings)
            msg = EmailMessage(
                subject="Test",
                to=["user@example.com"],
                body="Hello",
                from_email="sender@example.com",
            )
            result = await backend.send_message(msg)
            assert result is True
            mock_fastmail.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_returns_false_on_error(self):
        mock_settings = MagicMock()
        mock_settings.EMAIL_HOST = "smtp.example.com"
        mock_settings.EMAIL_PORT = 587
        mock_settings.EMAIL_USE_TLS = True
        mock_settings.EMAIL_USE_SSL = False
        mock_settings.EMAIL_HOST_USER = "user@example.com"
        mock_settings.EMAIL_HOST_PASSWORD = "secret"
        mock_settings.DEFAULT_FROM_EMAIL = "noreply@example.com"

        mock_fastmail = MagicMock()
        mock_fastmail.send_message = AsyncMock(side_effect=ConnectionError("SMTP down"))

        with patch(
            "djast.utils.email_backends.smtp.ConnectionConfig"
        ), patch(
            "djast.utils.email_backends.smtp.FastMail", return_value=mock_fastmail
        ):
            from djast.utils.email_backends.smtp import SMTPEmailBackend

            backend = SMTPEmailBackend(mock_settings)
            msg = EmailMessage(
                subject="Test",
                to=["user@example.com"],
                body="Hello",
                from_email="sender@example.com",
            )
            result = await backend.send_message(msg)
            assert result is False
