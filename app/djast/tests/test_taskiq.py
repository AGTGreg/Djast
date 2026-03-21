from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from djast.settings import settings
from djast.utils.email import (
    BaseEmailBackend,
    EmailMessage,
    _reset_backend,
    send_email,
    send_template_email,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset cached email backend and Taskiq broker between tests."""
    from djast.taskiq import _reset_broker

    _reset_backend()
    _reset_broker()
    yield
    _reset_backend()
    _reset_broker()


# ---------------------------------------------------------------------------
# Broker construction
# ---------------------------------------------------------------------------


class TestBuildBroker:
    def test_empty_url_returns_in_memory(self):
        with patch.object(settings, "TASKIQ_BROKER_URL", ""):
            from djast.taskiq import _build_broker

            broker = _build_broker()
            from taskiq import InMemoryBroker

            assert isinstance(broker, InMemoryBroker)

    def test_memory_url_returns_in_memory(self):
        with patch.object(settings, "TASKIQ_BROKER_URL", "memory://"):
            from djast.taskiq import _build_broker

            broker = _build_broker()
            from taskiq import InMemoryBroker

            assert isinstance(broker, InMemoryBroker)

    def test_redis_url_returns_list_queue_broker(self):
        with (
            patch.object(settings, "TASKIQ_BROKER_URL", "redis://localhost:6379/3"),
            patch.object(settings, "TASKIQ_RESULT_BACKEND_URL", "redis://localhost:6379/4"),
            patch.object(settings, "TASKIQ_RESULT_EX_TIME", 3600),
            patch.object(settings, "TASKIQ_RETRY_MAX_ATTEMPTS", 3),
            patch.object(settings, "TASKIQ_RETRY_DELAY", 5.0),
            patch.object(settings, "TASKIQ_RETRY_MAX_DELAY", 120.0),
        ):
            from djast.taskiq import _build_broker

            broker = _build_broker()
            from taskiq_redis import ListQueueBroker

            assert isinstance(broker, ListQueueBroker)

    def test_retry_disabled_when_max_attempts_zero(self):
        with (
            patch.object(settings, "TASKIQ_BROKER_URL", "redis://localhost:6379/3"),
            patch.object(settings, "TASKIQ_RESULT_BACKEND_URL", "redis://localhost:6379/4"),
            patch.object(settings, "TASKIQ_RESULT_EX_TIME", 3600),
            patch.object(settings, "TASKIQ_RETRY_MAX_ATTEMPTS", 0),
            patch.object(settings, "TASKIQ_RETRY_DELAY", 5.0),
            patch.object(settings, "TASKIQ_RETRY_MAX_DELAY", 120.0),
        ):
            from djast.taskiq import _build_broker

            broker = _build_broker()
            from taskiq.middlewares.smart_retry_middleware import SmartRetryMiddleware

            has_retry = any(
                isinstance(m, SmartRetryMiddleware)
                for m in broker.middlewares
            )
            assert not has_retry


class TestResetBroker:
    def test_reset_replaces_with_in_memory(self):
        from djast import taskiq as taskiq_module
        from djast.taskiq import _reset_broker

        _reset_broker()

        from taskiq import InMemoryBroker

        assert isinstance(taskiq_module.broker, InMemoryBroker)


# ---------------------------------------------------------------------------
# send_email_task
# ---------------------------------------------------------------------------


class TestSendEmailTask:
    @pytest.mark.asyncio
    async def test_calls_backend_with_correct_message(self):
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with patch("djast.tasks.get_email_backend", return_value=mock_backend):
            from djast.tasks import send_email_task

            result = await send_email_task(
                subject="Test",
                to=["user@example.com"],
                body="Hello",
                html_body="<p>Hello</p>",
                from_email="sender@example.com",
                cc=["cc@example.com"],
                bcc=["bcc@example.com"],
                reply_to=["reply@example.com"],
            )

        assert result is True
        mock_backend.send_message.assert_called_once()
        msg = mock_backend.send_message.call_args[0][0]
        assert isinstance(msg, EmailMessage)
        assert msg.subject == "Test"
        assert msg.to == ["user@example.com"]
        assert msg.body == "Hello"
        assert msg.html_body == "<p>Hello</p>"
        assert msg.cc == ["cc@example.com"]
        assert msg.bcc == ["bcc@example.com"]
        assert msg.reply_to == ["reply@example.com"]
        assert msg.attachments == []

    @pytest.mark.asyncio
    async def test_defaults_optional_fields(self):
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with patch("djast.tasks.get_email_backend", return_value=mock_backend):
            from djast.tasks import send_email_task

            await send_email_task(subject="Test", to=["u@e.com"])

        msg = mock_backend.send_message.call_args[0][0]
        assert msg.body == ""
        assert msg.html_body is None
        assert msg.cc == []
        assert msg.bcc == []
        assert msg.reply_to == []


# ---------------------------------------------------------------------------
# Email Taskiq routing in send_email()
# ---------------------------------------------------------------------------


class TestEmailTaskiqRouting:
    @pytest.mark.asyncio
    async def test_routes_through_taskiq_when_enabled(self):
        """EMAIL_USE_TASKIQ=True + SMTP backend → dispatches via Taskiq."""
        mock_kiq = AsyncMock()

        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", True),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.smtp.SMTPEmailBackend",
            ),
            patch("djast.tasks.send_email_task") as mock_task,
        ):
            mock_task.kiq = mock_kiq
            # Re-import to pick up the patched task
            with patch("djast.utils.email.send_email_task", mock_task, create=True):
                # We need to patch at the import location
                pass

            # Patch at the point of lazy import inside send_email
            with patch.dict(
                "sys.modules",
                {"djast.tasks": MagicMock(send_email_task=MagicMock(kiq=mock_kiq))},
            ):
                result = await send_email(
                    subject="Test",
                    body="Hello",
                    to=["user@example.com"],
                )

        assert result is True
        mock_kiq.assert_called_once_with(
            subject="Test",
            to=["user@example.com"],
            body="Hello",
            html_body=None,
            from_email=None,
            cc=None,
            bcc=None,
            reply_to=None,
        )

    @pytest.mark.asyncio
    async def test_sends_directly_when_console_backend(self):
        """EMAIL_USE_TASKIQ=True + console backend → sends directly."""
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", True),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.console.ConsoleEmailBackend",
            ),
            patch("djast.utils.email.get_email_backend", return_value=mock_backend),
        ):
            result = await send_email(
                subject="Test",
                body="Hello",
                to=["user@example.com"],
            )

        assert result is True
        mock_backend.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_raises_on_attachments_with_taskiq(self):
        """EMAIL_USE_TASKIQ=True + attachments → raises ValueError."""
        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", True),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.smtp.SMTPEmailBackend",
            ),
        ):
            with pytest.raises(ValueError, match="attachments are not supported"):
                await send_email(
                    subject="Test",
                    body="Hello",
                    to=["user@example.com"],
                    attachments=[("file.txt", b"data", "text/plain")],
                )

    @pytest.mark.asyncio
    async def test_sends_directly_when_taskiq_disabled(self):
        """EMAIL_USE_TASKIQ=False → sends directly regardless of backend."""
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", False),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.smtp.SMTPEmailBackend",
            ),
            patch("djast.utils.email.get_email_backend", return_value=mock_backend),
        ):
            result = await send_email(
                subject="Test",
                body="Hello",
                to=["user@example.com"],
            )

        assert result is True
        mock_backend.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_attachments_work_when_taskiq_disabled(self):
        """EMAIL_USE_TASKIQ=False + attachments → sends directly with attachments."""
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", False),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.smtp.SMTPEmailBackend",
            ),
            patch("djast.utils.email.get_email_backend", return_value=mock_backend),
        ):
            result = await send_email(
                subject="Test",
                body="Hello",
                to=["user@example.com"],
                attachments=[("file.txt", b"data", "text/plain")],
            )

        assert result is True
        msg = mock_backend.send_message.call_args[0][0]
        assert len(msg.attachments) == 1

    @pytest.mark.asyncio
    async def test_console_allows_attachments_even_with_taskiq_enabled(self):
        """EMAIL_USE_TASKIQ=True + console backend + attachments → sends directly."""
        mock_backend = MagicMock(spec=BaseEmailBackend)
        mock_backend.send_message = AsyncMock(return_value=True)

        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", True),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.console.ConsoleEmailBackend",
            ),
            patch("djast.utils.email.get_email_backend", return_value=mock_backend),
        ):
            result = await send_email(
                subject="Test",
                body="Hello",
                to=["user@example.com"],
                attachments=[("file.txt", b"data", "text/plain")],
            )

        assert result is True
        msg = mock_backend.send_message.call_args[0][0]
        assert len(msg.attachments) == 1


class TestSendTemplateEmailTaskiqRouting:
    @pytest.mark.asyncio
    async def test_template_email_routes_through_taskiq(self):
        """send_template_email inherits Taskiq routing via send_email."""
        mock_kiq = AsyncMock()

        with (
            patch.object(settings, "EMAIL_USE_TASKIQ", True),
            patch.object(
                settings,
                "EMAIL_BACKEND",
                "djast.utils.email_backends.smtp.SMTPEmailBackend",
            ),
            patch.object(settings, "DEFAULT_FROM_EMAIL", "noreply@example.com"),
            patch(
                "djast.utils.email.render_email_template",
                return_value="<h1>Hello</h1>",
            ),
            patch.dict(
                "sys.modules",
                {"djast.tasks": MagicMock(send_email_task=MagicMock(kiq=mock_kiq))},
            ),
        ):
            result = await send_template_email(
                subject="Welcome",
                to=["user@example.com"],
                template_name="welcome.html",
                context={"name": "Greg"},
            )

        assert result is True
        mock_kiq.assert_called_once()
        call_kwargs = mock_kiq.call_args[1]
        assert call_kwargs["html_body"] == "<h1>Hello</h1>"

