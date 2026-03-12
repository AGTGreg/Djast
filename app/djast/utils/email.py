from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from djast.settings import settings


@dataclass
class EmailMessage:
    """Represents an email message."""

    subject: str
    to: list[str]
    body: str = ""
    html_body: str | None = None
    from_email: str | None = None
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    attachments: list[tuple[str, bytes, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.from_email:
            self.from_email = settings.DEFAULT_FROM_EMAIL


class BaseEmailBackend(ABC):
    """Abstract base class for email backends.

    Subclass this and implement ``send_message`` / ``send_messages`` to create
    a custom email backend.  Set ``settings.EMAIL_BACKEND`` to the dotted
    import path of your subclass to activate it.
    """

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    @abstractmethod
    async def send_message(self, message: EmailMessage) -> bool:
        """Send a single email.  Return ``True`` on success."""

    async def send_messages(self, messages: list[EmailMessage]) -> int:
        """Send multiple emails.  Return the number of successful sends."""
        sent = 0
        for message in messages:
            if await self.send_message(message):
                sent += 1
        return sent


# ---------------------------------------------------------------------------
# Backend loader
# ---------------------------------------------------------------------------

_backend_instance: BaseEmailBackend | None = None


def _import_string(dotted_path: str) -> type:
    """Import a class from a dotted module path (e.g. 'pkg.mod.Class')."""
    module_path, _, class_name = dotted_path.rpartition(".")
    if not module_path:
        raise ImportError(f"Invalid dotted path: {dotted_path!r}")
    module = importlib.import_module(module_path)
    try:
        return getattr(module, class_name)
    except AttributeError:
        raise ImportError(
            f"Module {module_path!r} has no attribute {class_name!r}"
        )


def get_email_backend() -> BaseEmailBackend:
    """Return the configured email backend (cached singleton)."""
    global _backend_instance
    if _backend_instance is None:
        backend_cls = _import_string(settings.EMAIL_BACKEND)
        if not (isinstance(backend_cls, type) and issubclass(backend_cls, BaseEmailBackend)):
            raise TypeError(
                f"{settings.EMAIL_BACKEND!r} is not a BaseEmailBackend subclass"
            )
        _backend_instance = backend_cls(settings)
    return _backend_instance


def _reset_backend() -> None:
    """Reset the cached backend (used by tests)."""
    global _backend_instance
    _backend_instance = None


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

_jinja_env: Environment | None = None


def _get_jinja_env() -> Environment:
    """Return (and cache) a Jinja2 environment for email templates."""
    global _jinja_env
    if _jinja_env is None:
        template_dir = settings.EMAIL_TEMPLATE_DIR
        if not template_dir:
            raise ValueError(
                "settings.EMAIL_TEMPLATE_DIR must be set to use email templates"
            )
        path = Path(template_dir)
        if not path.is_dir():
            raise FileNotFoundError(
                f"Email template directory does not exist: {path}"
            )
        _jinja_env = Environment(
            loader=FileSystemLoader(str(path)),
            autoescape=select_autoescape(["html", "xml"]),
        )
    return _jinja_env


def _reset_jinja_env() -> None:
    """Reset the cached Jinja2 environment (used by tests)."""
    global _jinja_env
    _jinja_env = None


def render_email_template(template_name: str, context: dict[str, Any]) -> str:
    """Render a Jinja2 template and return the resulting HTML string."""
    env = _get_jinja_env()
    template = env.get_template(template_name)
    return template.render(context)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def _is_console_backend() -> bool:
    """Return ``True`` if the configured email backend is the console backend."""
    return "console" in settings.EMAIL_BACKEND.lower()


async def send_email(
    subject: str,
    body: str,
    to: list[str],
    *,
    html_body: str | None = None,
    from_email: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to: list[str] | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> bool:
    """Send a single email using the configured backend.

    When ``settings.EMAIL_USE_TASKIQ`` is ``True`` and the active backend is
    not the console backend, the email is dispatched via Taskiq as a background
    task.  Emails with attachments are **not supported** through Taskiq — a
    ``ValueError`` is raised if attachments are provided while the setting is
    enabled.
    """
    # Taskiq path: dispatch to task queue (non-console backends only)
    if settings.EMAIL_USE_TASKIQ and not _is_console_backend():
        if attachments:
            raise ValueError(
                "Email attachments are not supported when EMAIL_USE_TASKIQ "
                "is enabled. Either send without attachments or set "
                "EMAIL_USE_TASKIQ=False."
            )
        from djast.tasks import send_email_task

        await send_email_task.kiq(
            subject=subject,
            to=to,
            body=body,
            html_body=html_body,
            from_email=from_email,
            cc=cc,
            bcc=bcc,
            reply_to=reply_to,
        )
        return True

    # Direct path: inline send
    message = EmailMessage(
        subject=subject,
        to=to,
        body=body,
        html_body=html_body,
        from_email=from_email,
        cc=cc or [],
        bcc=bcc or [],
        reply_to=reply_to or [],
        attachments=attachments or [],
    )
    backend = get_email_backend()
    return await backend.send_message(message)


async def send_template_email(
    subject: str,
    to: list[str],
    template_name: str,
    context: dict[str, Any],
    *,
    body: str = "",
    from_email: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to: list[str] | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> bool:
    """Render a Jinja2 template and send as an HTML email."""
    html_body = render_email_template(template_name, context)
    return await send_email(
        subject=subject,
        body=body,
        to=to,
        html_body=html_body,
        from_email=from_email,
        cc=cc,
        bcc=bcc,
        reply_to=reply_to,
        attachments=attachments,
    )
