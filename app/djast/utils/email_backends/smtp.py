from __future__ import annotations

import logging
from io import BytesIO
from typing import Any

from fastapi import UploadFile
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType

from djast.utils.email import BaseEmailBackend, EmailMessage

logger = logging.getLogger(__name__)


class SMTPEmailBackend(BaseEmailBackend):
    """Email backend that sends messages via SMTP using fastapi-mail.

    Configure via settings::

        EMAIL_BACKEND = "djast.utils.email_backends.smtp.SMTPEmailBackend"
        EMAIL_HOST = "smtp.example.com"
        EMAIL_PORT = 587
        EMAIL_USE_TLS = True
        EMAIL_HOST_USER = "user@example.com"
        EMAIL_HOST_PASSWORD = "secret"
        DEFAULT_FROM_EMAIL = "noreply@example.com"
    """

    def __init__(self, settings: Any) -> None:
        super().__init__(settings)
        self._config = ConnectionConfig(
            MAIL_USERNAME=settings.EMAIL_HOST_USER,
            MAIL_PASSWORD=settings.EMAIL_HOST_PASSWORD,
            MAIL_FROM=settings.DEFAULT_FROM_EMAIL or settings.EMAIL_HOST_USER,
            MAIL_PORT=settings.EMAIL_PORT,
            MAIL_SERVER=settings.EMAIL_HOST,
            MAIL_STARTTLS=settings.EMAIL_USE_TLS,
            MAIL_SSL_TLS=settings.EMAIL_USE_SSL,
            USE_CREDENTIALS=bool(settings.EMAIL_HOST_USER),
            VALIDATE_CERTS=True,
        )
        self._mailer = FastMail(self._config)

    def _build_schema(self, message: EmailMessage) -> MessageSchema:
        """Convert an ``EmailMessage`` to a fastapi-mail ``MessageSchema``."""
        has_html = bool(message.html_body)
        subtype = MessageType.html if has_html else MessageType.plain

        attachments: list[UploadFile] = []
        for filename, content, mimetype in message.attachments:
            upload = UploadFile(
                filename=filename,
                file=BytesIO(content),
            )
            attachments.append(upload)

        return MessageSchema(
            subject=message.subject,
            recipients=message.to,
            body=message.html_body if has_html else message.body,
            alternative_body=message.body if has_html else None,
            subtype=subtype,
            cc=message.cc,
            bcc=message.bcc,
            reply_to=message.reply_to,
            attachments=attachments,
        )

    async def send_message(self, message: EmailMessage) -> bool:
        """Send a single email via SMTP.  Return ``True`` on success."""
        try:
            schema = self._build_schema(message)
            await self._mailer.send_message(schema)
            return True
        except Exception:
            logger.exception("Failed to send email to %s", message.to)
            return False
