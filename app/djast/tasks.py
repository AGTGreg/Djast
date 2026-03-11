from __future__ import annotations

from djast.taskiq import broker
from djast.utils.email import EmailMessage, get_email_backend


@broker.task(retry_on_error=True)
async def send_email_task(
    subject: str,
    to: list[str],
    body: str = "",
    html_body: str | None = None,
    from_email: str | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    reply_to: list[str] | None = None,
) -> bool:
    """Send an email via the configured backend, executed as a Taskiq task.

    Attachments are not supported through the task queue because binary data
    should not be serialised into Redis.  When ``EMAIL_USE_TASKIQ`` is enabled,
    calling ``send_email()`` with attachments raises ``ValueError``.
    """
    message = EmailMessage(
        subject=subject,
        to=to,
        body=body,
        html_body=html_body,
        from_email=from_email,
        cc=cc or [],
        bcc=bcc or [],
        reply_to=reply_to or [],
        attachments=[],
    )
    backend = get_email_backend()
    return await backend.send_message(message)
