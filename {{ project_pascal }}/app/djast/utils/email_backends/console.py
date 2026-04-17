from __future__ import annotations

import sys
from typing import Any

from djast.utils.email import BaseEmailBackend, EmailMessage


class ConsoleEmailBackend(BaseEmailBackend):
    """Email backend that prints messages to stdout.

    Useful for development and testing — no SMTP server required.
    """

    def __init__(self, settings: Any, *, stream: Any = None) -> None:
        super().__init__(settings)
        self.stream = stream or sys.stdout

    async def send_message(self, message: EmailMessage) -> bool:
        separator = "-" * 60
        lines = [
            separator,
            f"From:    {message.from_email}",
            f"To:      {', '.join(message.to)}",
        ]
        if message.cc:
            lines.append(f"Cc:      {', '.join(message.cc)}")
        if message.bcc:
            lines.append(f"Bcc:     {', '.join(message.bcc)}")
        if message.reply_to:
            lines.append(f"Reply-To:{', '.join(message.reply_to)}")
        lines.append(f"Subject: {message.subject}")
        lines.append(separator)
        if message.body:
            lines.append(message.body)
        if message.html_body:
            lines.append(f"\n[HTML body: {len(message.html_body)} chars]")
            preview = message.html_body[:500]
            lines.append(preview)
            if len(message.html_body) > 500:
                lines.append("... (truncated)")
        if message.attachments:
            lines.append(f"\n[Attachments: {len(message.attachments)}]")
            for filename, content, mimetype in message.attachments:
                lines.append(f"  - {filename} ({mimetype}, {len(content)} bytes)")
        lines.append(separator + "\n")

        self.stream.write("\n".join(lines))
        self.stream.flush()
        return True
