**Email Backend**

This document explains how to configure and use the email backend. It covers settings, sending emails, using templates, attachments, and writing custom backends.

**Files:** `app/djast/utils/email.py`, `app/djast/utils/email_backends/`, `app/djast/settings.py`

**Quick summary:**
- Async-first email sending with pluggable backends.
- Console backend for development (default), SMTP backend for production.
- Jinja2 template support for HTML emails.
- File attachments via `(filename, bytes, mimetype)` tuples.
- Swap backends by changing one setting: `EMAIL_BACKEND`.

---

**Configuration**

Add these to your environment (or `dev.env`):

| Setting | Default | Description |
|---|---|---|
| `EMAIL_BACKEND` | `djast.utils.email_backends.console.ConsoleEmailBackend` | Dotted path to the backend class |
| `EMAIL_HOST` | `""` | SMTP server hostname |
| `EMAIL_PORT` | `587` | SMTP port |
| `EMAIL_USE_TLS` | `True` | Use STARTTLS |
| `EMAIL_USE_SSL` | `False` | Use SSL/TLS |
| `EMAIL_HOST_USER` | `""` | SMTP login username |
| `EMAIL_HOST_PASSWORD` | `""` | SMTP login password |
| `DEFAULT_FROM_EMAIL` | `""` | Default sender address |
| `EMAIL_TEMPLATE_DIR` | `""` | Path to Jinja2 email templates directory |

**Production SMTP example** (`dev.env`):

```
EMAIL_BACKEND=djast.utils.email_backends.smtp.SMTPEmailBackend
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=noreply@example.com
EMAIL_HOST_PASSWORD=your-password
DEFAULT_FROM_EMAIL=noreply@example.com
EMAIL_TEMPLATE_DIR=templates/email
```

---

**Sending emails**

Import the convenience functions and `await` them:

```python
from djast.utils.email import send_email, send_template_email

# Plain text email
await send_email(
    subject="Welcome",
    body="Thanks for signing up!",
    to=["user@example.com"],
)

# With HTML alternative
await send_email(
    subject="Welcome",
    body="Thanks for signing up!",
    to=["user@example.com"],
    html_body="<h1>Welcome!</h1><p>Thanks for signing up.</p>",
)

# With attachments
await send_email(
    subject="Your report",
    body="See attached.",
    to=["user@example.com"],
    attachments=[("report.pdf", pdf_bytes, "application/pdf")],
)

# With CC, BCC, reply-to
await send_email(
    subject="Team update",
    body="Update content",
    to=["team@example.com"],
    cc=["manager@example.com"],
    bcc=["archive@example.com"],
    reply_to=["support@example.com"],
)
```

---

**Template emails**

Create Jinja2 templates in your `EMAIL_TEMPLATE_DIR`:

```html
<!-- templates/email/welcome.html -->
<h1>Hello {{ name }}</h1>
<p>Welcome to {{ site_name }}! Your account is ready.</p>
```

Send it:

```python
from djast.utils.email import send_template_email

await send_template_email(
    subject="Welcome to Djast",
    to=["user@example.com"],
    template_name="welcome.html",
    context={"name": "Greg", "site_name": "Djast"},
)
```

Templates are autoescaped for HTML/XML to prevent XSS in email content.

---

**Using EmailMessage directly**

For more control, create an `EmailMessage` and send it through a backend:

```python
from djast.utils.email import EmailMessage, get_email_backend

message = EmailMessage(
    subject="Direct send",
    to=["user@example.com"],
    body="Plain text body",
    html_body="<p>HTML body</p>",
    from_email="custom-sender@example.com",
    cc=["cc@example.com"],
    attachments=[("file.txt", b"content", "text/plain")],
)

backend = get_email_backend()
success = await backend.send_message(message)
```

---

**Built-in backends**

| Backend | Class path | Use case |
|---|---|---|
| Console | `djast.utils.email_backends.console.ConsoleEmailBackend` | Development — prints emails to stdout |
| SMTP | `djast.utils.email_backends.smtp.SMTPEmailBackend` | Production — sends via SMTP (uses fastapi-mail) |

---

**Writing a custom backend**

Subclass `BaseEmailBackend` and implement `send_message`:

```python
from djast.utils.email import BaseEmailBackend, EmailMessage

class MyBackend(BaseEmailBackend):
    async def send_message(self, message: EmailMessage) -> bool:
        # Your sending logic here (e.g., SendGrid API, Mailgun, SES)
        ...
        return True
```

Then set `EMAIL_BACKEND` to the dotted path of your class:

```
EMAIL_BACKEND=myapp.utils.email_backend.MyBackend
```

The `send_messages` method has a default implementation that loops over messages and calls `send_message`. Override it if your backend supports batch sending.
