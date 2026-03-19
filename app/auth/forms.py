from fastapi import Form
from fastapi.security import OAuth2PasswordRequestForm

from djast.settings import settings


# Resolved once at import time — used by auth and admin views.
LoginForm = OAuth2PasswordRequestForm
if settings.AUTH_USER_MODEL_TYPE == "email":
    LoginForm = OAuth2EmailRequestForm


class OAuth2EmailRequestForm:
    """
    This is a dependency class, use it like:
    `def login(form_data: OAuth2EmailRequestForm = Depends())`
    It creates a form that requests `email` and `password`.
    """
    def __init__(
        self,
        grant_type: str = Form(default=None, pattern="password"),
        email: str = Form(),
        password: str = Form(max_length=100),
        scope: str = Form(default=""),
        client_id: str | None = Form(default=None),
        client_secret: str | None = Form(default=None),
    ):
        self.grant_type = grant_type
        # OAuth2 spec requires 'username' field. We map email to it
        # so downstream code remains generic.
        self.username = email
        self.password = password
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret