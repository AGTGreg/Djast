from typing import Literal
from pydantic import BaseModel, EmailStr, Field
from djast.settings import settings
from auth.models import User


UserRead = User.get_schema(exclude={"password"})


class CreateUserResponse(BaseModel):
    user_id: int


if settings.AUTH_USER_MODEL_TYPE == "django":
    class UserCreate(BaseModel):
        username: str = Field(
            min_length=1, max_length=150, pattern=r"^[\w.@+\-]+$"
        )
        email: EmailStr | None = None
        password: str = Field(max_length=100)
else:
    class UserCreate(BaseModel):
        email: EmailStr
        password: str = Field(max_length=100)


class AccessToken(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class TokenData(BaseModel):
    sub: str  # We use 'sub' to store user ID
    type: Literal["access", "refresh"]
    exp: int
    jti: str
    iat: int


class PasswordChange(BaseModel):
    old_password: str = Field(max_length=100)
    new_password: str = Field(max_length=100)


class SetPassword(BaseModel):
    new_password: str = Field(max_length=100)


class VerifyEmailRequest(BaseModel):
    token: str = Field(max_length=512)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(max_length=512)
    new_password: str = Field(max_length=100)


# Response Schemas
class BaseResponse(BaseModel):
    message: str
