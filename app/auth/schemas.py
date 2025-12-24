from typing import Literal
from pydantic import BaseModel, EmailStr
from djast.settings import settings
from auth.models import User


UserRead = User.get_schema(exclude={"password"})


class CreateUserResponse(BaseModel):
    user_id: int


if settings.AUTH_USER_MODEL_TYPE == "django":
    class UserCreate(BaseModel):
        username: str
        email: EmailStr | None = None
        password: str
else:
    class UserCreate(BaseModel):
        email: EmailStr
        password: str


class AccessToken(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    sub: str  # We use 'sub' to store user ID
    type: Literal["access", "refresh"]
    exp: int
    jti: str
    iat: int


class PasswordChange(BaseModel):
    old_password: str
    new_password: str


# Response Schemas
class BaseResponse(BaseModel):
    message: str
