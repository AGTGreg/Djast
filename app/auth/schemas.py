from pydantic import BaseModel
from auth.models import User


UserInDB = User.get_schema()
UserRead = User.get_schema(exclude={"password"})


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


class TokenData(BaseModel):
    username: str | None = None
