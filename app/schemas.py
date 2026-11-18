from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

Username = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=32)]


class UserCreate(BaseModel):
    """Note: there is deliberately NO role field. Self-registered users are always 'User'."""
    username: Username
    password: str = Field(max_length=128)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class RoleUpdate(BaseModel):
    new_role: str = Field(max_length=32)


class StatusUpdate(BaseModel):
    is_active: bool
