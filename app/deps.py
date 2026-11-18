from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .audit import record
from .database import get_db
from .models import User
from .security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@dataclass
class AuthContext:
    user: User
    payload: dict


def _unauthorized() -> HTTPException:
    return HTTPException(401, "Could not validate credentials",
                         headers={"WWW-Authenticate": "Bearer"})


def get_auth_any_scope(token: str = Depends(oauth2_scheme),
                       db: Session = Depends(get_db)) -> AuthContext:
    """Valid token of ANY scope (used only by /api/me and the MFA enrolment endpoints)."""
    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, ValueError):
        raise _unauthorized()
    user = db.get(User, user_id)
    # Role/active state always come from the DB; token_version lets us revoke tokens instantly.
    if not user or not user.is_active or payload.get("tv") != user.token_version:
        raise _unauthorized()
    return AuthContext(user=user, payload=payload)


def get_current_user(ctx: AuthContext = Depends(get_auth_any_scope)) -> User:
    """Fix 9: the API is only usable with a 'full' token, which is only issued after MFA."""
    if ctx.payload.get("scope") != "full" or not ctx.user.mfa_enabled:
        raise HTTPException(403, "MFA enrolment required before using this resource")
    return ctx.user


class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, request: Request, user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)) -> User:
        if user.role.name not in self.allowed_roles:
            record(db, "access.denied", request=request, actor=user, success=False,
                   detail={"path": request.url.path, "required": self.allowed_roles})
            raise HTTPException(403, "Insufficient permissions: requires "
                                + " or ".join(self.allowed_roles))
        return user


require_admin = RoleChecker(["Admin"])
require_any = RoleChecker(["Admin", "User"])
