from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import record
from ..database import get_db
from ..deps import AuthContext, get_auth_any_scope
from ..schemas import MfaCode, Token
from ..security import (create_access_token, new_totp_secret, qr_data_uri, totp_uri,
                        verify_totp)

router = APIRouter(prefix="/api/mfa", tags=["mfa"])


@router.post("/setup")
def setup(request: Request, ctx: AuthContext = Depends(get_auth_any_scope),
          db: Session = Depends(get_db)):
    """Step 1: create a PENDING secret. MFA is NOT active until /enable proves the user holds it."""
    user = ctx.user
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled. Ask an administrator to reset it first.")
    secret = new_totp_secret()
    user.totp_secret = secret
    db.commit()
    record(db, "mfa.setup_started", request=request, actor=user)
    uri = totp_uri(secret, user.username)
    return {"secret": secret, "otpauth_uri": uri, "qr": qr_data_uri(uri)}


@router.post("/enable", response_model=Token)
def enable(data: MfaCode, request: Request, ctx: AuthContext = Depends(get_auth_any_scope),
           db: Session = Depends(get_db)):
    """Step 2 (fix 10): the user must enter a valid code from their app. Returns a FULL-scope token."""
    user = ctx.user
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled.")
    if not user.totp_secret:
        raise HTTPException(400, "Start MFA setup first.")
    if not verify_totp(user.totp_secret, data.code):
        record(db, "mfa.enable_failed", request=request, actor=user, success=False)
        raise HTTPException(400, "Invalid code. Check your authenticator app and try again.")
    user.mfa_enabled = True
    user.token_version += 1                     # the limited setup token can't be reused
    db.commit()
    record(db, "mfa.enabled", request=request, actor=user)
    return Token(access_token=create_access_token(user, "full"))
