import math
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from ..attempts import ghosts
from ..audit import record
from ..config import settings
from ..database import get_db
from ..models import Role, User, utcnow
from ..schemas import Token, UserCreate
from ..security import (burn_verify, create_access_token, hash_password, password_error,
                        verify_password, verify_totp)

router = APIRouter(tags=["auth"])

# Fix 7: unknown user, wrong password, wrong/missing MFA code, locked and disabled accounts all get
# the SAME kinds of messages ("N attempts remaining" / "try again in M minutes"). Unknown and disabled
# usernames use a look-alike counter (app/attempts.py), so the numbers never reveal which users exist.


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _invalid(remaining: int) -> HTTPException:
    return HTTPException(401, "Invalid credentials. "
                              f"{_plural(max(remaining, 0), 'attempt')} remaining before the account is locked.")


def _locked(minutes: int) -> HTTPException:
    return HTTPException(429, f"Too many failed attempts. Try again in {_plural(minutes, 'minute')}.",
                         headers={"Retry-After": str(minutes * 60)})


@router.post("/register")
def register(data: UserCreate, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(400, "Username already registered")
    problem = password_error(data.password)
    if problem:
        raise HTTPException(400, problem)

    # Fix 1: the role is decided by the server, never by the client.
    role = db.query(Role).filter(Role.name == "User").one()
    user = User(username=data.username, password_hash=hash_password(data.password), role_id=role.id)
    db.add(user)
    db.commit()
    record(db, "user.register", request=request, actor=user)
    return {"message": f"User '{user.username}' created successfully"}


def _register_failure(db: Session, request: Request, user: User, reason: str) -> tuple[bool, int]:
    """Returns (locked_now, attempts_remaining)."""
    user.failed_attempts += 1
    locked = user.failed_attempts >= settings.max_failed_attempts
    remaining = settings.max_failed_attempts - user.failed_attempts
    if locked:
        user.lockout_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
        user.failed_attempts = 0
        remaining = 0
    db.commit()
    record(db, "login.failure", request=request, actor=user, success=False, detail={"reason": reason})
    if locked:
        record(db, "account.locked", request=request, actor=user, success=False,
               detail={"minutes": settings.lockout_minutes})
    return locked, remaining


def _fail_ghost(db: Session, request: Request, name: str, user: User | None, password: str):
    """Unknown or disabled username: same work, same counter, same messages as a real account."""
    burn_verify(password)
    key = name[:64]
    minutes = ghosts.locked_minutes(key)
    if minutes:
        record(db, "login.failure", request=request, actor=user, actor_name=name, success=False,
               detail={"reason": "locked"})
        raise _locked(minutes)
    count, locked = ghosts.fail(key)
    record(db, "login.failure", request=request, actor=user, actor_name=name, success=False,
           detail={"reason": "disabled" if user else "unknown_user"})
    if locked:
        record(db, "account.locked", request=request, actor=user, actor_name=name, success=False,
               detail={"minutes": settings.lockout_minutes})
        raise _locked(settings.lockout_minutes)
    raise _invalid(settings.max_failed_attempts - count)


@router.post("/login", response_model=Token)
def login(request: Request, username: str = Form(..., max_length=64),
          password: str = Form(..., max_length=128), totp_code: str | None = Form(None, max_length=16),
          db: Session = Depends(get_db)):
    name = username.strip()
    user = db.query(User).filter(User.username == name).first()
    now = utcnow()

    if not user or not user.is_active:
        _fail_ghost(db, request, name, user, password)

    if user.lockout_until and user.lockout_until > now:
        burn_verify(password)
        record(db, "login.failure", request=request, actor=user, success=False,
               detail={"reason": "locked"})
        raise _locked(max(1, math.ceil((user.lockout_until - now).total_seconds() / 60)))

    if user.lockout_until:                      # lock expired
        user.lockout_until = None
        user.failed_attempts = 0

    if not verify_password(password, user.password_hash):
        locked, remaining = _register_failure(db, request, user, "wrong_password")
        raise _locked(settings.lockout_minutes) if locked else _invalid(remaining)

    if user.mfa_enabled and not verify_totp(user.totp_secret, totp_code):
        locked, remaining = _register_failure(db, request, user, "mfa_missing" if not totp_code else "mfa_invalid")
        raise _locked(settings.lockout_minutes) if locked else _invalid(remaining)

    user.failed_attempts = 0
    user.lockout_until = None
    user.prev_login_at = user.last_login_at
    user.last_login_at = now
    db.commit()

    scope = "full" if user.mfa_enabled else "mfa_setup"
    record(db, "login.success", request=request, actor=user, detail={"scope": scope})
    return Token(access_token=create_access_token(user, scope))
