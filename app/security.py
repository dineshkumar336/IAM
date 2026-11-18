import base64
import io
import re
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from .config import settings

# ---------- passwords ----------
ph = PasswordHasher()                       # Argon2id
_DUMMY_HASH = ph.hash("dummy-password-used-to-equalise-timing")

PASSWORD_RULES = [
    (r".{8,}", "Password must be at least 8 characters."),
    (r"[A-Z]", "Password must contain an uppercase letter."),
    (r"[a-z]", "Password must contain a lowercase letter."),
    (r"[0-9]", "Password must contain a number."),
    (r"[!@#$%^&*(),.?\":{}|<>]", "Password must contain a special character."),
]


def password_error(pw: str) -> str | None:
    for pattern, message in PASSWORD_RULES:
        if not re.search(pattern, pw):
            return message
    return None


def hash_password(pw: str) -> str:
    return ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return ph.verify(hashed, pw)
    except (VerificationError, InvalidHashError):
        return False


def burn_verify(pw: str) -> None:
    """Do the same Argon2 work for unknown/locked users so response time doesn't leak existence."""
    verify_password(pw, _DUMMY_HASH)


# ---------- tokens ----------
def create_access_token(user, scope: str) -> str:
    """scope='full'      -> MFA verified, can use the API
       scope='mfa_setup' -> password OK but MFA not enrolled yet: can ONLY call the MFA endpoints"""
    now = datetime.now(timezone.utc)
    minutes = settings.access_token_minutes if scope == "full" else 10
    payload = {"sub": str(user.id), "scope": scope, "tv": user.token_version,
               "iat": now, "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    # algorithms is pinned, so "alg: none" and algorithm-confusion tokens are rejected
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"],
                      options={"require": ["exp", "iat", "sub"]})


# ---------- TOTP ----------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str | None, code: str | None) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.totp_issuer)


def qr_data_uri(text: str) -> str:
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=10)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()
