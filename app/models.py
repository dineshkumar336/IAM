from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base


def utcnow() -> datetime:
    """Naive UTC datetime (what SQLite stores)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(32), unique=True, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role_id = Column(ForeignKey("roles.id"), nullable=False)
    role = relationship("Role", lazy="joined")

    is_active = Column(Boolean, default=True, nullable=False)       # fix 15: disable without deleting
    totp_secret = Column(String, nullable=True)                     # pending until mfa_enabled is True
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    token_version = Column(Integer, default=0, nullable=False)      # bump to kill all issued tokens
    failed_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    prev_login_at = Column(DateTime, nullable=True)         # shown as "Last sign-in" on the dashboard


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, index=True)
    actor_id = Column(Integer, nullable=True, index=True)   # no FK: history must outlive deleted users
    actor_name = Column(String(64), nullable=True)
    action = Column(String(64), nullable=False, index=True)
    target = Column(String(64), nullable=True)
    ip = Column(String(64), nullable=True)
    user_agent = Column(String(200), nullable=True)
    success = Column(Boolean, nullable=False, default=True)
    detail = Column(Text, default="")
    prev_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False)
