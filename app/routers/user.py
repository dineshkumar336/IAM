from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..audit import verify_chain
from ..config import settings
from ..database import get_db
from ..deps import AuthContext, get_auth_any_scope, get_current_user, require_admin, require_any
from ..models import AuditLog, User

router = APIRouter(tags=["user"])


@router.get("/api/me")
def me(ctx: AuthContext = Depends(get_auth_any_scope)):
    """Real session facts for the dashboard (fix 18): nothing here is hardcoded in the UI."""
    exp = datetime.fromtimestamp(ctx.payload["exp"], tz=timezone.utc)
    return {
        "username": ctx.user.username,
        "role": ctx.user.role.name,
        "mfa_enabled": ctx.user.mfa_enabled,
        "scope": ctx.payload.get("scope"),
        "session_expires_at": exp.isoformat().replace("+00:00", "Z"),
        "session_minutes": settings.access_token_minutes,
        "last_login_at": ctx.user.prev_login_at.isoformat() + "Z" if ctx.user.prev_login_at else None,
    }


@router.get("/api/user-data")
def user_data(user: User = Depends(require_any)):
    return {"message": "Standard endpoint reached.", "username": user.username,
            "role": user.role.name, "mfa_enabled": user.mfa_enabled}


@router.get("/api/admin-data")
def admin_data(user: User = Depends(require_admin)):
    return {"message": "Protected admin endpoint reached.", "username": user.username,
            "role": user.role.name, "mfa_enabled": user.mfa_enabled}


def _row(r: AuditLog) -> dict:
    return {"id": r.id, "timestamp": r.ts.isoformat() + "Z", "actor": r.actor_name,
            "action": r.action, "target": r.target, "ip": r.ip, "user_agent": r.user_agent,
            "success": r.success, "detail": r.detail or ""}


@router.get("/api/audit-logs")
def audit_logs(limit: int = Query(15, ge=1, le=100), offset: int = Query(0, ge=0),
               user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(AuditLog)
    if user.role.name != "Admin":               # normal users only see their own events
        q = q.filter(AuditLog.actor_id == user.id)
    total = q.count()
    rows = q.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()
    return {"total": total, "limit": limit, "offset": offset, "items": [_row(r) for r in rows]}


@router.get("/api/audit-logs/verify")
def audit_verify(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return verify_chain(db)
