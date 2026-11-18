from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..audit import record
from ..database import get_db
from ..deps import require_admin
from ..models import Role, User, utcnow
from ..schemas import RoleUpdate, StatusUpdate

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return user


def _ensure_not_last_admin(db: Session, target: User) -> None:
    """Fix 13: the system must always keep at least one active administrator."""
    if target.role.name == "Admin" and target.is_active:
        others = (db.query(User).join(Role).filter(Role.name == "Admin", User.is_active.is_(True),
                                                   User.id != target.id).count())
        if others == 0:
            raise HTTPException(400, "Denied: this is the last active administrator.")


def _no_self(admin: User, target: User, what: str) -> None:
    if admin.id == target.id:
        raise HTTPException(400, f"You cannot {what} your own account.")


@router.get("/users")
def list_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    now = utcnow()
    out = []
    for u in db.query(User).order_by(User.id).all():
        locked = bool(u.lockout_until and u.lockout_until > now)
        remaining = int((u.lockout_until - now).total_seconds() // 60) + 1 if locked else 0
        out.append({"id": u.id, "username": u.username, "role": u.role.name,
                    "mfa_enabled": u.mfa_enabled, "is_active": u.is_active,
                    "is_locked": locked, "lockout_remaining": remaining, "is_self": u.id == admin.id})
    return out


@router.put("/users/{user_id}/role")
def update_role(user_id: int, data: RoleUpdate, request: Request,
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = _get_user(db, user_id)
    role = db.query(Role).filter(Role.name == data.new_role).first()
    if not role:
        raise HTTPException(400, "Unknown role")
    _no_self(admin, target, "change the role of")
    if role.name != "Admin":
        _ensure_not_last_admin(db, target)
    old = target.role.name
    target.role_id = role.id
    db.commit()
    record(db, "user.role_change", request=request, actor=admin, target=target.username,
           detail={"from": old, "to": role.name})
    return {"message": f"{target.username} is now {role.name}"}


@router.put("/users/{user_id}/status")
def set_status(user_id: int, data: StatusUpdate, request: Request,
               admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Fix 15: disable / re-enable an account without deleting it."""
    target = _get_user(db, user_id)
    if not data.is_active:
        _no_self(admin, target, "disable")
        _ensure_not_last_admin(db, target)
    target.is_active = data.is_active
    target.token_version += 1                  # tokens issued before this change stop working
    db.commit()
    record(db, "user.enable" if data.is_active else "user.disable", request=request,
           actor=admin, target=target.username)
    return {"message": f"{target.username} {'enabled' if data.is_active else 'disabled'}"}


@router.put("/users/{user_id}/reset-mfa")
def reset_mfa(user_id: int, request: Request, admin: User = Depends(require_admin),
              db: Session = Depends(get_db)):
    target = _get_user(db, user_id)
    _no_self(admin, target, "reset MFA on")
    target.totp_secret = None
    target.mfa_enabled = False
    target.token_version += 1                  # kills the user's current sessions; they must re-enrol
    db.commit()
    record(db, "user.mfa_reset", request=request, actor=admin, target=target.username)
    return {"message": f"MFA reset for {target.username}"}


@router.put("/users/{user_id}/unlock")
def unlock(user_id: int, request: Request, admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    target = _get_user(db, user_id)
    target.failed_attempts = 0
    target.lockout_until = None
    db.commit()
    record(db, "user.unlock", request=request, actor=admin, target=target.username)
    return {"message": f"{target.username} unlocked"}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)):
    target = _get_user(db, user_id)
    _no_self(admin, target, "delete")
    _ensure_not_last_admin(db, target)
    name = target.username
    db.delete(target)
    db.commit()
    record(db, "user.delete", request=request, actor=admin, target=name)
    return {"message": f"{name} deleted"}
