"""Tamper-evident audit log (fix 16).
Every row stores a SHA-256 over its own fields plus the previous row's hash.
Editing or deleting any row breaks the chain, which /api/audit-logs/verify detects."""
import hashlib
import json
import threading

from fastapi import Request

from .models import AuditLog, User, utcnow

_lock = threading.Lock()
GENESIS = "0" * 64


def client_ip(request: Request | None) -> str | None:
    return request.client.host if request and request.client else None


def _digest(prev, ts, actor_id, actor_name, action, target, ip, ua, success, detail) -> str:
    payload = json.dumps([prev, ts.isoformat(), actor_id, actor_name, action, target, ip, ua,
                          bool(success), detail], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def record(db, action: str, *, request: Request | None = None, actor: User | None = None,
           actor_name: str | None = None, target: str | None = None,
           success: bool = True, detail: dict | None = None) -> None:
    with _lock:
        last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev = last.hash if last else GENESIS
        ts = utcnow()
        name = (actor.username if actor else actor_name)
        name = name[:64] if name else None
        ua = request.headers.get("user-agent", "")[:200] if request else None
        det = json.dumps(detail, sort_keys=True) if detail else ""
        entry = AuditLog(ts=ts, actor_id=actor.id if actor else None, actor_name=name,
                         action=action, target=(target[:64] if target else None),
                         ip=client_ip(request), user_agent=ua, success=success,
                         detail=det, prev_hash=prev)
        entry.hash = _digest(prev, ts, entry.actor_id, entry.actor_name, action, entry.target,
                             entry.ip, ua, success, det)
        db.add(entry)
        db.commit()


def verify_chain(db) -> dict:
    prev, count = GENESIS, 0
    for e in db.query(AuditLog).order_by(AuditLog.id).yield_per(500):
        count += 1
        if e.prev_hash != prev:
            return {"valid": False, "checked": count, "broken_at": e.id, "head": prev,
                    "reason": "Chain broken: an entry was deleted or reordered."}
        calc = _digest(e.prev_hash, e.ts, e.actor_id, e.actor_name, e.action, e.target,
                       e.ip, e.user_agent, e.success, e.detail or "")
        if calc != e.hash:
            return {"valid": False, "checked": count, "broken_at": e.id, "head": prev,
                    "reason": "An entry was modified after it was written."}
        prev = e.hash
    return {"valid": True, "checked": count, "broken_at": None, "head": prev, "reason": None}
