import re
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel
import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

SECRET_KEY = "iam-internship-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

SQLALCHEMY_DATABASE_URL = "sqlite:///./iam_tool.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    totp_secret = Column(String, nullable=True)
    role_id = Column(Integer, ForeignKey("roles.id"))
    role = relationship("Role")
    failed_attempts = Column(Integer, default=0)
    lockout_until = Column(DateTime, nullable=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

def init_db():
    db = SessionLocal()
    if not db.query(Role).first():
        db.add_all([Role(name="Admin"), Role(name="User")])
        db.commit()
    db.close()

init_db()

app = FastAPI(
    title="IAM API", 
    docs_url=None, 
    redoc_url=None, 
    openapi_url=None
)
app.mount("/static", StaticFiles(directory="static"), name="static")

ph = PasswordHasher()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def log_audit(db: Session, user_id: int, action: str):
    log = AuditLog(user_id=user_id, action=action)
    db.add(log)
    db.commit()

@app.get("/", include_in_schema=False)
def serve_dashboard():
    with open("static/index.html", "r") as f:
        return HTMLResponse(content=f.read(), status_code=200)

class UserCreate(BaseModel):
    username: str
    password: str
    role_name: str = "User"

class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    if len(user.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    if not re.search(r"[A-Z]", user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"\d", user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character.")
    
    role = db.query(Role).filter(Role.name == user.role_name).first()
    if not role:
        raise HTTPException(status_code=400, detail="Invalid role specified")
        
    hashed_password = ph.hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password, role_id=role.id)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    log_audit(db, new_user.id, "User Registered")
    return {"message": f"User '{user.username}' created successfully as {user.role_name}"}

@app.post("/login", response_model=Token)
def login(username: str = Form(...), password: str = Form(...), totp_code: str = Form(None), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        log_audit(db, None, f"Failed login: Unknown user '{username}'")
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    if user.lockout_until:
        aware_lockout = user.lockout_until.replace(tzinfo=timezone.utc)
        if aware_lockout > datetime.now(timezone.utc):
            remaining = int((aware_lockout - datetime.now(timezone.utc)).total_seconds() // 60) + 1
            raise HTTPException(status_code=403, detail=f"Account locked. Try again in {remaining} minutes.")
        else:
            user.failed_attempts = 0
            user.lockout_until = None
            db.commit()

    def handle_failed_attempt(base_msg: str):
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            log_audit(db, user.id, "Account locked (15 mins) due to multiple failed attempts")
            db.commit()
            raise HTTPException(status_code=403, detail="Account locked. Try again in 15 minutes.")
        db.commit()
        attempts_left = 5 - user.failed_attempts
        raise HTTPException(status_code=401, detail=f"{base_msg} {attempts_left} attempts remaining.")
        
    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        log_audit(db, user.id, "Failed login: Incorrect password")
        handle_failed_attempt("Invalid credentials.")
        
    if user.totp_secret:
        if not totp_code:
            raise HTTPException(status_code=401, detail="MFA code required")
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(totp_code):
            log_audit(db, user.id, "Failed login: Invalid MFA code")
            handle_failed_attempt("Invalid MFA code.")

    user.failed_attempts = 0
    user.lockout_until = None
    db.commit()

    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": user.username, "role": user.role.name, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    log_audit(db, user.id, "Successful Login")
    return {"access_token": encoded_jwt, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        if user.role.name not in self.allowed_roles:
            log_audit(db, user.id, f"Unauthorized access attempt to {self.allowed_roles}")
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

@app.get("/api/user-data")
def read_user_data(user: User = Depends(RoleChecker(["Admin", "User"]))):
    return {"message": "Standard resource accessed.", "username": user.username, "role": user.role.name, "mfa_enabled": bool(user.totp_secret)}

@app.get("/api/admin-data")
def read_admin_data(user: User = Depends(RoleChecker(["Admin"]))):
    return {"message": "Sensitive admin resource accessed.", "username": user.username, "role": user.role.name}

@app.post("/api/setup-mfa")
def setup_mfa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.totp_secret:
        return {"message": "MFA is already enabled."}
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.commit()
    log_audit(db, user.id, "Enabled MFA")
    return {"secret": secret, "message": "MFA enabled successfully."}

@app.get("/api/audit-logs")
def get_audit_logs(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role.name == "Admin":
        logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(15).all()
    else:
        logs = db.query(AuditLog).filter(AuditLog.user_id == user.id).order_by(AuditLog.timestamp.desc()).limit(15).all()
    return [{"id": log.id, "action": log.action, "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S")} for log in logs]

class RoleUpdate(BaseModel):
    new_role: str

@app.get("/api/admin/users")
def get_all_users(admin: User = Depends(RoleChecker(["Admin"])), db: Session = Depends(get_db)):
    users = db.query(User).all()
    
    current_time = datetime.now(timezone.utc)
    user_list = []
    for u in users:
        is_locked = False
        remaining_mins = 0
        if u.lockout_until:
            aware_lockout = u.lockout_until.replace(tzinfo=timezone.utc)
            if aware_lockout > current_time:
                is_locked = True
                remaining_mins = int((aware_lockout - current_time).total_seconds() // 60) + 1
            
        user_list.append({
            "id": u.id, 
            "username": u.username, 
            "role": u.role.name, 
            "mfa_enabled": bool(u.totp_secret),
            "is_locked": is_locked,
            "lockout_remaining": remaining_mins
        })
    return user_list

@app.put("/api/admin/users/{target_user_id}/role")
def update_user_role(target_user_id: int, role_data: RoleUpdate, admin: User = Depends(RoleChecker(["Admin"])), db: Session = Depends(get_db)):
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    new_role_obj = db.query(Role).filter(Role.name == role_data.new_role).first()
    if not new_role_obj:
        raise HTTPException(status_code=400, detail="Invalid role")

    target_user.role_id = new_role_obj.id
    db.commit()
    log_audit(db, admin.id, f"Changed role of user {target_user.username} to {role_data.new_role}")
    return {"message": f"User updated to {role_data.new_role}"}

@app.put("/api/admin/users/{target_user_id}/reset-mfa")
def reset_user_mfa(target_user_id: int, admin: User = Depends(RoleChecker(["Admin"])), db: Session = Depends(get_db)):
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    target_user.totp_secret = None
    db.commit()
    log_audit(db, admin.id, f"Admin disabled MFA for user {target_user.username}")
    return {"message": f"MFA disabled for {target_user.username}. They must reconfigure it on next login."}

@app.put("/api/admin/users/{target_user_id}/unlock")
def unlock_user(target_user_id: int, admin: User = Depends(RoleChecker(["Admin"])), db: Session = Depends(get_db)):
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    target_user.failed_attempts = 0
    target_user.lockout_until = None
    db.commit()
    
    log_audit(db, admin.id, f"Admin manually unlocked user account: {target_user.username}")
    return {"message": f"Account '{target_user.username}' has been unlocked."}

@app.delete("/api/admin/users/{target_user_id}")
def delete_user(target_user_id: int, admin: User = Depends(RoleChecker(["Admin"])), db: Session = Depends(get_db)):
    if admin.id == target_user_id:
        raise HTTPException(status_code=400, detail="Action denied: You cannot delete your own active admin account.")
        
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    username = target_user.username
    db.delete(target_user)
    db.commit()
    
    log_audit(db, admin.id, f"Admin permanently deleted user: {username}")
    return {"message": f"Identity '{username}' removed successfully."}