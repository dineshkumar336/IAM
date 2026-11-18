"""Create (or promote) the first administrator.

Interactive:      python -m scripts.create_admin
Non-interactive:  ADMIN_USERNAME=alice ADMIN_PASSWORD='...' python -m scripts.create_admin
"""
import getpass
import os
import sys

from app.audit import record
from app.database import Base, SessionLocal, engine
from app.models import Role, User
from app.security import hash_password, password_error
from app.seed import seed_roles

Base.metadata.create_all(bind=engine)

username = (os.environ.get("ADMIN_USERNAME") or input("Admin username: ")).strip()
if len(username) < 3 or len(username) > 32:
    sys.exit("Username must be 3-32 characters.")

with SessionLocal() as db:
    seed_roles(db)
    admin_role = db.query(Role).filter_by(name="Admin").one()
    user = db.query(User).filter_by(username=username).first()

    if user:
        user.role_id = admin_role.id
        db.commit()
        record(db, "system.admin_promoted", actor_name="create_admin.py", target=username)
        print(f"Existing user '{username}' promoted to Admin.")
    else:
        password = os.environ.get("ADMIN_PASSWORD")
        if not password:
            password = getpass.getpass("Admin password: ")
            if password != getpass.getpass("Repeat password: "):
                sys.exit("Passwords do not match.")
        problem = password_error(password)
        if problem:
            sys.exit(problem)
        user = User(username=username, password_hash=hash_password(password), role_id=admin_role.id)
        db.add(user)
        db.commit()
        record(db, "system.admin_created", actor_name="create_admin.py", target=username)
        print(f"Admin '{username}' created. Log in, then you will be asked to enrol MFA.")
