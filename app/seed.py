from .models import Role


def seed_roles(db) -> None:
    for name in ("Admin", "User"):
        if not db.query(Role).filter_by(name=name).first():
            db.add(Role(name=name))
    db.commit()
