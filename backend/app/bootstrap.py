"""Provision the initial admin account from the environment.

The app deliberately reuses the PostgreSQL credentials as the administrator
login: those values already have to be configured to run the stack and are known
to the operator, so there is no separate "create admin" step and no way to end up
locked out by an account whose password nobody remembers.

``ADMIN_USERNAME``/``ADMIN_PASSWORD`` may override them when a distinct app login
is wanted.
"""
import os

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import User
from app.security import hash_password


def get_admin_credentials() -> tuple[str, str] | None:
    """Return the admin credentials, defaulting to the PostgreSQL ones."""
    username = (os.getenv("ADMIN_USERNAME") or os.getenv("POSTGRES_USER") or "").strip()
    password = os.getenv("ADMIN_PASSWORD") or os.getenv("POSTGRES_PASSWORD") or ""
    if not username or not password:
        return None
    return username, password


def ensure_admin_user(db: Session) -> User | None:
    """Create the admin account if it does not exist yet.

    Existing accounts are left untouched, so a password changed from inside the
    app is not reverted on the next restart. Returns the admin, or ``None`` when
    no credentials are configured.
    """
    credentials = get_admin_credentials()
    if credentials is None:
        return None

    username, password = credentials
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        user = User(username=username, password_hash=hash_password(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"Provisioned admin account '{username}' from the environment.")
    return user


def seed_admin_user() -> None:
    """Startup hook: open a short-lived session and ensure the admin exists."""
    db = SessionLocal()
    try:
        ensure_admin_user(db)
    finally:
        db.close()
