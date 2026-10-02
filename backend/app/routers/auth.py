"""Authentication endpoints and the route guard.

The app is single-tenant: the first run creates one admin account, and every
user shares the same datasets. Sessions are signed httpOnly cookies managed by
Starlette's ``SessionMiddleware`` (see ``main.py``); only the user id is stored
in the session, never a token the browser JS could read.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import AuthStatus, LoginRequest, SetupRequest, UserOut
from app.security import hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["Auth"])

SESSION_USER_KEY = "user_id"


def get_current_user(request: Request, db: Session) -> User | None:
    """Resolve the logged-in user from the signed session cookie, if any."""
    user_id = request.session.get(SESSION_USER_KEY)
    if not user_id:
        return None
    return db.get(User, user_id)


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency used to protect routes: 401 when unauthenticated."""
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def _user_count(db: Session) -> int:
    return db.query(User).count()


@router.get("/status", response_model=AuthStatus)
def auth_status(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return AuthStatus(
        needs_setup=_user_count(db) == 0,
        authenticated=user is not None,
        username=user.username if user else None,
    )


@router.post("/setup", response_model=UserOut, status_code=201)
def setup(payload: SetupRequest, request: Request, db: Session = Depends(get_db)):
    """Create the first admin account and log it in.

    Only allowed while no user exists, so it cannot be used to add accounts
    after the initial setup.
    """
    if _user_count(db) > 0:
        raise HTTPException(status_code=403, detail="Setup has already been completed")

    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    request.session[SESSION_USER_KEY] = user.id
    return user


@router.post("/login", response_model=UserOut)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    request.session[SESSION_USER_KEY] = user.id
    return user


@router.post("/logout", status_code=204)
def logout(request: Request):
    request.session.clear()


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(require_user)):
    return user
