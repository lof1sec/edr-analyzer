"""Session-bound double-submit protection for all state-changing API requests."""
import hmac
import secrets

from fastapi import HTTPException, Request

TOKEN_KEY = "csrf_token"


def token(request: Request) -> str:
    if TOKEN_KEY not in request.session:
        request.session[TOKEN_KEY] = secrets.token_urlsafe(32)
    return request.session[TOKEN_KEY]


def validate(request: Request, allowed_origins: list[str]) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS") or not request.url.path.startswith("/api/"):
        return
    origin = request.headers.get("origin")
    if request.headers.get("sec-fetch-site") == "cross-site" and not origin:
        raise HTTPException(status_code=403, detail="Invalid request origin")
    if origin and origin not in allowed_origins and origin != str(request.base_url).rstrip("/"):
        raise HTTPException(status_code=403, detail="Invalid request origin")
    expected = request.session.get(TOKEN_KEY)
    supplied = request.headers.get("x-csrf-token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
