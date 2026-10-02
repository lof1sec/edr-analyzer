import asyncio
import os
import secrets
from contextlib import asynccontextmanager

from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import OperationalError
from starlette.middleware.sessions import SessionMiddleware

from alembic import command
from app.routers import auth, datasets, graph

ALEMBIC_INI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alembic.ini")


def run_migrations() -> None:
    """Apply all pending Alembic migrations (replaces ``create_all``)."""
    command.upgrade(Config(ALEMBIC_INI), "head")


def get_allowed_origins() -> list[str]:
    """Read the comma-separated allowlist of browser origins from the environment.

    Defaults to the local Vite dev server. Never fall back to "*": combined with
    credentialed requests it is rejected by browsers and effectively disables
    origin protection.
    """
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def get_secret_key() -> str:
    """Return the key used to sign session cookies.

    ``SECRET_KEY`` is required in production. For local development (and tests)
    an ephemeral key keeps the app bootable, at the cost of invalidating all
    sessions on every restart.
    """
    key = os.getenv("SECRET_KEY", "").strip()
    if key:
        return key
    print(
        "WARNING: SECRET_KEY is not set; using an ephemeral key. "
        "Sessions will not survive a restart."
    )
    return secrets.token_urlsafe(48)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Retry logic for database connection on startup
    retries = 5
    while retries > 0:
        try:
            await asyncio.to_thread(run_migrations)
            print("Database migrations applied.")
            break
        except OperationalError:
            retries -= 1
            print(f"Database not ready. Retrying in 5 seconds... ({retries} left)")
            await asyncio.sleep(5)

    if retries == 0:
        print("Failed to connect to the database. Starting anyway, but expect errors.")

    yield

app = FastAPI(title="EDR Logs Analysis API", lifespan=lifespan)

# Session middleware is added before CORS so CORS stays the outermost layer and
# can answer preflight requests for credentialed (cookie) calls.
app.add_middleware(
    SessionMiddleware,
    secret_key=get_secret_key(),
    same_site="lax",
    https_only=os.getenv("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(datasets.router)
app.include_router(graph.router)

@app.get("/")
def read_root():
    return {"status": "ok"}
