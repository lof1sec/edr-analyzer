import asyncio
import os
from contextlib import asynccontextmanager

from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import OperationalError

from alembic import command
from app.routers import datasets, graph

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(datasets.router)
app.include_router(graph.router)

@app.get("/")
def read_root():
    return {"status": "ok"}
