"""Shared pytest configuration and HTTP test fixtures.

Runs from the ``backend`` directory (``python -m pytest``); make sure the
application package is importable and that importing ``app.database`` does not
require a real database connection.

The ``client`` / ``admin_client`` fixtures back the HTTP tests with a single
in-memory sqlite database. ``TestClient`` is used without its context manager so
the PostgreSQL startup migrations are never run; the schema is created straight
from the models. The JSON columns use
``JSON().with_variant(JSONB, "postgresql")`` so they also work on sqlite.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Tests exercise pure parsing/graph logic and never connect to the database.
os.environ.setdefault("DATABASE_URL", "sqlite://")
# Fixed session signing key so cookies are valid across requests in tests.
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.routers import graph_cache
from main import app

# One shared in-memory database for the whole test session (StaticPool keeps a
# single connection alive so every session sees the same schema/data).
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

ADMIN_PASSWORD = "correct-horse-battery"


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db


@pytest.fixture
def _fresh_database():
    Base.metadata.create_all(bind=engine)
    graph_cache.invalidate()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session(_fresh_database):
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(_fresh_database):
    # No context manager: entering it would run the lifespan (PostgreSQL
    # migrations). A fresh TestClient also isolates the session cookie per test.
    return TestClient(app)


@pytest.fixture
def admin_client(client):
    """A client with the first admin account created and logged in."""
    resp = client.post(
        "/api/auth/setup",
        json={"username": "admin", "password": ADMIN_PASSWORD},
    )
    assert resp.status_code == 201
    return client
