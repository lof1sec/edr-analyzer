"""HTTP-level tests for the API, backed by an in-memory sqlite database.

``TestClient`` is used without its context manager so the app's startup
migrations (which target PostgreSQL) are never run; the schema is created
directly from the models instead.
"""
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.routers import graph_cache
from main import app

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_database():
    Base.metadata.create_all(bind=engine)
    graph_cache.invalidate()
    yield
    Base.metadata.drop_all(bind=engine)


def _upload(content: bytes, name: str, content_type: str = "text/csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), content_type)},
    )


def test_upload_list_graph_search_element_logs_and_delete_flow():
    csv = (
        b"ActionType,DeviceName,InitiatingProcessId,ProcessId,"
        b"InitiatingProcessFileName,FileName\n"
        b"ProcessCreated,H1,500,600,services.exe,svchost.exe\n"
        b"FileCreated,H1,600,,svchost.exe,evil.dll\n"
    )
    resp = _upload(csv, "events.csv")
    assert resp.status_code == 200
    dataset_id = resp.json()["dataset_id"]

    listing = client.get("/api/datasets/").json()
    assert [d["id"] for d in listing] == [dataset_id]
    assert listing[0]["log_count"] == 2

    graph = client.get(f"/api/graph/{dataset_id}").json()
    assert graph["unmapped_events"] == {}
    node_ids = [n["data"]["id"] for n in graph["elements"]["nodes"]]
    assert "600" in node_ids

    logs = client.get(
        f"/api/graph/{dataset_id}/element-logs", params={"element_id": "600"}
    ).json()
    assert logs["returned"] >= 1

    found = client.get(
        f"/api/graph/{dataset_id}/search", params={"q": "svchost"}
    ).json()
    assert "600" in found["ids"]

    assert client.delete(f"/api/datasets/{dataset_id}").status_code == 200
    assert client.get(f"/api/graph/{dataset_id}").status_code == 404


def test_unmapped_events_are_aggregated_to_counts():
    csv = b"ActionType,DeviceName\nSomeUnknownAction,H1\nSomeUnknownAction,H1\n"
    dataset_id = _upload(csv, "unknown.csv").json()["dataset_id"]

    graph = client.get(f"/api/graph/{dataset_id}").json()
    assert graph["unmapped_events"] == {"SomeUnknownAction": 2}


def test_graph_for_missing_dataset_returns_404():
    assert client.get("/api/graph/999999").status_code == 404


def test_upload_rejects_malformed_json_with_400():
    resp = _upload(b"[ not json", "bad.json", "application/json")
    assert resp.status_code == 400


def test_upload_rejects_unsupported_extension_with_400():
    resp = _upload(b"nope", "events.txt", "text/plain")
    assert resp.status_code == 400
