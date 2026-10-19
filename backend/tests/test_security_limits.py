import io

from fastapi.testclient import TestClient

from app.parsers.builder import MAX_ARTIFACT_TITLE_CHARS, GraphBuilder
from app.routers import datasets, login_limits
from app.routers.datasets import _parse_json_rows
from main import app


def test_csrf_required_for_login_and_mutations(client):
    raw = TestClient(app)
    payload = {"username": "admin", "password": "correct-horse-battery"}
    assert raw.post("/api/auth/setup", json=payload).status_code == 403
    token = raw.get("/api/auth/csrf").json()["token"]
    assert raw.post("/api/auth/setup", json=payload, headers={"Origin": "https://evil.example", "X-CSRF-Token": token}).status_code == 403
    assert raw.post("/api/auth/setup", json=payload, headers={"X-CSRF-Token": token}).status_code == 201
    assert raw.post("/api/auth/logout").status_code == 403
    assert raw.post("/api/auth/logout", headers={"X-CSRF-Token": token}).status_code == 204
    assert raw.delete("/api/datasets/1", headers={"X-CSRF-Token": token}).status_code == 403


def test_login_limits_with_clock(client, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(login_limits.time, "monotonic", lambda: now[0])
    token = client.get("/api/auth/csrf").json()["token"]
    headers = {"X-CSRF-Token": token, "X-Forwarded-For": "8.8.8.8"}
    payload = {"username": "admin", "password": "wrong"}
    for _ in range(5):
        assert client.post("/api/auth/login", json=payload, headers=headers).status_code == 401
    blocked = client.post("/api/auth/login", json=payload, headers=headers)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "900"
    now[0] += 901
    assert client.post("/api/auth/login", json=payload, headers=headers).status_code == 401
    for index in range(19):
        client.post("/api/auth/login", json={"username": f"different{index}", "password": "wrong"}, headers=headers)
    assert client.post("/api/auth/login", json={"username": "fresh", "password": "wrong"}, headers=headers).status_code == 429


def test_login_limiter_identity_state_is_bounded(monkeypatch):
    monkeypatch.setattr(login_limits, "MAX_IDENTITIES", 2)
    store = {}
    login_limits._get_bucket(store, "first", 100).append(100)
    login_limits._get_bucket(store, "second", 200).append(200)
    login_limits._get_bucket(store, "third", 201).append(201)
    assert set(store) == {"second", "third"}
    login_limits._get_bucket(store, "fourth", 1200).append(1200)
    assert set(store) == {"fourth"}


def test_json_size_and_depth_limits():
    import pytest
    from fastapi import HTTPException

    from app.routers.datasets import _validate_json_event

    deep = {}
    current = deep
    for _ in range(64):
        current["child"] = {}
        current = current["child"]
    with pytest.raises(HTTPException) as exc:
        _validate_json_event(deep)
    assert exc.value.status_code == 400
    with pytest.raises(HTTPException) as exc:
        list(_parse_json_rows(io.BytesIO(b'{"x":"' + b'a' * (8 * 1024 * 1024 + 1) + b'"}'), "utf-8"))
    assert exc.value.status_code == 413


def test_oversized_unterminated_jsonl_record_fails_before_full_read(monkeypatch):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(datasets, "MAX_JSON_EVENT_BYTES", 64)
    stream = io.BytesIO(b'{"ActionType":"FileCreated"}\n' + b'x' * (1024 * 1024))
    rows = _parse_json_rows(stream, "utf-8")
    assert next(rows)[0] == "FileCreated"
    with pytest.raises(HTTPException) as exc:
        next(rows)
    assert exc.value.status_code == 413
    # TextIOWrapper may prefetch a small chunk, but cannot buffer the full row.
    assert stream.tell() < 1024 * 1024


def test_artifact_title_bounded_and_evidence_kept():
    builder = GraphBuilder()
    event = {"secret": "z" * 9000}
    builder.add_or_update_artifact_node("artifact", "label", "x" * 9000, "file", event)
    builder.add_or_update_artifact_node("artifact", "label", "y" * 9000, "file", event)
    node = builder.nodes_dict["artifact"]
    assert len(node["title"]) <= MAX_ARTIFACT_TITLE_CHARS
    assert node["raw_logs"][0]["secret"] == event["secret"]
