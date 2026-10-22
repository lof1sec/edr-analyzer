"""HTTP-level tests for the API.

The shared ``client`` / ``admin_client`` fixtures (and the in-memory sqlite
engine) live in ``conftest.py``.
"""
import io
from datetime import UTC, datetime

import pytest

from app.models import LogEvent
from app.routers import datasets as datasets_router


def _upload(client, content, name, content_type="text/csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), content_type)},
    )


def test_upload_timezone_normalizes_csv_and_rejects_invalid_zone(admin_client, db_session):
    csv = b"ActionType,Timestamp\nProcessCreated,\"Sep 14, 2026 3:02:15 PM\"\n"
    endpoint = "/api/datasets/upload"
    files = {"file": ("times.csv", io.BytesIO(csv), "text/csv")}
    response = admin_client.post(endpoint, files=files, data={"timezone": "America/Santiago"})
    assert response.status_code == 200
    event = db_session.query(LogEvent).filter_by(dataset_id=response.json()["dataset_id"]).one()
    assert event.event_time == int(datetime(2026, 9, 14, 18, 2, 15, tzinfo=UTC).timestamp() * 1000)

    response = admin_client.post(
        endpoint,
        files={"file": ("times.csv", io.BytesIO(csv), "text/csv")},
        data={"timezone": "Invalid/Timezone"},
    )
    assert response.status_code == 400


def test_upload_list_graph_search_element_logs_and_delete_flow(admin_client):
    csv = (
        b"ActionType,DeviceName,InitiatingProcessId,ProcessId,"
        b"InitiatingProcessFileName,FileName\n"
        b"ProcessCreated,H1,500,600,services.exe,svchost.exe\n"
        b"FileCreated,H1,600,,svchost.exe,evil.dll\n"
    )
    resp = _upload(admin_client, csv, "events.csv")
    assert resp.status_code == 200
    dataset_id = resp.json()["dataset_id"]

    listing = admin_client.get("/api/datasets/").json()
    assert [d["id"] for d in listing] == [dataset_id]
    assert listing[0]["log_count"] == 2

    graph = admin_client.get(f"/api/graph/{dataset_id}").json()
    assert graph["unmapped_events"] == {}
    node_ids = [n["data"]["id"] for n in graph["elements"]["nodes"]]
    assert "600@H1" in node_ids

    logs = admin_client.get(
        f"/api/graph/{dataset_id}/element-logs", params={"element_id": "600@H1"}
    ).json()
    assert logs["returned"] >= 1

    found = admin_client.get(
        f"/api/graph/{dataset_id}/search", params={"q": "svchost"}
    ).json()
    assert "600@H1" in found["ids"]

    assert admin_client.delete(f"/api/datasets/{dataset_id}").status_code == 200
    assert admin_client.get(f"/api/graph/{dataset_id}").status_code == 404


def test_csv_invalid_certificate_dates_preserve_evidence_and_spawn(admin_client, db_session):
    csv = (b"ActionType,DeviceName,InitiatingProcessId,ProcessId,Type,CertificateCreationTime,"
           b"CertificateExpirationTime,CertificateCountersignatureTime\n"
           b"ProcessCreated,H1,500,600,DeviceProcessEvents,Invalid date,Invalid date,Invalid date\n")
    response = _upload(admin_client, csv, "process.csv")
    assert response.status_code == 200
    dataset_id = response.json()["dataset_id"]
    event = db_session.query(LogEvent).filter_by(dataset_id=dataset_id).one().data
    assert event["Type"] == "DeviceProcessEvents"
    assert event["CertificateCreationTime"] == "Invalid date"
    assert event["CertificateExpirationTime"] == "Invalid date"
    assert event["CertificateCountersignatureTime"] == "Invalid date"
    graph = admin_client.get(f"/api/graph/{dataset_id}").json()
    assert graph["unmapped_events"] == {}
    assert any(edge["data"]["source"] == "500@H1" and edge["data"]["target"] == "600@H1"
               and edge["data"]["label"] == "Spawns" for edge in graph["elements"]["edges"])
    logs = admin_client.get(f"/api/graph/{dataset_id}/element-logs",
                            params={"element_id": "600@H1"}).json()
    assert any(log["CertificateCreationTime"] == "Invalid date" for log in logs["raw_logs"])


def test_unmapped_events_are_aggregated_to_counts(admin_client):
    csv = b"ActionType,DeviceName\nSomeUnknownAction,H1\nSomeUnknownAction,H1\n"
    dataset_id = _upload(admin_client, csv, "unknown.csv").json()["dataset_id"]

    graph = admin_client.get(f"/api/graph/{dataset_id}").json()
    assert graph["unmapped_events"] == {"SomeUnknownAction": 2}


def test_graph_for_missing_dataset_returns_404(admin_client):
    assert admin_client.get("/api/graph/999999").status_code == 404


def test_upload_rejects_malformed_json_with_400(admin_client):
    resp = _upload(admin_client, b"[ not json", "bad.json", "application/json")
    assert resp.status_code == 400


def test_upload_rejects_unsupported_extension_with_400(admin_client):
    resp = _upload(admin_client, b"nope", "events.txt", "text/plain")
    assert resp.status_code == 400


def test_upload_rolls_back_all_batches_on_unexpected_error(admin_client, monkeypatch):
    original_flush = datasets_router._flush_batch
    calls = 0

    def fail_on_second_batch(db, batch):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("unexpected parser failure")
        original_flush(db, batch)

    monkeypatch.setattr(datasets_router, "_flush_batch", fail_on_second_batch)
    data = b"ActionType,DeviceName\n" + b"ProcessCreated,H1\n" * 1001
    with pytest.raises(RuntimeError, match="unexpected parser failure"):
        _upload(admin_client, data, "interrupted.csv")
    assert admin_client.get("/api/datasets/").json() == []


def test_upload_stores_json_escaped_nuls_without_postgresql_incompatible_values(
    admin_client, db_session,
):
    content = (
        b'{"#event_simpleName":"NewScriptWritten","timestamp":"1791477927898",'
        b'"ScriptContent":"{\\u0000Write-Host \\"ok\\"",'
        b'"nested":{"item\\u0000name":["a\\u0000b",42]}}\n'
    )
    response = _upload(admin_client, content, "nul.jsonl", "application/jsonl")
    assert response.status_code == 200
    log = db_session.query(LogEvent).filter_by(dataset_id=response.json()["dataset_id"]).one()
    assert log.event_type == "NewScriptWritten"
    assert log.data["ScriptContent"] == '{Write-Host "ok"'
    assert log.data["nested"]["itemname"] == ["ab", 42]
    assert "\x00" not in str(log.data)


def _upload_defender_rows(client, rows, name="events.csv"):
    header = (
        b"ActionType,DeviceName,InitiatingProcessId,ProcessId,"
        b"InitiatingProcessFileName,FileName\n"
    )
    return _upload(client, header + rows, name)


def test_layout_can_be_saved_and_fetched(admin_client):
    dataset_id = _upload_defender_rows(
        admin_client,
        b"ProcessCreated,H1,500,600,services.exe,svchost.exe\n",
        "layout.csv",
    ).json()["dataset_id"]

    assert admin_client.get(f"/api/graph/{dataset_id}/layout").json()["positions"] == {}

    saved = admin_client.put(
        f"/api/graph/{dataset_id}/layout",
        json={"positions": {"600": {"x": 10, "y": 20}}},
    )
    assert saved.status_code == 200

    positions = admin_client.get(f"/api/graph/{dataset_id}/layout").json()["positions"]
    assert positions == {"600": {"x": 10.0, "y": 20.0}}


def test_layout_for_missing_dataset_returns_404(admin_client):
    assert admin_client.get("/api/graph/999999/layout").status_code == 404


def test_hub_descendants_are_collapsed_and_expandable(admin_client, monkeypatch):
    monkeypatch.setenv("CLUSTER_MIN_CHILDREN", "2")
    rows = b"".join(
        f"FileCreated,H1,500,,hub.exe,file{i}.dll\n".encode() for i in range(3)
    )
    dataset_id = _upload_defender_rows(admin_client, rows, "hub.csv").json()["dataset_id"]

    graph = admin_client.get(f"/api/graph/{dataset_id}").json()
    cluster_nodes = [
        node["data"] for node in graph["elements"]["nodes"] if node["data"].get("isCluster")
    ]
    assert len(cluster_nodes) == 1
    assert cluster_nodes[0]["clusterCount"] == 3

    # The collapsed files are not part of the initial payload...
    node_ids = {node["data"]["id"] for node in graph["elements"]["nodes"]}
    assert "file0.dll" not in node_ids

    # ...but are returned on demand by the cluster endpoint.
    expanded = admin_client.get(
        f"/api/graph/{dataset_id}/clusters/{cluster_nodes[0]['id']}"
    ).json()
    assert {node["data"]["id"] for node in expanded["nodes"]} == {
        "file0.dll",
        "file1.dll",
        "file2.dll",
    }
    assert len(expanded["edges"]) == 3


def test_neighbors_endpoint_returns_subgraph(admin_client):
    dataset_id = _upload_defender_rows(
        admin_client,
        b"ProcessCreated,H1,500,600,services.exe,svchost.exe\n"
        b"FileCreated,H1,600,,svchost.exe,evil.dll\n",
        "neighbors.csv",
    ).json()["dataset_id"]

    neighbors = admin_client.get(
        f"/api/graph/{dataset_id}/neighbors", params={"element_id": "600@H1"}
    ).json()
    ids = {node["data"]["id"] for node in neighbors["nodes"]}
    assert "600@H1" in ids
    assert "evil.dll" in ids
