"""HTTP tests for the graph time-range filter and the time-range endpoint."""

import io
from datetime import datetime


def _ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


def _upload(client, content, name="events.csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), "text/csv")},
    )


_HEADER = (
    b"ActionType,DeviceName,Timestamp,InitiatingProcessId,ProcessId,"
    b"InitiatingProcessFileName,FileName\n"
)

_ROWS = (
    b"FileCreated,H1,2026-10-05T12:00:00Z,600,,svchost.exe,file0.dll\n"
    b"FileCreated,H1,2026-10-05T12:05:00Z,600,,svchost.exe,file1.dll\n"
    b"FileCreated,H1,2026-10-05T12:10:00Z,600,,svchost.exe,file2.dll\n"
)


def _node_ids(graph):
    return {node["data"]["id"] for node in graph["elements"]["nodes"]}


def test_graph_time_filter_keeps_only_events_in_window(admin_client):
    dataset_id = _upload(admin_client, _HEADER + _ROWS).json()["dataset_id"]

    full = admin_client.get(f"/api/graph/{dataset_id}").json()
    assert {"file0.dll", "file1.dll", "file2.dll"} <= _node_ids(full)

    # From 12:05 onward: file0 is out, file1/file2 stay.
    from_graph = admin_client.get(
        f"/api/graph/{dataset_id}", params={"from": _ms("2026-10-05T12:05:00+00:00")}
    ).json()
    ids = _node_ids(from_graph)
    assert "file1.dll" in ids and "file2.dll" in ids
    assert "file0.dll" not in ids

    # Up to 12:05: file2 is out.
    to_graph = admin_client.get(
        f"/api/graph/{dataset_id}", params={"to": _ms("2026-10-05T12:05:00+00:00")}
    ).json()
    ids = _node_ids(to_graph)
    assert "file0.dll" in ids and "file1.dll" in ids
    assert "file2.dll" not in ids

    # Exact window 12:05..12:05: only file1.
    exact = admin_client.get(
        f"/api/graph/{dataset_id}",
        params={
            "from": _ms("2026-10-05T12:05:00+00:00"),
            "to": _ms("2026-10-05T12:05:00+00:00"),
        },
    ).json()
    assert _node_ids(exact) == {"600@H1", "file1.dll"}


def test_time_range_endpoint_reports_full_span(admin_client):
    dataset_id = _upload(admin_client, _HEADER + _ROWS).json()["dataset_id"]

    body = admin_client.get(f"/api/graph/{dataset_id}/time-range").json()
    assert body["min_ms"] == _ms("2026-10-05T12:00:00+00:00")
    assert body["max_ms"] == _ms("2026-10-05T12:10:00+00:00")


def test_time_range_endpoint_ignores_undated_events(admin_client):
    rows = (
        b"FileCreated,H1,2026-10-05T12:00:00Z,600,,svchost.exe,dated.dll\n"
        b"FileCreated,H1,,600,,svchost.exe,undated.dll\n"
    )
    dataset_id = _upload(admin_client, _HEADER + rows).json()["dataset_id"]

    span = admin_client.get(f"/api/graph/{dataset_id}/time-range").json()
    assert span["min_ms"] == _ms("2026-10-05T12:00:00+00:00")
    assert span["max_ms"] == _ms("2026-10-05T12:00:00+00:00")

    # Filtering by time excludes the undated event entirely.
    graph = admin_client.get(
        f"/api/graph/{dataset_id}", params={"from": _ms("2026-10-05T12:00:00+00:00")}
    ).json()
    ids = _node_ids(graph)
    assert "dated.dll" in ids
    assert "undated.dll" not in ids


def test_time_range_endpoint_for_missing_dataset_returns_404(admin_client):
    assert admin_client.get("/api/graph/999999/time-range").status_code == 404
