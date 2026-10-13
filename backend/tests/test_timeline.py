"""HTTP tests for the chronological timeline endpoint."""
import io

from sqlalchemy import inspect

from app.models import LogEvent


def _upload(client, content, name="events.csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), "text/csv")},
    )


_HEADER = (
    b"ActionType,DeviceName,Timestamp,InitiatingProcessId,ProcessId,"
    b"InitiatingProcessFileName,FileName\n"
)


def test_timeline_time_index_exists(db_session):
    indexes = {index["name"] for index in inspect(db_session.bind).get_indexes(LogEvent.__tablename__)}
    assert "ix_log_events_dataset_time_id" in indexes


def test_timeline_orders_by_time_and_puts_undated_last(admin_client):
    csv = _HEADER + (
        b"FileCreated,H1,2026-10-05T12:00:02Z,600,,svchost.exe,second.dll\n"
        b"ProcessCreated,H1,2026-10-05T12:00:00Z,500,600,services.exe,svchost.exe\n"
        b"FileCreated,H1,,600,,svchost.exe,undated.dll\n"
    )
    dataset_id = _upload(admin_client, csv).json()["dataset_id"]

    body = admin_client.get(f"/api/graph/{dataset_id}/timeline").json()
    assert body["total"] == 3
    # The two dated events come first, chronologically; the undated one last.
    assert [e["event_type"] for e in body["entries"]] == [
        "ProcessCreated",
        "FileCreated",
        "FileCreated",
    ]
    times = [e["time_ms"] for e in body["entries"]]
    assert times[0] < times[1]
    assert times[2] is None

    first = body["entries"][0]
    assert first["index"] == 0
    assert first["iso"] is not None
    assert first["vendor"] == "defender"
    assert "svchost.exe" in first["summary"]
    assert "600@H1" in first["element_ids"]


def test_timeline_pagination_and_filters(admin_client):
    rows = b"".join(
        f"FileCreated,H1,2026-10-05T12:00:{i:02d}Z,600,,svchost.exe,f{i}.dll\n".encode()
        for i in range(5)
    )
    dataset_id = _upload(admin_client, _HEADER + rows).json()["dataset_id"]

    page1 = admin_client.get(
        f"/api/graph/{dataset_id}/timeline", params={"limit": 2}
    ).json()
    assert page1["total"] == 5
    assert len(page1["entries"]) == 2

    page2 = admin_client.get(
        f"/api/graph/{dataset_id}/timeline", params={"limit": 2, "offset": 2}
    ).json()
    assert [e["id"] for e in page1["entries"]] != [e["id"] for e in page2["entries"]]

    filtered = admin_client.get(
        f"/api/graph/{dataset_id}/timeline", params={"event_type": "FileCreated"}
    ).json()
    assert filtered["total"] == 5

    empty = admin_client.get(
        f"/api/graph/{dataset_id}/timeline", params={"event_type": "Nope"}
    ).json()
    assert empty["total"] == 0
    assert empty["entries"] == []

    searched = admin_client.get(
        f"/api/graph/{dataset_id}/timeline", params={"q": "f2.dll"}
    ).json()
    assert searched["total"] == 1


def test_timeline_for_missing_dataset_returns_404(admin_client):
    assert admin_client.get("/api/graph/999999/timeline").status_code == 404


def test_upload_with_non_finite_timestamp_does_not_crash(admin_client):
    """Regression: ``NaN`` in a JSON export used to break the whole upload."""
    content = (
        b'{"ActionType": "FileCreated", "DeviceName": "H1", "Timestamp": NaN, '
        b'"InitiatingProcessId": "600", "FileName": "x.dll"}\n'
    )
    resp = admin_client.post(
        "/api/datasets/upload",
        files={"file": ("events.jsonl", io.BytesIO(content), "application/jsonl")},
    )
    assert resp.status_code == 200
    dataset_id = resp.json()["dataset_id"]

    body = admin_client.get(f"/api/graph/{dataset_id}/timeline").json()
    assert body["total"] == 1
    assert body["entries"][0]["time_ms"] is None


def test_timeline_matches_graph_window_and_ignores_unmapped_events(admin_client):
    csv = _HEADER + (
        b"FileCreated,H1,2026-10-05T12:00:00Z,600,,svchost.exe,first.dll\n"
        b"FileCreated,H1,2026-10-05T12:10:00Z,600,,svchost.exe,last.dll\n"
        b"UnmappedEvent,H1,2026-10-05T12:10:00Z,,,,\n"
        b"FileCreated,H1,,600,,svchost.exe,undated.dll\n"
    )
    dataset_id = _upload(admin_client, csv).json()["dataset_id"]
    base = f"/api/graph/{dataset_id}"
    assert admin_client.get(f"{base}/timeline").json()["total"] == 3
    window = {"from": 1791202200000}  # 2026-10-05 12:10:00 UTC
    graph = admin_client.get(base, params=window).json()
    timeline = admin_client.get(f"{base}/timeline", params=window).json()
    assert timeline["total"] == 1
    assert timeline["entries"][0]["event_type"] == "FileCreated"
    assert "last.dll" in {node["data"]["id"] for node in graph["elements"]["nodes"]}
    assert "last.dll" in timeline["entries"][0]["element_ids"]


def test_timeline_applies_graph_filters_before_pagination(admin_client):
    csv = (
        b"ActionType,DeviceName,Timestamp,InitiatingProcessId,ProcessId,"
        b"InitiatingProcessFileName,FileName,AccountName\n"
        b"FileCreated,H1,2026-10-05T12:00:00Z,600,,a.exe,alpha.dll,alice\n"
        b"FileCreated,H1,2026-10-05T12:00:01Z,700,,b.exe,beta.dll,bob\n"
        b"FileCreated,H1,2026-10-05T12:00:02Z,600,,a.exe,gamma.dll,alice\n"
    )
    dataset_id = _upload(admin_client, csv).json()["dataset_id"]
    path = f"/api/graph/{dataset_id}/timeline"
    params = {"hidden_user": "bob", "limit": 1}
    first = admin_client.get(path, params=params).json()
    second = admin_client.get(path, params={**params, "offset": 1}).json()
    assert first["total"] == second["total"] == 2
    assert [first["entries"][0]["element_ids"][1],
            second["entries"][0]["element_ids"][1]] == ["alpha.dll", "gamma.dll"]
    assert admin_client.get(path, params={"hidden_pid": "600@H1"}).json()["total"] == 1
    assert admin_client.get(path, params={"hidden_event_type": "FileCreated"}).json()["total"] == 0
    assert admin_client.get(path, params={"graph_q": "beta.dll"}).json()["total"] == 1


def test_timeline_targets_edges_and_expands_clusters_for_focus(admin_client, monkeypatch):
    monkeypatch.setenv("CLUSTER_MIN_CHILDREN", "2")
    monkeypatch.setenv("MAX_INITIAL_ELEMENTS", "3")
    csv = _HEADER + (
        b"FileCreated,H1,2026-10-05T12:00:00Z,600,,a.exe,alpha.dll\n"
        b"FileCreated,H1,2026-10-05T12:00:01Z,600,,a.exe,beta.dll\n"
    )
    dataset_id = _upload(admin_client, csv).json()["dataset_id"]
    path = f"/api/graph/{dataset_id}"
    graph = admin_client.get(path).json()
    assert not any(node["data"]["id"] == "alpha.dll" for node in graph["elements"]["nodes"])
    entries = admin_client.get(f"{path}/timeline").json()["entries"]
    assert len(entries) == 2
    first = entries[0]
    assert "alpha.dll" in first["element_ids"]
    assert first["focus_element_id"].startswith("edge_")
    assert first["focus_cluster_id"] is not None
    focused = admin_client.get(f"{path}/focus", params={"element_id": first["focus_element_id"]}).json()
    assert focused["cluster_id"] == first["focus_cluster_id"]
    assert "alpha.dll" in {node["data"]["id"] for node in focused["nodes"]}


def test_timeline_keeps_mapped_node_only_event(admin_client):
    content = (
        b'{"#event_simpleName":"NetworkLinkConfigGetAddress",'
        b'"ContextProcessId":"1111","ComputerName":"lnx1"}\n'
    )
    response = admin_client.post(
        "/api/datasets/upload",
        files={"file": ("events.jsonl", io.BytesIO(content), "application/jsonl")},
    )
    dataset_id = response.json()["dataset_id"]
    timeline = admin_client.get(f"/api/graph/{dataset_id}/timeline").json()
    assert timeline["total"] == 1
    assert timeline["entries"][0]["focus_element_id"] == "1111@lnx1"


def test_focus_loads_paged_edge_without_shipping_event_references(admin_client, monkeypatch):
    monkeypatch.setenv("CLUSTER_MIN_CHILDREN", "0")
    monkeypatch.setenv("MAX_INITIAL_ELEMENTS", "2")
    dataset_id = _upload(admin_client, _HEADER + (
        b"FileCreated,H1,2026-10-05T12:00:00Z,600,,a.exe,alpha.dll\n"
        b"FileCreated,H1,2026-10-05T12:00:01Z,600,,a.exe,beta.dll\n"
    )).json()["dataset_id"]
    base = f"/api/graph/{dataset_id}"
    graph = admin_client.get(base).json()
    assert "event_elements" not in graph
    entry = admin_client.get(f"{base}/timeline").json()["entries"][1]
    focus = admin_client.get(
        f"{base}/focus", params={"element_id": entry["focus_element_id"]}
    ).json()
    assert focus["cluster_id"] is None
    assert {node["data"]["id"] for node in focus["nodes"]} == {"600@H1", "beta.dll"}
    assert {edge["data"]["id"] for edge in focus["edges"]} == {entry["focus_element_id"]}
    assert admin_client.get(f"{base}/focus", params={"element_id": "missing"}).status_code == 404
