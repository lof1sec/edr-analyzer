"""HTTP tests for the chronological timeline endpoint."""
import io


def _upload(client, content, name="events.csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), "text/csv")},
    )


_HEADER = (
    b"ActionType,DeviceName,Timestamp,InitiatingProcessId,ProcessId,"
    b"InitiatingProcessFileName,FileName\n"
)


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
    assert "600" in first["element_ids"]


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
