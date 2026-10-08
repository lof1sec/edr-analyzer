"""HTTP-level tests for the API.

The shared ``client`` / ``admin_client`` fixtures (and the in-memory sqlite
engine) live in ``conftest.py``.
"""
import io


def _upload(client, content, name, content_type="text/csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), content_type)},
    )


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
