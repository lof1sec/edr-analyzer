"""Tests for the truncated initial graph payload and the paged /elements endpoint."""

import io

from app.routers.graph import _truncate_elements


def _upload(client, content, name="events.csv"):
    return client.post(
        "/api/datasets/upload",
        files={"file": (name, io.BytesIO(content), "text/csv")},
    )


_HEADER = (
    b"ActionType,DeviceName,InitiatingProcessId,ProcessId,"
    b"InitiatingProcessFileName,FileName\n"
)


def _node(nid, group="process"):
    return {"data": {"id": nid, "group": group}}


def _edge(eid, source, target):
    return {"data": {"id": eid, "source": source, "target": target}}


def test_truncate_elements_keeps_backbone_and_fills_artifacts():
    nodes = [_node("p0"), _node("p1"), _node("p2")]
    nodes += [_node(f"a{i}", group="file") for i in range(10)]
    edges = [_edge("e01", "p0", "p1"), _edge("e12", "p1", "p2")]
    edges += [_edge(f"ea{i}", "p0", f"a{i}") for i in range(10)]

    selected_nodes, selected_edges, omitted_nodes, omitted_edges = _truncate_elements(
        nodes, edges, cap=8
    )
    selected_ids = {n["data"]["id"] for n in selected_nodes}
    # The process backbone is kept whole and no edge dangles.
    assert {"p0", "p1", "p2"} <= selected_ids
    for e in selected_edges:
        assert e["data"]["source"] in selected_ids
        assert e["data"]["target"] in selected_ids
    assert len(selected_nodes) + len(selected_edges) <= 8
    # Omitted nodes are sorted deterministically for stable paging.
    assert [n["data"]["id"] for n in omitted_nodes] == sorted(
        n["data"]["id"] for n in omitted_nodes
    )


def test_truncate_elements_returns_full_graph_when_within_cap():
    nodes = [_node("p0"), _node("a0", group="file")]
    edges = [_edge("e0", "p0", "a0")]
    selected_nodes, selected_edges, omitted_nodes, omitted_edges = _truncate_elements(
        nodes, edges, cap=10
    )
    assert selected_nodes == nodes
    assert selected_edges == edges
    assert omitted_nodes == []
    assert omitted_edges == []


def test_truncate_elements_disabled_when_cap_not_positive():
    nodes = [_node("p0"), _node("a0", group="file")]
    edges = [_edge("e0", "p0", "a0")]
    selected_nodes, selected_edges, omitted_nodes, omitted_edges = _truncate_elements(
        nodes, edges, cap=0
    )
    assert selected_nodes == nodes
    assert omitted_nodes == []


def test_large_graph_is_truncated_and_pages_recover_everything(admin_client, monkeypatch):
    monkeypatch.setenv("MAX_INITIAL_ELEMENTS", "5")
    rows = b"".join(
        f"FileCreated,H1,500,,hub.exe,file{i}.dll\n".encode() for i in range(10)
    )
    dataset_id = _upload(admin_client, _HEADER + rows).json()["dataset_id"]

    graph = admin_client.get(f"/api/graph/{dataset_id}").json()
    assert graph["truncated"] is True
    assert graph["total_nodes"] == 11  # 1 process hub + 10 file artifacts
    assert graph["total_edges"] == 10
    assert len(graph["elements"]["nodes"]) + len(graph["elements"]["edges"]) <= 5

    # Walk the pages; every returned edge must reference already-loaded nodes.
    loaded = {n["data"]["id"] for n in graph["elements"]["nodes"]}
    total_nodes = len(graph["elements"]["nodes"])
    total_edges = len(graph["elements"]["edges"])
    offset = 0
    while True:
        page = admin_client.get(
            f"/api/graph/{dataset_id}/elements", params={"offset": offset, "limit": 3}
        ).json()
        assert page["nodes"], "page made no progress"
        page_ids = {n["data"]["id"] for n in page["nodes"]}
        assert page_ids.isdisjoint(loaded)
        for e in page["edges"]:
            assert e["data"]["source"] in (loaded | page_ids)
            assert e["data"]["target"] in (loaded | page_ids)
        loaded |= page_ids
        total_nodes += len(page["nodes"])
        total_edges += len(page["edges"])
        if page["remaining"] == 0:
            break
        offset += len(page["nodes"])

    assert total_nodes == 11
    assert total_edges == 10


def test_small_graph_is_not_truncated(admin_client):
    rows = b"FileCreated,H1,500,,hub.exe,file0.dll\n"
    dataset_id = _upload(admin_client, _HEADER + rows).json()["dataset_id"]

    graph = admin_client.get(f"/api/graph/{dataset_id}").json()
    assert graph["truncated"] is False
    assert graph["total_nodes"] == 2
    assert graph["total_edges"] == 1

    page = admin_client.get(f"/api/graph/{dataset_id}/elements").json()
    assert page["nodes"] == []
    assert page["edges"] == []
    assert page["remaining"] == 0
