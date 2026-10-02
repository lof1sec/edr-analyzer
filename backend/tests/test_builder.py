import json

from app.parsers.builder import GraphBuilder, string_hash


def test_string_hash_is_deterministic():
    assert string_hash("a") == string_hash("a")
    assert string_hash("a") != string_hash("b")
    assert string_hash(r"C:\Windows\cmd.exe") == string_hash(r"C:\Windows\cmd.exe")


def test_edge_ids_are_unique_for_duplicate_events():
    builder = GraphBuilder()
    event = {"ActionType": "ProcessCreated", "ProcessId": "42"}
    for _ in range(5):
        builder.add_edge("1", "42", "Spawns", "#ff4d4d", "ProcessCreated", raw_event=event)

    ids = [edge["id"] for edge in builder.edges_list]
    assert len(ids) == 5
    assert len(set(ids)) == 5


def test_process_nodes_are_keyed_by_pid():
    builder = GraphBuilder()
    builder.get_or_create_process_node("42", "cmd.exe")
    builder.get_or_create_process_node("43", "cmd.exe")
    assert set(builder.nodes_dict) == {"42", "43"}


def test_elements_are_json_serialisable():
    builder = GraphBuilder()
    builder.get_or_create_process_node("42", "cmd.exe")
    builder.add_edge("1", "42", "Spawns", "#ff4d4d", "ProcessCreated", raw_event={"a": 1})
    json.dumps(builder.build_cytoscape_elements())
