import json

from app.parsers.builder import (
    MAX_RAW_LOGS_PER_ELEMENT,
    GraphBuilder,
    string_hash,
)


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


def test_raw_logs_are_separated_from_element_data():
    builder = GraphBuilder()
    builder.get_or_create_process_node("42", "cmd.exe", raw_event={"a": 1})
    builder.add_edge("1", "42", "Spawns", "#ff4d4d", "ProcessCreated", raw_event={"b": 2})

    payload = builder.build_cytoscape_elements()

    for element in payload["elements"]["nodes"] + payload["elements"]["edges"]:
        assert "raw_logs" not in element["data"]
        assert "search_index" not in element["data"]

    assert payload["raw_logs"]["42"] == [{"a": 1}]
    assert payload["raw_logs"]["edge_1"] == [{"b": 2}]
    # The search haystack lives in a side map, never in the element data.
    assert "42" in payload["search_index"]
    assert "edge_1" in payload["search_index"]


def test_raw_logs_are_capped_but_total_is_kept():
    builder = GraphBuilder()
    total = MAX_RAW_LOGS_PER_ELEMENT + 5
    for i in range(total):
        builder.get_or_create_process_node("42", "cmd.exe", raw_event={"i": i})

    payload = builder.build_cytoscape_elements()
    node = next(n for n in payload["elements"]["nodes"] if n["data"]["id"] == "42")

    assert len(payload["raw_logs"]["42"]) == MAX_RAW_LOGS_PER_ELEMENT
    assert payload["raw_logs"]["42"][0] == {"i": 0}
    assert node["data"]["raw_logs_total"] == total


def test_search_index_covers_events_beyond_the_raw_log_cap():
    builder = GraphBuilder()
    total = MAX_RAW_LOGS_PER_ELEMENT + 50
    for i in range(total):
        builder.get_or_create_process_node("42", "cmd.exe", raw_event={"marker": f"token{i}"})

    payload = builder.build_cytoscape_elements()
    last_token = f"token{total - 1}"

    # Searchable even though the retained evidence list dropped it.
    assert last_token in payload["search_index"]["42"]
    assert last_token not in json.dumps(payload["raw_logs"]["42"])
