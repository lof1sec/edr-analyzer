"""Property tests for the GraphBuilder primitives and its output invariants."""
from hypothesis import given
from hypothesis import strategies as st

from app.parsers.builder import (
    GraphBuilder,
    get_additional_fields_dict,
    hash_str,
    string_hash,
)
from tests.strategies import assert_graph_invariants, event_dict, json_value

ARTIFACT_GROUPS = [
    "file",
    "registry",
    "network",
    "module",
    "commandline",
    "commandline-exec",
    "alert",
]

nonempty_id = st.one_of(
    st.integers(min_value=1, max_value=10_000),
    st.text(min_size=1, max_size=16).filter(lambda value: not value.startswith("edge_")),
)


@given(event=event_dict)
def test_additional_fields_always_returns_dict(event):
    assert isinstance(get_additional_fields_dict(event), dict)


@given(value=st.one_of(json_value, event_dict))
def test_hashes_accept_any_value(value):
    # ``json_value`` includes lists/dicts, i.e. unhashable inputs, which must not
    # blow up the (cached) digest helpers.
    assert isinstance(hash_str(value), str)
    assert isinstance(string_hash(value), str)
    assert hash_str(value) == hash_str(value)
    assert string_hash(value) == string_hash(value)


@st.composite
def random_graph(draw):
    builder = GraphBuilder()
    ids = draw(st.lists(nonempty_id, unique=True, max_size=8))
    for node_id in ids:
        if draw(st.booleans()):
            builder.get_or_create_process_node(
                node_id, draw(st.one_of(st.none(), st.text(max_size=8)))
            )
        else:
            builder.add_or_update_artifact_node(
                node_id,
                draw(st.text(max_size=8)),
                draw(st.text(max_size=16)),
                draw(st.sampled_from(ARTIFACT_GROUPS)),
            )
    if ids:
        for _ in range(draw(st.integers(min_value=0, max_value=8))):
            builder.add_edge(
                draw(st.sampled_from(ids)),
                draw(st.sampled_from(ids)),
                draw(st.text(max_size=8)),
                "#ffffff",
                draw(st.text(max_size=8)),
            )
    return builder


@given(builder=random_graph())
def test_built_graph_always_satisfies_invariants(builder):
    assert_graph_invariants(builder.build_cytoscape_elements())
