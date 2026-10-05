"""Property tests: the Defender parser must never crash and always build a
structurally valid graph, whatever the event fields contain."""
from hypothesis import given

from app.parsers.builder import GraphBuilder
from app.parsers.defender import parse_defender_event
from tests.strategies import (
    DEFENDER_EVENT_TYPES,
    assert_graph_invariants,
    event_dict,
    event_type_strategy,
    optional_id,
)


@given(
    event=event_dict,
    evt_type=event_type_strategy(DEFENDER_EVENT_TYPES),
    actor=optional_id,
    actor_name=optional_id,
    target=optional_id,
    target_name=optional_id,
    username=optional_id,
    hostname=optional_id,
)
def test_defender_events_never_crash(
    event, evt_type, actor, actor_name, target, target_name, username, hostname
):
    builder = GraphBuilder()
    parse_defender_event(
        builder,
        event,
        evt_type,
        actor,
        actor_name,
        target,
        target_name,
        username,
        hostname,
    )
    assert_graph_invariants(builder.build_cytoscape_elements())
