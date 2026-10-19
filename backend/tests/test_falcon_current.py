"""Conservative Falcon observation mappings and evidence boundaries."""

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_current import EVENTS
from app.parsers.vendor import FALCON


def graph(name, **fields):
    event = {"#event_simpleName": name, "ComputerName": "HOST", **fields}
    builder = GraphBuilder()
    builder.current_event_id = 7
    builder.current_event_time = 1700000000000
    parse_falcon_event(builder, event, name, **describe_event(event, FALCON))
    return builder, builder.build_cytoscape_elements()


@pytest.mark.parametrize("name", sorted(EVENTS))
def test_current_events_are_mapped_with_host_scoped_process_and_timeline(name):
    builder, payload = graph(name, ContextProcessId="10")
    assert not builder.unmapped_events
    assert "10@HOST" in builder.nodes_dict or name in {"ProcessRollup2Stats", "ProcessRollup2StatsLRU"}
    assert builder.event_elements[7]["nodes"]
    assert all(node["data"].get("first_time") == 1700000000000
               for node in payload["elements"]["nodes"])


@pytest.mark.parametrize("name", ["ProcessBlocked", "RawBindIP4", "OdsMaliciousFileFound",
                                   "OdsActionStatus", "ProcessRollup2Stats"])
def test_observation_does_not_infer_unrelated_action(name):
    builder, payload = graph(name, ContextProcessId="10", TargetProcessId="20",
                             LocalAddressIP4="127.0.0.1")
    labels = [edge["data"]["label"] for edge in payload["elements"]["edges"]]
    assert labels == ["Observed"] if name != "ProcessRollup2Stats" else labels == []
    assert not builder.unmapped_events


@pytest.mark.parametrize("name", ["PhpEvalString", "Pop3Command", "PeHeaderInfo",
                                   "PrimaryTokenInfo", "PodInfo", "ProxyConnectionInfo"])
def test_sensitive_fields_remain_in_raw_evidence(name):
    secret = "SECRET_PRIVATE_PAYLOAD"
    builder, payload = graph(name, ContextProcessId="10", CommandArg1=secret,
                             TokenPrivileges=secret, PodSpec=secret, ProxyPassword=secret,
                             DecodedScript=secret, PeHeader=secret)
    assert secret not in str(payload["elements"])
    assert secret in str(payload["raw_logs"])
    assert not builder.unmapped_events
