"""Coverage and identity regressions for the Falcon family manifest."""

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_families import (
    AD_EVENTS,
    AGENT_EVENTS,
    CLOUD_EVENTS,
    FAMILY_EVENTS,
    FILE_EVENTS,
    SENSOR_EVENTS,
    parse_falcon_family,
)
from app.parsers.vendor import FALCON
from tests.strategies import assert_graph_invariants


@pytest.mark.parametrize("kind", sorted(FAMILY_EVENTS))
def test_falcon_family_is_mapped_with_evidence_and_timeline_refs(kind):
    event = {"#event_simpleName": kind, "ComputerName": "WIN1",
             "AccountObjectSid": "S-1-5-21", "AwsInstanceId": "i-123",
             "TargetFileName": r"C:\temp\sample.bin", "AgenticSessionId": "session-1",
             "PatternId": "pattern-1"}
    builder = GraphBuilder()
    builder.current_event_id = 17
    parse_falcon_family(builder, event, kind, "Unknown", "WIN1")
    assert builder.event_elements[17]["nodes"]
    assert builder.event_elements[17]["edges"]
    builder.current_event_id = None
    builder.event_elements.clear()
    payload = builder.build_cytoscape_elements()
    assert_graph_invariants(payload)
    assert not builder.unmapped_events
    assert all(node["data"]["group"] != "process" for node in payload["elements"]["nodes"])
    assert any(edge["data"]["source"] in {node["data"]["id"] for node in payload["elements"]["nodes"]}
               for edge in payload["elements"]["edges"])
    assert all("raw_logs" not in node["data"] for node in payload["elements"]["nodes"])


@pytest.mark.parametrize(("kind", "field", "expected"), [
    ("ActiveDirectoryAccountLocked", "AccountObjectSid", "S-1-5-21"),
    ("AwsEc2Instance", "AwsInstanceId", "i-123"),
    ("AgenticFileOpen", "TargetFileName", "sample.bin"),
    ("AgenticSessionStart", "AgenticSessionId", "session-1"),
    ("AmsBytePatternScanResult", "PatternId", "pattern-1"),
])
def test_family_uses_domain_specific_identity(kind, field, expected):
    event = {"#event_simpleName": kind, "ComputerName": "WIN1", field: expected,
             "ContextProcessId": "42"}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, kind, **describe_event(event, FALCON))
    assert any(expected in node["label"] for node in builder.nodes_dict.values())
    assert any(edge["source"] == "42@WIN1" for edge in builder.edges_list)
    assert "42@WIN1" in builder.nodes_dict


def test_manifest_families_are_disjoint():
    families = (AD_EVENTS, CLOUD_EVENTS, FILE_EVENTS, AGENT_EVENTS, SENSOR_EVENTS)
    assert sum(map(len, families)) == len(FAMILY_EVENTS)
    assert "ClassifiedModuleLoad" not in FAMILY_EVENTS


def test_ad_actor_target_and_auth_to_dc():
    builder = GraphBuilder()
    event = {"PerformedByAccountObjectGuid": "actor-guid", "PerformedOnAccountObjectSid": "target-sid",
             "DomainName": "corp.example", "CustomerId": "tenant-a"}
    parse_falcon_family(builder, event, "ActiveDirectoryAuditUserModified", "", "DC1")
    actor = next(n["id"] for n in builder.nodes_dict.values() if n["label"] == "AD actor: actor-guid")
    target = next(n["id"] for n in builder.nodes_dict.values() if n["label"] == "AD account: target-sid")
    assert any(e["source"] == actor and e["target"] == target for e in builder.edges_list)
    auth = {"SourceAccountObjectSid": "source-sid", "DomainName": "corp.example", "CustomerId": "tenant-a"}
    parse_falcon_family(builder, auth, "ActiveDirectoryAuthenticationFailure", "", "DC1")
    source = next(n["id"] for n in builder.nodes_dict.values() if n["label"] == "AD actor: source-sid")
    assert any(e["source"] == source and builder.nodes_dict[e["target"]]["label"] == "Host: DC1"
               for e in builder.edges_list)


def test_cloud_scope_and_reliable_vpc_relationship():
    builder = GraphBuilder()
    event = {"AwsInstanceId": "i-123", "AwsVpcId": "vpc-123", "AwsRegion": "eu-west-1",
             "AwsAccountId": "111"}
    parse_falcon_family(builder, event, "AwsEc2Instance", "", "")
    instance = next(n["id"] for n in builder.nodes_dict.values() if n["label"] == "AWS AwsEc2Instance: i-123")
    vpc = next(n["id"] for n in builder.nodes_dict.values() if n["label"] == "AWS VPC: vpc-123")
    assert any(e["source"] == instance and e["target"] == vpc for e in builder.edges_list)
    parse_falcon_family(builder, {**event, "AwsAccountId": "222"}, "AwsEc2Instance", "", "")
    assert len([n for n in builder.nodes_dict.values() if n["label"] == "AWS AwsEc2Instance: i-123"]) == 2


def test_agentic_identifiers_and_sensitive_content_not_in_titles():
    builder = GraphBuilder()
    event = {"AgenticSessionId": "session-a", "AgenticToolUseId": "tool-a",
             "AgenticProduct": "assistant", "AgenticPrompt": "SECRET PROMPT",
             "ToolInput": "SECRET INPUT", "ToolOutput": "SECRET OUTPUT", "Password": "SECRET PASSWORD"}
    parse_falcon_family(builder, event, "AgenticToolRequest", "", "")
    assert any(e["label"] == "Uses Tool" for e in builder.edges_list)
    assert all("SECRET" not in n["title"] for n in builder.nodes_dict.values())


def test_missing_identity_does_not_merge_different_rows_or_invent_process():
    builder = GraphBuilder()
    for row in (11, 12):
        builder.current_event_id = row
        parse_falcon_family(builder, {"AccountName": "unknown", "ComputerName": "DC1"},
                            "ActiveDirectoryAccountLocked", "", "DC1")
    observations = [node for node in builder.nodes_dict.values()
                    if node["label"] == "ActiveDirectoryAccountLocked: observation"]
    assert len(observations) == 2
    assert not any(node["group"] == "process" for node in builder.nodes_dict.values())
