"""Regression coverage for Falcon process-to-I/O families."""

import json

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_additional import ADDITIONAL_EVENTS
from app.parsers.falcon_families import FAMILY_EVENTS
from app.parsers.falcon_next import EVENTS as NEXT_EVENTS
from app.parsers.falcon_process_to_io import EVENTS, FILE, FIREWALL, FIRMWARE, HOST, HTTP, IDP, PROCESS, SERVICE
from app.parsers.falcon_targeted import TARGETED_EVENTS
from app.parsers.vendor import FALCON


@pytest.mark.parametrize("kind", sorted(EVENTS))
def test_event_is_mapped_and_sensitive_values_stay_in_evidence(kind):
    event = {"#event_simpleName": kind, "ComputerName": "host1", "ContextProcessId": "42",
             "ContextProcessId_UPID": "999", "RawProcessId": "888", "TargetFileName": "sample.txt",
             "DomainName": "example.org", "FileContentsDiff": "PRIVATE_SENTINEL",
             "FimDiffData": "PRIVATE_SENTINEL", "HttpRequestHeaders": "PRIVATE_SENTINEL",
             "CommandArguments": "PRIVATE_SENTINEL", "IdpTelemetryObjectArray": "PRIVATE_SENTINEL",
             "EfiVariableData": "PRIVATE_SENTINEL", "InstanceMetadataRequest": "PRIVATE_SENTINEL"}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, kind, **describe_event(event, FALCON))
    payload = builder.build_cytoscape_elements()
    assert not builder.unmapped_events
    assert kind == "HostedServiceStopped" or "42@host1" in {
        node["data"]["id"] for node in payload["elements"]["nodes"]}
    assert "999@host1" not in str(payload["elements"])
    assert "PRIVATE_SENTINEL" not in json.dumps(payload["elements"])
    assert "PRIVATE_SENTINEL" in str(payload["raw_logs"])


def test_family_sets_are_disjoint_and_existing_mappings_take_precedence():
    groups = (FILE, FIREWALL, HTTP, FIRMWARE, IDP, SERVICE, PROCESS, HOST)
    assert len(EVENTS) == sum(map(len, groups)) == 99
    assert not EVENTS & (ADDITIONAL_EVENTS | FAMILY_EVENTS | NEXT_EVENTS | TARGETED_EVENTS)


def test_policy_simulation_does_not_claim_enforcement():
    event = {"#event_simpleName": "IdpPolicyAccessRuleMatch", "ComputerName": "host1",
             "ContextProcessId": "42", "SimulationMode": "true", "RuleId": "r1"}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, event["#event_simpleName"], **describe_event(event, FALCON))
    assert "Simulated Policy Match" in str(builder.build_cytoscape_elements()["elements"]["edges"])


@pytest.mark.parametrize(("kind", "field", "value", "expected"), [
    ("FirewallRuleIP4Matched", "FirewallRuleId", "fw-1", "Aggregated Rule Matches"),
    ("HttpResponse", "HttpStatus", "404", "HttpStatus: 404"),
    ("FirmwareImageAnalyzed", "BiosId", "bios-1", "bios-1"),
    ("IdpCloudHealthStatus", "IdpCloudConnectivityState", "offline", "offline"),
    ("FalconServiceStatus", "FalconServiceComponent", "sensor", "sensor"),
    ("InstalledApplication", "AppProductId", "pkg-1", "pkg-1"),
    ("FsVolumeMounted", "VolumeSessionUUID", "volume-1", "volume-1"),
    ("FileIntegrityMonitorRuleMatched", "ObjectAccessOperationType", "read", "read"),
])
def test_schema_fields_are_exposed(kind, field, value, expected):
    event = {"#event_simpleName": kind, "ComputerName": "host1", "ContextProcessId": "42", field: value}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, kind, **describe_event(event, FALCON))
    assert expected in str(builder.build_cytoscape_elements()["elements"])


def test_rename_and_process_links_are_directional():
    for kind, fields, label in (
        ("FileRenameInfo", {"SourceFileName": "old.txt", "TargetFileName": "new.txt"}, "Renamed To"),
        ("FalconProcessHandleOpDetectInfo", {"TargetProcessId": "77", "HandleOperation": "Open"}, "Open"),
        ("InjectedThreadFromUnsignedModule", {"TargetProcessId": "77"}, "Injected Thread"),
    ):
        event = {"#event_simpleName": kind, "ComputerName": "host1", "ContextProcessId": "42", **fields}
        builder = GraphBuilder()
        parse_falcon_event(builder, event, kind, **describe_event(event, FALCON))
        payload = builder.build_cytoscape_elements()["elements"]
        assert label in str(payload["edges"])
        if kind != "FileRenameInfo":
            assert {"42@host1", "77@host1"} <= {n["data"]["id"] for n in payload["nodes"]}


def test_stopped_service_has_no_context_initiator_and_url_is_private():
    for kind, fields, forbidden in (
        ("HostedServiceStopped", {"TargetProcessId": "77"}, "42@host1"),
        ("HttpRequestDetect", {"HttpUrl": "https://example.org/secret?token=private"}, "private"),
    ):
        event = {"#event_simpleName": kind, "ComputerName": "host1", "ContextProcessId": "42", **fields}
        builder = GraphBuilder()
        parse_falcon_event(builder, event, kind, **describe_event(event, FALCON))
        assert forbidden not in str(builder.build_cytoscape_elements()["elements"])
