"""Conservative mappings for Falcon classifications and sensor observations."""

import io
import json

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_targeted import TARGETED_EVENTS
from app.parsers.vendor import FALCON


def graph(name, **fields):
    event = {"#event_simpleName": name, "ComputerName": "WIN1", **fields}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, name, **describe_event(event, FALCON))
    assert not builder.unmapped_events
    return builder.build_cytoscape_elements()


@pytest.mark.parametrize("name", sorted(TARGETED_EVENTS))
def test_targeted_observations_with_missing_fields(name):
    payload = graph(name, RawProcessId="999", Dump="PRIVATE_DUMP", StackTrace="PRIVATE_STACK")
    nodes = [n["data"] for n in payload["elements"]["nodes"]]
    assert nodes and all(n["group"] != "process" for n in nodes)
    assert "PRIVATE_DUMP" not in json.dumps(payload["elements"])
    assert "PRIVATE_STACK" not in json.dumps(payload["elements"])
    assert any("PRIVATE_DUMP" in str(log) for logs in payload["raw_logs"].values() for log in logs)


def test_classified_start_has_host_scoped_parent_target_and_not_raw_pid():
    payload = graph("ClassifiedProcessStart", ParentProcessId="11", TargetProcessId="22",
                    RawProcessId="33", Classification="RMM")
    nodes = {n["data"]["id"] for n in payload["elements"]["nodes"]}
    assert {"11@WIN1", "22@WIN1"} <= nodes
    assert "33@WIN1" not in nodes
    assert any(e["data"]["source"] == "11@WIN1" and e["data"]["target"] == "22@WIN1"
               for e in payload["elements"]["edges"])


@pytest.mark.parametrize("name", ["CreateThreadKernelNoStartImage", "CreateThreadNoStartImage",
                                   "CreateThreadReflectiveDll"])
def test_threads_link_only_explicit_processes(name):
    payload = graph(name, ContextProcessId="11", TargetProcessId="22")
    assert any(e["data"]["source"] == "11@WIN1" and e["data"]["target"] == "22@WIN1"
               for e in payload["elements"]["edges"])
    payload = graph(name, TargetProcessId="22")
    assert all(e["data"]["source"] != "11@WIN1" for e in payload["elements"]["edges"])


@pytest.mark.parametrize("name,field", [("CommandHistory", "CommandHistory"),
                                      ("CriticalEnvironmentVariableChanged", "EnvironmentVariableValue"),
                                      ("DataEgress", "JustificationUserExplanation")])
def test_sensitive_content_is_evidence_only(name, field):
    payload = graph(name, ContextProcessId="11", EnvironmentVariableName="TOKEN",
                    DataEgressId="egress-1", **{field: "PRIVATE_SECRET_987"})
    assert "PRIVATE_SECRET_987" not in json.dumps(payload["elements"])
    assert any("PRIVATE_SECRET_987" in str(log) for logs in payload["raw_logs"].values() for log in logs)


def test_custom_file_ioa_is_alert_not_file_write():
    payload = graph("CustomIOAFileWrittenDetectionInfoEvent", ContextProcessId="11",
                    TargetFileName="suspicious.txt", PatternId="44")
    assert any(n["data"]["group"] == "alert" for n in payload["elements"]["nodes"])
    assert not any(n["data"]["group"] == "file" for n in payload["elements"]["nodes"])


def test_egress_is_assessment_not_success_or_destination():
    payload = graph("DataEgress", ContextProcessId="11", DataEgressId="id-1",
                    AssessedFileName="report.txt", DataProtectionPolicyRuleAction="Block",
                    JustificationUserExplanation="private")
    assert "Block" in json.dumps(payload["elements"])
    assert "private" not in json.dumps(payload["elements"])
    assert "Exfiltrates" not in json.dumps(payload["elements"])


@pytest.mark.parametrize("name", sorted(TARGETED_EVENTS))
def test_targeted_timeline_has_evidence_refs(admin_client, name):
    event = {"#event_simpleName": name, "ComputerName": "WIN1", "timestamp": "1791477927898",
             "ContextProcessId": "11", "TargetProcessId": "22", "TargetFileName": "sample.txt"}
    response = admin_client.post("/api/datasets/upload", files={
        "file": ("events.jsonl", io.BytesIO(json.dumps(event).encode()), "application/jsonl")})
    assert response.status_code == 200
    timeline = admin_client.get(f"/api/graph/{response.json()['dataset_id']}/timeline").json()
    assert timeline["total"] == 1
    assert timeline["entries"][0]["element_ids"]
