"""Graph and timeline regressions for additional Falcon mappings."""

import io
import json

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_additional import ADDITIONAL_EVENTS
from app.parsers.vendor import FALCON
from tests.strategies import assert_graph_invariants


def _graph(event):
    builder = GraphBuilder()
    event = {"#event_simpleName": event["#event_simpleName"],
             "ComputerName": "WIN1", **event}
    ctx = describe_event(event, FALCON)
    parse_falcon_event(builder, event, event["#event_simpleName"], **ctx)
    payload = builder.build_cytoscape_elements()
    assert_graph_invariants(payload)
    assert builder.unmapped_events == []
    return payload


NEW_EVENTS = (
    "VolumeSnapshotOperationBlocked", "VulnerableDriverDetectInfo", "WebScriptFileWritten",
    "WfpFilterTamperingFilterAdded", "WfpFilterTamperingFilterDeleted", "WmiCreateProcess",
    "WmiFilterConsumerBindingEtw", "WmiProviderRegistrationEtw", "WmiQueryDetectInfo",
    "WroteExeAndGeneratedServiceEvent", "WSLDistributionRegistered", "WSLDistributionStarted",
    "WSLDistributionStopping", "WSLDistributionUnregistered", "WSLMetadata", "WSLVMStarted",
    "WSLVMStopping", "XarFileWritten", "XumdHookEvent", "XumdStatus", "XzFileWritten",
    "Yz1FileWritten", "ZerologonExploitAttempt", "ZipFileWritten", "ZpaqFileWritten",
    "ZstdFileWritten",
)


@pytest.mark.parametrize("name", NEW_EVENTS)
def test_requested_event_is_mapped(name):
    payload = _graph({"#event_simpleName": name, "ContextProcessId": "10",
                      "TargetProcessId": "20", "TargetFileName": "C:\\test.zip"})
    assert payload["elements"]["nodes"]


def test_new_event_dispatch_does_not_overlap_existing_file_and_targeted_handlers():
    assert len(NEW_EVENTS) == 26
    assert not ADDITIONAL_EVENTS.intersection({
        "WebScriptFileWritten", "XarFileWritten", "XzFileWritten", "Yz1FileWritten",
        "ZipFileWritten", "ZpaqFileWritten", "ZstdFileWritten",
    })


@pytest.mark.parametrize("name", ["WfpFilterTamperingFilterAdded", "WSLMetadata",
                                   "VolumeSnapshotOperationBlocked"])
def test_host_events_and_ambiguous_rpc_do_not_invent_remote_process(name):
    payload = _graph({"#event_simpleName": name, "RpcClientProcessId": "999",
                      "WslHostAgentId": "888", "CommandLine": "PRIVATE_COMMAND"})
    serialized = json.dumps(payload["elements"])
    assert "999@WIN1" not in serialized
    assert "888@WIN1" not in serialized
    assert "PRIVATE_COMMAND" not in serialized


def test_wmi_create_process_uses_target_without_inventing_spawn():
    payload = _graph({"#event_simpleName": "WmiCreateProcess", "TargetProcessId": "20",
                      "ContextProcessId": "10", "CommandLine": "PRIVATE_COMMAND"})
    nodes = {n["data"]["id"] for n in payload["elements"]["nodes"]}
    assert "20@WIN1" in nodes
    assert "10@WIN1" not in nodes
    assert "Spawns" not in json.dumps(payload["elements"])
    assert "PRIVATE_COMMAND" not in json.dumps(payload["elements"])


@pytest.mark.parametrize(("name", "fields", "label"), [
    ("InjectedThread", {"ContextProcessId": "10", "TargetProcessId": "20",
                        "TargetThreadId": "30", "InjectedThreadFlag": "0x202",
                        "ThreadStartAddress": "0xabcd"}, "InjectedThread"),
    ("DllInjection", {"ContextProcessId": "10", "TargetProcessId": "20",
                     "InjectedDll": r"C:\tmp\bad.dll"}, "DllInjection"),
    ("ProcessInjection", {"ContextProcessId": "10", "TargetProcessId": "20",
                         "ThreadExecutionControlType": "3", "PayloadClassificationFlags": 6,
                         "InjecteeImageFileName": r"C:\Windows\svchost.exe"}, "ProcessInjection"),
])
def test_injection_has_source_to_target_edge_and_evidence(name, fields, label):
    payload = _graph({"#event_simpleName": name, **fields})
    nodes = {node["data"]["id"]: node["data"] for node in payload["elements"]["nodes"]}
    edges = [edge["data"] for edge in payload["elements"]["edges"]]
    assert {"10@WIN1", "20@WIN1"} <= nodes.keys()
    assert any(e["source"] == "10@WIN1" and e["target"] == "20@WIN1"
               and e["label"] == label for e in edges)
    alert = next(node for node in nodes.values() if node["group"] == "alert")
    assert "20@WIN1" in {e["source"] for e in edges if e["target"] == alert["id"]}
    if name == "InjectedThread":
        assert "START_ADDRESS_PRIVATE_MEM" in alert["title"]
        assert "START_ADDRESS_IN_NAMED_PE" in alert["title"]
    elif name == "DllInjection":
        assert any(n["group"] == "module" and n["label"] == "bad.dll" for n in nodes.values())
    else:
        assert "PROCESS_HOLLOWING" in alert["title"]
        assert "KNOWN_MALICIOUS" in alert["title"]


@pytest.mark.parametrize(("name", "fields", "group", "edge", "detail"), [
    ("NewExecutableRenamed", {"ContextProcessId": "10", "SourceFileName": r"C:\a.exe",
                              "TargetFileName": r"C:\b.exe"}, "file", "Renames Executable", "C:\\a.exe"),
    ("ReflectiveDotnetModuleLoad", {"ContextProcessId": "10", "AssemblyName": "Evil.Assembly",
                                    "DotnetModuleId": "123", "AssemblyFlags": "0x2",
                                    "DotnetModuleFlags": "0x4"}, "module", "Loads .NET Module", "ASSEMBLY_DYNAMIC"),
    ("ScriptControlDetectInfo", {"ContextProcessId": "10", "ScriptContentName": "evil.ps1",
                                 "ScriptContent": "secret contents", "PatternId": "44",
                                 "TemplateDisposition": "30", "ScriptContentSource": "3"},
     "alert", "Detects Script", "PREVENT"),
    ("SensitiveWmiQuery", {"ContextProcessId": "10", "WmiNamespaceName": r"root\cimv2",
                           "WmiQuery": "SELECT * FROM Win32_Process"},
     "commandline", "Queries WMI", "root\\cimv2"),
    ("CreateService", {"ContextProcessId": "10", "RpcClientProcessId": "11",
                       "ServiceObjectName": "EvilSvc", "ServiceImagePath": r"C:\evil.exe",
                       "ServiceStart": "2", "ServiceType": "16"},
     "registry", "Creates Service", "AUTO_START"),
])
def test_process_artifacts(name, fields, group, edge, detail):
    payload = _graph({"#event_simpleName": name, **fields})
    nodes = {n["data"]["id"]: n["data"] for n in payload["elements"]["nodes"]}
    artifact = next(node for node in nodes.values() if node["group"] == group)
    edges = [e["data"] for e in payload["elements"]["edges"]]
    owner = "11@WIN1" if name == "CreateService" else "10@WIN1"
    assert any(e["source"] == owner and e["target"] == artifact["id"]
               and e["label"] == edge for e in edges)
    assert detail in artifact["title"]
    if name == "ScriptControlDetectInfo":
        assert "secret contents" not in artifact["title"]
    if name == "CreateService":
        assert "10@WIN1" not in nodes


def test_remote_command_response_is_host_scoped_without_copying_output():
    payload = _graph({"#event_simpleName": "RemoteCommandResponse",
                      "CommandName": "whoami", "CommandCode": 6,
                      "CommandStdOut": "SECRET_STDOUT", "CommandStdErr": "SECRET_STDERR",
                      "CloudErrorCode": "11", "CommandSequenceNumber": 1})
    nodes = {n["data"]["id"]: n["data"] for n in payload["elements"]["nodes"]}
    response = next(n for n in nodes.values() if n["id"].startswith("remote_response_"))
    assert nodes["host_WIN1"]["group"] == "network"
    assert "EXEC (6)" in response["title"]
    assert "RR_EXECUTION_TIMEOUT_ERROR (11)" in response["title"]
    assert "SECRET_STDOUT" not in json.dumps(payload["elements"])
    assert "SECRET_STDERR" not in json.dumps(payload["elements"])
    assert payload["elements"]["edges"][0]["data"]["source"] == "host_WIN1"
    assert any("SECRET_STDOUT" in str(log) for logs in payload["raw_logs"].values()
               for log in logs)


def test_injection_uses_upids_not_raw_pids_and_keeps_unknown_codes():
    payload = _graph({"#event_simpleName": "InjectedThread",
                      "ContextProcessId": "101", "TargetProcessId": "202",
                      "RawProcessId": "42", "RawThreadId": "43",
                      "InjectedThreadFlag": "0x400", "TargetThreadId": 900})
    nodes = {n["data"]["id"]: n["data"] for n in payload["elements"]["nodes"]}
    assert {"101@WIN1", "202@WIN1"} <= nodes.keys()
    assert "42@WIN1" not in nodes
    alert = next(n for n in nodes.values() if n["group"] == "alert")
    assert "0x400 (0x400)" in alert["title"]


def test_file_rename_keeps_both_files_as_process_leaves():
    payload = _graph({"#event_simpleName": "NewExecutableRenamed",
                      "ContextProcessId": "10", "SourceFileName": r"C:\a.exe",
                      "TargetFileName": r"C:\b.exe"})
    nodes = {n["data"]["id"]: n["data"] for n in payload["elements"]["nodes"]}
    files = [n for n in nodes.values() if n["group"] == "file"]
    assert {n["label"] for n in files} == {"a.exe", "b.exe"}
    assert all(edge["data"]["source"] == "10@WIN1"
               for edge in payload["elements"]["edges"])


@pytest.mark.parametrize("name", [
    "InjectedThread", "DllInjection", "ProcessInjection", "NewExecutableRenamed",
    "ReflectiveDotnetModuleLoad", "ScriptControlDetectInfo", "SensitiveWmiQuery",
    "CreateService", "RemoteCommandResponse",
])
def test_missing_optional_fields_are_safe(name):
    _graph({"#event_simpleName": name, "ContextProcessId": "10",
            "InjectedThreadFlag": {"unexpected": 1}, "TemplateDisposition": "bogus"})


@pytest.mark.parametrize(("name", "fields", "summary_part"), [
    ("InjectedThread", {"ContextProcessId": "10", "TargetProcessId": "20"}, "20"),
    ("DllInjection", {"ContextProcessId": "10", "TargetProcessId": "20"}, "20"),
    ("ProcessInjection", {"ContextProcessId": "10", "TargetProcessId": "20"}, "20"),
    ("NewExecutableRenamed", {"ContextProcessId": "10", "SourceFileName": "a.exe",
                              "TargetFileName": "b.exe"}, "b.exe"),
    ("ReflectiveDotnetModuleLoad", {"ContextProcessId": "10", "AssemblyName": "Evil"}, "Evil"),
    ("ScriptControlDetectInfo", {"ContextProcessId": "10", "ScriptContentName": "evil.ps1"}, "evil.ps1"),
    ("SensitiveWmiQuery", {"ContextProcessId": "10", "WmiQuery": "SELECT x"}, "SELECT x"),
    ("CreateService", {"RpcClientProcessId": "11", "ServiceObjectName": "EvilSvc"}, "EvilSvc"),
    ("RemoteCommandResponse", {"CommandName": "whoami"}, "whoami"),
])
def test_upload_timeline_maps_each_event(admin_client, name, fields, summary_part):
    event = {"#event_simpleName": name, "ComputerName": "WIN1",
             "timestamp": "1791477927898", **fields}
    resp = admin_client.post("/api/datasets/upload", files={
        "file": ("events.jsonl", io.BytesIO(json.dumps(event).encode()), "application/jsonl")})
    assert resp.status_code == 200
    dataset_id = resp.json()["dataset_id"]
    timeline = admin_client.get(f"/api/graph/{dataset_id}/timeline").json()
    assert timeline["total"] == 1
    assert summary_part in timeline["entries"][0]["summary"]
    assert timeline["entries"][0]["element_ids"]
    if name == "RemoteCommandResponse":
        assert "host_WIN1" in timeline["entries"][0]["element_ids"]
