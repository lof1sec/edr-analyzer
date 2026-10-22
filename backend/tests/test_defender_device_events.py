"""DeviceEvents must not invent actors or relationships from unrelated tables."""

from app.parsers.builder import GraphBuilder
from app.parsers.defender import (
    classify_defender_table,
    device_events_table,
    is_confirmed_device_event,
    parse_defender_event,
)
from app.parsers.events import describe_event
from app.parsers.vendor import DEFENDER


def parse(event):
    builder = GraphBuilder()
    builder.current_event_id = 1
    context = describe_event(event, DEFENDER)
    parse_defender_event(builder, event, event["ActionType"], **context)
    return builder


def test_table_marker_is_explicit_only():
    assert device_events_table({"ActionType": "FileCreated", "FileName": "a"}) is None
    assert device_events_table({"SourceTable": "DeviceEvents"}) == "DeviceEvents"
    assert not is_confirmed_device_event({"ActionType": "PowerShellCommand"})
    assert is_confirmed_device_event({"TableName": "DeviceEvents", "SourceTable": "DeviceEvents"})


def test_conflicting_markers_cannot_confirm_device_events():
    event = {"TableName": "DeviceEvents", "SourceTable": "DeviceProcessEvents",
             "ActionType": "PowerShellCommand", "InitiatingProcessId": 42,
             "AdditionalFields": '{"Command":"Get-Process"}'}
    assert not is_confirmed_device_event(event)
    builder = parse(event)
    assert not builder.nodes_dict
    assert not builder.edges_list
    assert builder.unmapped_events == ["PowerShellCommand"]


def test_process_table_creates_parent_child_relationship():
    builder = parse({"TableName": "DeviceProcessEvents", "ActionType": "ProcessCreated",
                     "InitiatingProcessId": 1, "ProcessId": 2, "DeviceName": "host"})
    spawn = [edge for edge in builder.edges_list if edge["label"] == "Spawns"]
    assert len(spawn) == 1
    assert (spawn[0]["source"], spawn[0]["target"]) == ("1@host", "2@host")
    assert builder.nodes_dict["defender_event_1"]["group"] == "event"
    assert builder.event_elements[1]["edges"]


def test_invalid_certificate_dates_do_not_block_process_spawn():
    event = {"ActionType": "ProcessCreated", "InitiatingProcessId": 1, "ProcessId": 2,
             "DeviceName": "host", "Type": "DeviceProcessEvents",
             "CertificateCreationTime": "Invalid date", "CertificateExpirationTime": "Invalid date",
             "CertificateCountersignatureTime": "Invalid date"}
    builder = parse(event)
    assert [(edge["source"], edge["target"]) for edge in builder.edges_list
            if edge["label"] == "Spawns"] == [("1@host", "2@host")]
    assert builder.nodes_dict["1@host"]["raw_logs"][0] == event


def test_process_signatures_and_shared_initiator_identifier():
    assert classify_defender_table({"ActionType": "ProcessCreated", "ProcessUniqueId": "abc"}) == "DeviceProcessEvents"
    assert classify_defender_table({"ActionType": "ProcessCreated", "ProcessIntegrityLevel": "High"}) == "DeviceProcessEvents"
    assert classify_defender_table({"ActionType": "PowerShellCommand", "InitiatingProcessUniqueId": "abc"}) == "DeviceEvents"
    assert classify_defender_table({"TableName": "DeviceEvents", "ActionType": "ProcessCreated",
                                    "ProcessUniqueId": "abc"}) is None


def test_open_process_never_implies_spawn():
    for event in (
        {"TableName": "DeviceProcessEvents"},
        {"ProcessUniqueId": "unique"},
        {},
    ):
        builder = parse({**event, "ActionType": "OpenProcess", "InitiatingProcessId": 1,
                         "ProcessId": 2, "DeviceName": "host"})
        assert not any(edge["label"] == "Spawns" or edge["target"] == "2@host"
                       for edge in builder.edges_list)
        assert builder.nodes_dict["defender_event_1"]["group"] == "event"
        assert builder.unmapped_events == []


def test_unknown_action_does_not_connect_unrelated_processes():
    builder = parse({"TableName": "DeviceEvents", "ActionType": "AppControlPolicyApplied", "InitiatingProcessId": 1,
                     "ProcessId": 2, "DeviceName": "host"})
    assert not any(edge["label"] == "Spawns" or edge["target"] == "2@host"
                   for edge in builder.edges_list)
    assert builder.nodes_dict["defender_event_1"]["group"] == "event"
    assert builder.unmapped_events == []


def test_explicit_powershell_command_retains_evidence_and_event_refs():
    event = {"TableName": "DeviceEvents", "ActionType": "PowerShellCommand",
             "InitiatingProcessId": 42, "DeviceName": "host",
             "AdditionalFields": '{"Command":"Get-Process"}'}
    builder = parse(event)
    semantic = [edge for edge in builder.edges_list if edge["label"] == "Executes PS"]
    assert len(semantic) == 1
    assert semantic[0]["source"] == "42@host"
    assert builder.event_elements[1]["edges"]
    assert builder.nodes_dict["42@host"]["raw_logs"][0] == event


def test_missing_command_does_not_create_placeholder():
    builder = parse({"TableName": "DeviceEvents", "ActionType": "PowerShellCommand", "InitiatingProcessId": 42,
                     "AdditionalFields": "not json"})
    assert builder.nodes_dict["defender_event_1"]["group"] == "event"
    assert not any(node["group"] == "commandline-exec" for node in builder.nodes_dict.values())
    assert builder.unmapped_events == []


def test_activity_families_link_only_observed_actor_and_artifact():
    cases = [
        ("DeviceFileEvents", "FileCreated", {"FolderPath": "C:\\tmp\\a"}, "file"),
        ("DeviceRegistryEvents", "RegistryValueSet", {"RegistryKey": "HKLM\\a",
                                                     "RegistryValueName": "b"}, "registry"),
        ("DeviceNetworkEvents", "ConnectionSuccess", {"RemoteIP": "192.0.2.1",
                                                      "RemotePort": 443}, "network"),
        ("DeviceImageLoadEvents", "ImageLoaded", {"FolderPath": "C:\\tmp\\a.dll"}, "module"),
    ]
    for table, action, fields, group in cases:
        event = {"TableName": table, "ActionType": action, "InitiatingProcessId": 7,
                 "DeviceName": "host", **fields}
        builder = parse(event)
        relation = "Loads Module" if action == "ImageLoaded" else action
        semantic = [edge for edge in builder.edges_list if edge["label"] == relation]
        assert len(semantic) == 1
        edge = semantic[0]
        assert edge["source"] == "7@host"
        assert builder.nodes_dict[edge["target"]]["group"] == group
        assert builder.event_elements[1]["edges"]


def test_ambiguous_or_unsupported_provenance_is_unmapped():
    for event in [
        {"TableName": "DeviceFileEvents", "ActionType": "RegistryValueSet",
         "RegistryKey": "HKLM\\a"},
        {"ActionType": "RegistryValueSet", "RegistryKey": "HKLM\\a", "RemoteIP": "192.0.2.1",
         "TableName": "DeviceNetworkEvents"},
    ]:
        event["InitiatingProcessId"] = 7
        builder = parse(event)
        assert not builder.edges_list
        assert builder.unmapped_events == [event["ActionType"]]
    assert classify_defender_table({"ActionType": "FileCreated", "FolderPath": "a"}) == "DeviceFileEvents"
    logon = parse({"TableName": "DeviceLogonEvents", "ActionType": "LogonSuccess"})
    assert logon.nodes_dict["defender_event_1"]["group"] == "event"
    assert logon.unmapped_events == []
