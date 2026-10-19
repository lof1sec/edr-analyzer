import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.defender import classify_defender_table, parse_defender_event
from app.parsers.defender_catalog import ACTION_TABLES
from app.parsers.events import describe_event
from app.parsers.vendor import DEFENDER


def test_every_catalog_action_produces_unique_observation():
    builder = GraphBuilder()
    index = 0
    for table, actions in ACTION_TABLES.items():
        for action in actions:
            index += 1
            event = {"TableName": table, "ActionType": action}
            builder.current_event_id = index
            parse_defender_event(builder, event, action, **describe_event(event, DEFENDER))
            assert f"defender_event_{index}" in builder.nodes_dict
            assert f"defender_event_{index}" in builder.event_elements[index]["nodes"]
    assert not builder.unmapped_events


def test_unknown_declared_action_and_actionless_tables():
    for table, event in (("DeviceEvents", {"ActionType": "NovelAction"}),
                         ("DeviceInfo", {}), ("DeviceNetworkInfo", {}),
                         ("DeviceFileCertificateInfo", {})):
        row = {"TableName": table, **event}
        assert classify_defender_table(row) == table
        builder = GraphBuilder()
        builder.current_event_id = 12
        parse_defender_event(builder, row, event.get("ActionType", table),
                             **describe_event(row, DEFENDER))
        assert "defender_event_12" in builder.nodes_dict


def test_conflicting_evidence_creates_no_graph_elements():
    event = {"TableName": "DeviceFileEvents", "ActionType": "RegistryValueSet",
             "InitiatingProcessId": 123, "DeviceName": "host"}
    builder = GraphBuilder()
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    assert not builder.nodes_dict
    assert not builder.edges_list


def test_disruption_subject_does_not_become_process():
    event = {"ActionType": "ContainedUserLogonBlocked", "DeviceName": "reporter",
             "SourceDeviceName": "source", "TargetDeviceName": "target",
             "SourceUserSid": "S-1-5-21", "InitiatingProcessId": 999}
    builder = GraphBuilder()
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    assert not any(node["group"] == "process" for node in builder.nodes_dict.values())
    assert {edge["label"] for edge in builder.edges_list} == {
        "Source device", "Target device", "Source account"}
    assert "DeviceName: reporter" in builder.nodes_dict[next(
        key for key in builder.nodes_dict if key.startswith("defender_event_")
    )]["title"]


@pytest.mark.parametrize(("action", "table"), [
    ("SslConnectionInspected", "DeviceNetworkEvents"),
    ("KerberosConnectionInspected", "DeviceNetworkEvents"),
    ("ClrUnbackedModuleLoaded", "DeviceEvents"),
    ("OtherAlertRelatedActivity", "DeviceEvents"),
])
def test_new_actions_classification_and_conflicts(action, table):
    assert classify_defender_table({"ActionType": action}) == table
    other = "DeviceEvents" if table == "DeviceNetworkEvents" else "DeviceNetworkEvents"
    assert classify_defender_table({"TableName": other, "ActionType": action}) is None
    assert classify_defender_table({"ActionType": action, "LocalIPType": "public"}) == (
        table if table == "DeviceNetworkEvents" else None
    )


@pytest.mark.parametrize(("action", "extra", "relation"), [
    ("SslConnectionInspected", {"RemoteIP": "192.0.2.1"}, "SslConnectionInspected"),
    ("SslConnectionInspected", {"RemoteUrl": "example.org"}, "SslConnectionInspected"),
    ("KerberosConnectionInspected", {"RemoteIP": "192.0.2.1"}, "KerberosConnectionInspected"),
    ("KerberosConnectionInspected", {"RemoteUrl": "example.org"}, "KerberosConnectionInspected"),
    ("ClrUnbackedModuleLoaded", {"AdditionalFields": {"ModuleILPathOrName": "Assembly"}}, "Loads Module"),
])
def test_new_action_artifacts_are_attributed_to_event(action, extra, relation):
    event = {"ActionType": action, "InitiatingProcessId": 42, "DeviceName": "host", **extra}
    builder = GraphBuilder()
    builder.current_event_id = 7
    parse_defender_event(builder, event, action, **describe_event(event, DEFENDER))
    assert [edge["label"] for edge in builder.edges_list].count(relation) == 1
    assert len(builder.event_elements[7]["nodes"]) == 3
    assert len(builder.event_elements[7]["edges"]) == 2


@pytest.mark.parametrize(("action", "extra"), [
    ("SslConnectionInspected", {"RemotePort": 443}),
    ("KerberosConnectionInspected", {"RemotePort": 88, "AccountName": "unverified"}),
    ("ClrUnbackedModuleLoaded", {"AdditionalFields": {"ModuleILPathOrName": []}}),
    ("ClrUnbackedModuleLoaded", {"AdditionalFields": {"ModuleILPathOrName": "  "}}),
    ("OtherAlertRelatedActivity", {"AlertId": "alert-1", "RemoteIP": "192.0.2.1"}),
])
@pytest.mark.parametrize("actor", [None, 42])
def test_new_actions_do_not_invent_artifacts(action, extra, actor):
    event = {"ActionType": action, "InitiatingProcessId": actor, **extra}
    builder = GraphBuilder()
    builder.current_event_id = 8
    parse_defender_event(builder, event, action, **describe_event(event, DEFENDER))
    assert {node["group"] for node in builder.nodes_dict.values()} <= {"event", "process"}
    assert {edge["label"] for edge in builder.edges_list} <= {"Reported by"}
    assert "defender_event_8" in builder.event_elements[8]["nodes"]


@pytest.mark.parametrize("action,extra", [
    ("SslConnectionInspected", {"RemoteIP": "192.0.2.1"}),
    ("KerberosConnectionInspected", {"RemoteIP": "192.0.2.1"}),
    ("ClrUnbackedModuleLoaded", {"AdditionalFields": {"ModuleILPathOrName": "Assembly"}}),
])
def test_new_artifacts_require_actor(action, extra):
    event = {"ActionType": action, **extra}
    builder = GraphBuilder()
    parse_defender_event(builder, event, action, **describe_event(event, DEFENDER))
    assert {node["group"] for node in builder.nodes_dict.values()} == {"event"}


def test_kerberos_inspection_preserves_evidence_without_implying_logon():
    event = {"ActionType": "KerberosConnectionInspected", "InitiatingProcessId": 42,
             "DeviceName": "host", "RemoteIP": "192.0.2.1", "RemotePort": 88,
             "AccountName": "unverified", "AccountDomain": "untrusted",
             "InitiatingProcessAccountName": "process-user",
             "InitiatingProcessAccountDomain": "trusted"}
    fields = describe_event(event, DEFENDER)
    assert fields["username"] == "trusted\\process-user"
    builder = GraphBuilder()
    builder.current_event_id = 9
    parse_defender_event(builder, event, event["ActionType"], **fields)
    assert {edge["label"] for edge in builder.edges_list} == {
        "Reported by", "KerberosConnectionInspected"}
    assert not ({"account", "user"} & {node["group"] for node in builder.nodes_dict.values()})
    assert builder.nodes_dict["42@host"]["raw_logs"][0] == event
    assert builder.nodes_dict["defender_event_9"]["raw_logs"][0] == event
    assert describe_event({**event, "InitiatingProcessAccountName": ""}, DEFENDER)["username"] == "Unknown"
    assert describe_event({"ActionType": "ConnectionAttempt", "AccountName": "other"}, DEFENDER)["username"] == "other"
