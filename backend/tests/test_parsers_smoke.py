import json

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.defender import parse_defender_event
from app.parsers.falcon import parse_falcon_event


def _build_falcon():
    builder = GraphBuilder()
    parse_falcon_event(
        builder,
        {
            "#event_simpleName": "ProcessRollup2",
            "ContextProcessId": "100",
            "ParentProcessId": "50",
            "TargetProcessId": "101",
            "ParentBaseFileName": "explorer.exe",
            "ImageFileName": r"C:\tmp\evil.exe",
            "CommandLine": "evil.exe -x",
            "UserName": r"CORP\alice",
            "ComputerName": "H1",
            "timestamp": "111",
        },
        "ProcessRollup2", "100", None, "101", None, r"CORP\alice", "H1",
    )
    parse_falcon_event(
        builder,
        {
            "#event_simpleName": "NewExecutableWritten",
            "ContextProcessId": "101",
            "TargetFileName": r"C:\tmp\evil.exe",
            "SHA256HashData": "abc",
            "timestamp": "112",
        },
        "NewExecutableWritten", "101", None, None, None, None, None,
    )
    return builder


def _build_defender():
    builder = GraphBuilder()
    parse_defender_event(
        builder,
        {
            "ActionType": "ProcessCreated",
            "InitiatingProcessId": "500",
            "ProcessId": "600",
            "InitiatingProcessFileName": "services.exe",
            "FileName": "svchost.exe",
            "ProcessCommandLine": "svchost -k netsvcs",
            "AccountName": "SYSTEM",
            "DeviceName": "H2",
        },
        "ProcessCreated", "500", "services.exe", "600", "svchost.exe", "SYSTEM", "H2",
    )
    parse_defender_event(
        builder,
        {
            "ActionType": "ConnectionSuccess",
            "InitiatingProcessId": "600",
            "RemoteIP": "1.2.3.4",
            "RemotePort": "443",
            "LocalIP": "10.0.0.1",
            "LocalPort": "5000",
            "DeviceName": "H2",
        },
        "ConnectionSuccess", "600", None, None, None, "SYSTEM", "H2",
    )
    return builder


@pytest.mark.parametrize("build", [_build_falcon, _build_defender])
def test_graph_ids_are_unique_and_serialisable(build):
    payload = build().build_cytoscape_elements()
    json.dumps(payload)  # must not raise

    node_ids = [n["data"]["id"] for n in payload["elements"]["nodes"]]
    edge_ids = [e["data"]["id"] for e in payload["elements"]["edges"]]

    assert len(node_ids) == len(set(node_ids))
    assert len(edge_ids) == len(set(edge_ids))
    assert not (set(node_ids) & set(edge_ids))


def test_defender_powershell_command_uses_dark_orange_exec_style():
    builder = GraphBuilder()
    parse_defender_event(
        builder,
        {
            "ActionType": "PowerShellCommand",
            "InitiatingProcessId": "700",
            "AdditionalFields": '{"Command": "Get-ChildItem"}',
        },
        "PowerShellCommand", "700", "powershell.exe", None, None, "SYSTEM", "H2",
    )

    payload = builder.build_cytoscape_elements()
    node = next(n for n in payload["elements"]["nodes"] if n["data"]["group"] == "commandline-exec")
    assert node["data"]["group"] == "commandline-exec"

    edge = next(e for e in payload["elements"]["edges"] if e["data"]["label"] == "Executes PS")
    assert edge["data"]["color"] == "#c2410c"


def test_falcon_registry_numeric_value_does_not_crash():
    """Regression: a numeric ``RegValueName`` used to hit ``len(int)``."""
    builder = GraphBuilder()
    parse_falcon_event(
        builder,
        {
            "#event_simpleName": "RegValueCommit",
            "ContextProcessId": "900",
            "RegObjectName": r"\Registry\Machine\Software\X",
            "RegValueName": 1,
        },
        "RegValueCommit", "900", "reg.exe", None, None, None, "H1",
    )

    payload = builder.build_cytoscape_elements()
    reg_nodes = [n for n in payload["elements"]["nodes"] if n["data"]["group"] == "registry"]
    assert len(reg_nodes) == 1


def test_falcon_command_history_uses_dark_orange_exec_style():
    builder = GraphBuilder()
    parse_falcon_event(
        builder,
        {
            "#event_simpleName": "CommandHistory",
            "ContextProcessId": "800",
            "CommandHistory": "whoami",
        },
        "CommandHistory", "800", "cmd.exe", None, None, "CORP\\bob", "H1",
    )

    payload = builder.build_cytoscape_elements()
    node = next(n for n in payload["elements"]["nodes"] if n["data"]["group"] == "commandline-exec")
    assert node["data"]["group"] == "commandline-exec"

    edge = next(e for e in payload["elements"]["edges"] if e["data"]["label"] == "History")
    assert edge["data"]["color"] == "#c2410c"
