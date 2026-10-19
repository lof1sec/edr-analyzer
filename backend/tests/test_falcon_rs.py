"""Exact Falcon R-S dispatch and conservative evidence semantics."""

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_rs import EVENTS
from app.parsers.vendor import FALCON


def graph(name, **fields):
    event = {"#event_simpleName": name, "ComputerName": "HOST", **fields}
    builder = GraphBuilder()
    builder.current_event_id = 7
    builder.current_event_time = 1700000000000
    parse_falcon_event(builder, event, name, **describe_event(event, FALCON))
    return builder, builder.build_cytoscape_elements()


@pytest.mark.parametrize("name", sorted(EVENTS))
def test_exact_event_dispatch_and_timeline(name):
    builder, payload = graph(name, ContextProcessId="10", RawProcessId="999")
    assert not builder.unmapped_events
    assert "999@HOST" not in builder.nodes_dict
    assert builder.event_elements[7]["nodes"]
    assert all(node["data"].get("first_time") == 1700000000000
               for node in payload["elements"]["nodes"])


@pytest.mark.parametrize("name", ["RecoveryActionKillProcessesReply", "RecoveryActionDeleteFilesComplete",
                                    "RemediationMonitorKillProcess", "RemediationActionKillProcess",
                                    "ServiceStopped"])
def test_status_does_not_claim_real_kill_or_file_delete(name):
    builder, payload = graph(name, TargetProcessId="20", RawProcessId="30", ContextProcessId="10")
    assert "20@HOST" not in builder.nodes_dict
    assert "30@HOST" not in builder.nodes_dict
    assert "Kills" not in str(payload["elements"])
    assert "Deletes File" not in str(payload["elements"])


def test_local_bind_is_not_remote_traffic():
    _, payload = graph("RawBindIP6", ContextProcessId="10", LocalAddressIP6="::1",
                       RemoteAddressIP6="2001:db8::1")
    assert "Binds Local Address" in str(payload["elements"])
    assert "2001:db8::1" not in str(payload["elements"])


def test_container_execution_uses_target_not_raw_parent():
    builder, _ = graph("RecentlyModifiedFileExecutedInContainer", TargetProcessId="20",
                       ParentProcessId="1234", TargetFileName="/tmp/a")
    assert "20@HOST" in builder.nodes_dict
    assert "1234@HOST" not in builder.nodes_dict


@pytest.mark.parametrize("name", ["ScriptControlScanInfo", "ScheduledTaskModified", "RegCredAccessDetectInfo"])
def test_sensitive_payload_kept_in_raw_evidence(name):
    secret = "PRIVATE_SECRET_3b7e"
    _, payload = graph(name, ContextProcessId="10", TaskXml=secret,
                       ScriptContent=secret, Credential=secret)
    assert secret not in str(payload["elements"])
    assert secret in str(payload["raw_logs"])


def test_shell_command_line_shows_reconstructed_command_without_other_sensitive_fields():
    command = "echo hello && whoami"
    builder, payload = graph("ShellCommandLineInfo", ContextProcessId="10",
                             ReconstructedCommandLine=command, Credential="PRIVATE_SECRET")
    node = next(node for node in payload["elements"]["nodes"]
                if node["data"]["group"] == "shell-command")
    assert node["data"]["label"] == command
    assert command not in node["data"]["title"]
    assert "PRIVATE_SECRET" not in str(payload["elements"])
    assert command in str(payload["raw_logs"])
    assert "PRIVATE_SECRET" in str(payload["raw_logs"])
    assert "10@HOST" in builder.nodes_dict
    assert any(edge["data"]["target"] == node["data"]["id"]
               for edge in payload["elements"]["edges"])


@pytest.mark.parametrize("command, expected", [
    (None, "ShellCommandLineInfo"),
    ({"nested": "private"}, "ShellCommandLineInfo"),
    ("x" * 200, "x" * 160),
])
def test_shell_command_line_fallback_and_length(command, expected):
    _, payload = graph("ShellCommandLineInfo", ContextProcessId="10",
                       ReconstructedCommandLine=command)
    node = next(node for node in payload["elements"]["nodes"]
                if node["data"]["group"] == "shell-command")
    assert node["data"]["label"] == expected
