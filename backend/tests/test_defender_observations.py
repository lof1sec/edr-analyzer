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


def test_dns_connection_inspected_includes_additional_fields_in_node():
    event = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "DnsConnectionInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "RemoteIP": "8.8.8.8",
        "RemotePort": 53,
        "AdditionalFields": (
            '{"query":"example.test","qtype_name":"A","rcode_name":"NOERROR","direction":"Out"}'
        ),
    }
    builder = GraphBuilder()
    builder.current_event_id = 10
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    node = net_nodes[0]
    assert node["label"] == (
        "8.8.8.8:53\n"
        "Query: example.test\n"
        "QType: A | RCode: NOERROR\n"
        "Direction: Out"
    )
    assert "Remote: 8.8.8.8:53" in node["title"]
    assert "Query: example.test" in node["title"]
    assert "QType: A" in node["title"]
    assert "RCode: NOERROR" in node["title"]
    assert "Direction: Out" in node["title"]


def test_dns_connection_inspected_separates_queries_to_same_resolver_and_handles_long_query():
    long_domain = "a" * 70 + ".example.test"
    events = [
        {
            "Type": "DeviceNetworkEvents",
            "ActionType": "DnsConnectionInspected",
            "InitiatingProcessId": 42,
            "DeviceName": "host",
            "RemoteIP": "10.0.0.2",
            "RemotePort": 53,
            "AdditionalFields": {"query": "first.test", "qtype_name": "A",
                                 "rcode_name": "NOERROR", "direction": "Out"},
        },
        {
            "Type": "DeviceNetworkEvents",
            "ActionType": "DnsConnectionInspected",
            "InitiatingProcessId": 42,
            "DeviceName": "host",
            "RemoteIP": "10.0.0.2",
            "RemotePort": 53,
            "AdditionalFields": {"query": long_domain, "qtype_name": "TXT",
                                 "rcode_name": "NXDOMAIN", "direction": "Out"},
        },
    ]
    builder = GraphBuilder()
    for idx, event in enumerate(events, start=1):
        builder.current_event_id = idx
        parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))

    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 2
    long_node = next(n for n in net_nodes if "NXDOMAIN" in n["label"])
    assert "QType: TXT | RCode: NXDOMAIN" in long_node["label"]
    assert "Direction: Out" in long_node["label"]
    assert long_domain in long_node["title"]


def test_dns_connection_inspected_partial_and_empty_additional_fields():
    # Query only (no RemoteIP) still renders the DNS artifact.
    event_query_only = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "DnsConnectionInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "AdditionalFields": '{"query":"only.test","direction":"Out"}',
    }
    builder = GraphBuilder()
    parse_defender_event(builder, event_query_only, "DnsConnectionInspected",
                         **describe_event(event_query_only, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    assert net_nodes[0]["label"] == "Query: only.test\nDirection: Out"

    # RemoteIP:RemotePort without DNS fields stays compact.
    event_ip_only = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "DnsConnectionInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "RemoteIP": "8.8.8.8",
        "RemotePort": 53,
    }
    builder = GraphBuilder()
    parse_defender_event(builder, event_ip_only, "DnsConnectionInspected",
                         **describe_event(event_ip_only, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    assert net_nodes[0]["label"] == "8.8.8.8:53"

    # Neither RemoteIP/RemoteUrl nor query creates no network artifact.
    event_empty = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "DnsConnectionInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "AdditionalFields": '{"qtype_name":"A","direction":"Out"}',
    }
    builder = GraphBuilder()
    parse_defender_event(builder, event_empty, "DnsConnectionInspected",
                         **describe_event(event_empty, DEFENDER))
    assert not [n for n in builder.nodes_dict.values() if n["group"] == "network"]


def test_http_connection_inspected_includes_url_and_additional_fields_in_node():
    event = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "HttpConnectionInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "RemoteIP": "93.184.216.34",
        "RemotePort": 80,
        "RemoteUrl": "http://example.test/api/v1",
        "AdditionalFields": (
            '{"host":"example.test","method":"POST","direction":"Out","status_code":200}'
        ),
    }
    builder = GraphBuilder()
    builder.current_event_id = 11
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    node = net_nodes[0]
    assert node["label"] == (
        "93.184.216.34:80\n"
        "URL: http://example.test/api/v1\n"
        "Host: example.test\n"
        "Method: POST | Status: 200\n"
        "Direction: Out"
    )
    assert "Remote: 93.184.216.34:80" in node["title"]
    assert "RemoteUrl: http://example.test/api/v1" in node["title"]
    assert "Host: example.test" in node["title"]
    assert "Method: POST" in node["title"]
    assert "Status: 200" in node["title"]
    assert "Direction: Out" in node["title"]


def test_http_connection_inspected_handles_partial_long_and_empty_fields():
    long_url = "https://example.test/" + "x" * 70
    events = [
        {
            "Type": "DeviceNetworkEvents",
            "ActionType": "HttpConnectionInspected",
            "InitiatingProcessId": 42,
            "DeviceName": "host",
            "RemoteIP": "93.184.216.34",
            "RemotePort": 443,
            "RemoteUrl": long_url,
            "AdditionalFields": {"host": "a.test", "method": "GET", "status_code": 404, "direction": "Out"},
        },
        {
            "Type": "DeviceNetworkEvents",
            "ActionType": "HttpConnectionInspected",
            "InitiatingProcessId": 42,
            "DeviceName": "host",
            "RemoteIP": "93.184.216.34",
            "RemotePort": 443,
            "AdditionalFields": {"host": "b.test", "method": "HEAD", "status_code": 200, "direction": "In"},
        },
    ]
    builder = GraphBuilder()
    for idx, event in enumerate(events, start=1):
        builder.current_event_id = idx
        parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))

    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 2
    first = next(n for n in net_nodes if "a.test" in n["label"])
    assert "Method: GET | Status: 404" in first["label"]
    assert "Direction: Out" in first["label"]
    assert long_url in first["title"]

    # RemoteIP:RemotePort alone stays compact; missing IP/URL/host invents no node.
    b_compact = GraphBuilder()
    ev_compact = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "HttpConnectionInspected",
        "InitiatingProcessId": 42,
        "RemoteIP": "192.0.2.10",
        "RemotePort": 8080,
    }
    parse_defender_event(b_compact, ev_compact, "HttpConnectionInspected", **describe_event(ev_compact, DEFENDER))
    assert [n["label"] for n in b_compact.nodes_dict.values() if n["group"] == "network"] == ["192.0.2.10:8080"]

    b_empty = GraphBuilder()
    ev_empty = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "HttpConnectionInspected",
        "InitiatingProcessId": 42,
        "AdditionalFields": '{"method":"GET","status_code":200}',
    }
    parse_defender_event(b_empty, ev_empty, "HttpConnectionInspected", **describe_event(ev_empty, DEFENDER))
    assert not [n for n in b_empty.nodes_dict.values() if n["group"] == "network"]


def test_listening_connection_created_uses_local_ip_and_port():
    event = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "ListeningConnectionCreated",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "LocalIP": "0.0.0.0",
        "LocalPort": 445,
        "RemoteIP": "192.0.2.1",
        "RemotePort": 0,
    }
    builder = GraphBuilder()
    builder.current_event_id = 12
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    assert net_nodes[0]["label"] == "0.0.0.0:445"
    assert "0.0.0.0:445" in net_nodes[0]["title"]
    edges = [e for e in builder.edges_list if e["label"] == "ListeningConnectionCreated"]
    assert len(edges) == 1
    assert edges[0]["source"] == "42@host"

    # Without LocalIP, no network artifact is invented even if LocalPort is set.
    b_no_ip = GraphBuilder()
    ev_no_ip = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "ListeningConnectionCreated",
        "InitiatingProcessId": 42,
        "LocalPort": 445,
    }
    parse_defender_event(b_no_ip, ev_no_ip, "ListeningConnectionCreated", **describe_event(ev_no_ip, DEFENDER))
    assert not [n for n in b_no_ip.nodes_dict.values() if n["group"] == "network"]


def test_network_signature_inspected_includes_local_endpoint_and_signature_fields():
    event = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NetworkSignatureInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "RemoteIP": "198.51.100.20",
        "RemotePort": 443,
        "LocalIP": "10.0.0.5",
        "LocalPort": 51234,
        "AdditionalFields": (
            '{"SignatureName":"CobaltStrikeBeacon","SignatureMatchedContent":"GET /submit.php?id=123"}'
        ),
    }
    builder = GraphBuilder()
    builder.current_event_id = 13
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    node = net_nodes[0]
    assert node["label"] == (
        "Remote: 198.51.100.20:443\n"
        "Local: 10.0.0.5:51234\n"
        "Signature: CobaltStrikeBeacon\n"
        "Matched: GET /submit.php?id=123"
    )
    assert "Remote: 198.51.100.20:443" in node["title"]
    assert "Local: 10.0.0.5:51234" in node["title"]
    assert "SignatureName: CobaltStrikeBeacon" in node["title"]
    assert "SignatureMatchedContent: GET /submit.php?id=123" in node["title"]


def test_network_signature_inspected_handles_long_content_and_compact_fallback():
    long_match = "LINE1\n" + "X" * 80
    ev_long = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NetworkSignatureInspected",
        "InitiatingProcessId": 42,
        "RemoteIP": "198.51.100.20",
        "RemotePort": 80,
        "LocalIP": "10.0.0.5",
        "LocalPort": 55555,
        "AdditionalFields": {"SignatureName": "SigA", "SignatureMatchedContent": long_match},
    }
    builder = GraphBuilder()
    parse_defender_event(builder, ev_long, "NetworkSignatureInspected", **describe_event(ev_long, DEFENDER))
    node = next(n for n in builder.nodes_dict.values() if n["group"] == "network")
    assert "Signature: SigA" in node["label"]
    assert "Matched: LINE1 " in node["label"]
    assert long_match in node["title"]

    # RemoteIP:RemotePort alone stays compact; empty fields create no network node.
    b_compact = GraphBuilder()
    ev_compact = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NetworkSignatureInspected",
        "InitiatingProcessId": 42,
        "RemoteIP": "198.51.100.20",
        "RemotePort": 443,
    }
    parse_defender_event(b_compact, ev_compact, "NetworkSignatureInspected", **describe_event(ev_compact, DEFENDER))
    assert [n["label"] for n in b_compact.nodes_dict.values() if n["group"] == "network"] == ["198.51.100.20:443"]

    b_empty = GraphBuilder()
    ev_empty = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NetworkSignatureInspected",
        "InitiatingProcessId": 42,
        "LocalPort": 443,
    }
    parse_defender_event(b_empty, ev_empty, "NetworkSignatureInspected", **describe_event(ev_empty, DEFENDER))
    assert not [n for n in b_empty.nodes_dict.values() if n["group"] == "network"]


def test_ntlm_authentication_inspected_includes_additional_fields_in_node():
    event = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NtlmAuthenticationInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "RemoteIP": "10.0.0.10",
        "RemotePort": 445,
        "AdditionalFields": (
            '{"username":"alice","hostname":"WS-01","server_nb_computer_name":"DC01",'
            '"success":"true","direction":"Out"}'
        ),
    }
    builder = GraphBuilder()
    builder.current_event_id = 14
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    node = net_nodes[0]
    assert node["label"] == (
        "10.0.0.10:445\n"
        "User: alice\n"
        "Host: WS-01\n"
        "Server: DC01\n"
        "Success: true | Direction: Out"
    )
    assert "Remote: 10.0.0.10:445" in node["title"]
    assert "Username: alice" in node["title"]
    assert "Hostname: WS-01" in node["title"]
    assert "Server NB: DC01" in node["title"]
    assert "Success: true" in node["title"]
    assert "Direction: Out" in node["title"]


def test_ntlm_authentication_inspected_handles_boolean_false_compact_and_empty():
    ev_false = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NtlmAuthenticationInspected",
        "InitiatingProcessId": 42,
        "RemoteIP": "10.0.0.10",
        "RemotePort": 445,
        "AdditionalFields": {"username": "bob", "success": False, "direction": "In"},
    }
    builder = GraphBuilder()
    parse_defender_event(builder, ev_false, "NtlmAuthenticationInspected", **describe_event(ev_false, DEFENDER))
    node = next(n for n in builder.nodes_dict.values() if n["group"] == "network")
    assert node["label"] == "10.0.0.10:445\nUser: bob\nSuccess: False | Direction: In"

    b_compact = GraphBuilder()
    ev_compact = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NtlmAuthenticationInspected",
        "InitiatingProcessId": 42,
        "RemoteIP": "10.0.0.10",
        "RemotePort": 445,
    }
    parse_defender_event(b_compact, ev_compact, "NtlmAuthenticationInspected", **describe_event(ev_compact, DEFENDER))
    assert [n["label"] for n in b_compact.nodes_dict.values() if n["group"] == "network"] == ["10.0.0.10:445"]

    b_empty = GraphBuilder()
    ev_empty = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "NtlmAuthenticationInspected",
        "InitiatingProcessId": 42,
        "AdditionalFields": '{"success":"false","direction":"Out"}',
    }
    parse_defender_event(b_empty, ev_empty, "NtlmAuthenticationInspected", **describe_event(ev_empty, DEFENDER))
    assert not [n for n in b_empty.nodes_dict.values() if n["group"] == "network"]


def test_ssl_connection_inspected_includes_additional_fields_in_node():
    event = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "SslConnectionInspected",
        "InitiatingProcessId": 42,
        "DeviceName": "host",
        "RemoteIP": "93.184.216.34",
        "RemotePort": 443,
        "AdditionalFields": '{"server_name":"example.test","version":"TLSv13","direction":"Out"}',
    }
    builder = GraphBuilder()
    builder.current_event_id = 15
    parse_defender_event(builder, event, event["ActionType"], **describe_event(event, DEFENDER))
    net_nodes = [n for n in builder.nodes_dict.values() if n["group"] == "network"]
    assert len(net_nodes) == 1
    node = net_nodes[0]
    assert node["label"] == (
        "93.184.216.34:443\n"
        "Server: example.test\n"
        "Version: TLSv13 | Direction: Out"
    )
    assert "Remote: 93.184.216.34:443" in node["title"]
    assert "Server Name: example.test" in node["title"]
    assert "Version: TLSv13" in node["title"]
    assert "Direction: Out" in node["title"]


def test_ssl_connection_inspected_handles_partial_compact_and_empty_fields():
    ev_sni_only = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "SslConnectionInspected",
        "InitiatingProcessId": 42,
        "AdditionalFields": {"server_name": "sni-only.test", "version": "TLSv12"},
    }
    b_sni = GraphBuilder()
    parse_defender_event(b_sni, ev_sni_only, "SslConnectionInspected", **describe_event(ev_sni_only, DEFENDER))
    assert [n["label"] for n in b_sni.nodes_dict.values() if n["group"] == "network"] == [
        "Server: sni-only.test\nVersion: TLSv12"
    ]

    ev_compact = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "SslConnectionInspected",
        "InitiatingProcessId": 42,
        "RemoteIP": "93.184.216.34",
        "RemotePort": 443,
    }
    b_compact = GraphBuilder()
    parse_defender_event(b_compact, ev_compact, "SslConnectionInspected", **describe_event(ev_compact, DEFENDER))
    assert [n["label"] for n in b_compact.nodes_dict.values() if n["group"] == "network"] == ["93.184.216.34:443"]

    ev_empty = {
        "Type": "DeviceNetworkEvents",
        "ActionType": "SslConnectionInspected",
        "InitiatingProcessId": 42,
        "AdditionalFields": '{"version":"TLSv13","direction":"Out"}',
    }
    b_empty = GraphBuilder()
    parse_defender_event(b_empty, ev_empty, "SslConnectionInspected", **describe_event(ev_empty, DEFENDER))
    assert not [n for n in b_empty.nodes_dict.values() if n["group"] == "network"]
