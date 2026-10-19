from app.parsers.builder import GraphBuilder
from app.parsers.defender import classify_defender_table, parse_defender_event
from app.parsers.events import describe_event
from app.parsers.vendor import DEFENDER, extract_event_type, get_vendor


def test_literal_action_catalog_and_conflicts():
    assert classify_defender_table({'ActionType': 'RegistryKeyRenamed'}) == 'DeviceRegistryEvents'
    assert classify_defender_table({'ActionType': 'ConnectionAttempt'}) == 'DeviceNetworkEvents'
    assert classify_defender_table({'ActionType': 'LogonSuccess'}) == 'DeviceLogonEvents'
    assert classify_defender_table({'ActionType': 'AntivirusDetection'}) == 'DeviceEvents'
    assert classify_defender_table({'ActionType': 'FileCreated', 'TableName': 'DeviceEvents'}) is None
    assert classify_defender_table({'ActionType': 'UnlistedAction', 'TableName': 'DeviceEvents'}) == 'DeviceEvents'
    assert classify_defender_table({'ActionType': 'FileCreated', 'RegistryKey': 'HKLM'}) == 'DeviceFileEvents'
    assert classify_defender_table({'RegistryKey': 'HKLM'}) is None
    assert get_vendor({'TableName': 'DeviceNetworkInfo'}) == DEFENDER


def test_shared_columns_do_not_override_device_events_actions():
    for event in ({'ActionType': 'BrowserLaunchedToOpenUrl', 'RemoteIP': '192.0.2.4',
                   'RemoteUrl': 'https://example.test'},
                  {'ActionType': 'PowerShellCommand', 'RegistryKey': 'HKLM',
                   'AdditionalFields': '{"Command":"Get-Process"}'}):
        event['InitiatingProcessId'] = 42
        assert classify_defender_table(event) == 'DeviceEvents'
        builder = GraphBuilder()
        parse_defender_event(builder, event, event['ActionType'], **describe_event(event, DEFENDER))
        assert len([edge for edge in builder.edges_list if edge['label'] in {'Launches URL', 'Executes PS'}]) == 1
        assert len([node for node in builder.nodes_dict.values() if node['group'] == 'event']) == 1


def test_actionless_exclusive_signatures_and_disruption_actions():
    for field, table in [('OSPlatform', 'DeviceInfo'), ('MacAddress', 'DeviceNetworkInfo'),
                         ('SignerHash', 'DeviceFileCertificateInfo')]:
        event = {field: 'value'}
        assert get_vendor(event) == DEFENDER
        assert classify_defender_table(event) == table
        assert extract_event_type(event) == table
    assert classify_defender_table({'OSPlatform': 'Windows', 'SignerHash': 'hash'}) is None
    assert classify_defender_table({'ActionType': 'ContainedUserLogonBlocked'}) == 'DisruptionAndResponseEvents'
    assert classify_defender_table({'ActionType': 'ContainedUserLogonBlocked',
                                    'TableName': 'DeviceFileCertificateInfo'}) is None
