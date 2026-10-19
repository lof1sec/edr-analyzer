"""Coverage for the 72 requested Falcon event names and their distinct roles."""

import json

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_next import EVENTS
from app.parsers.vendor import FALCON

NAMES = """DataProtectionArchiveAssessed DataProtectionBrowserConnect DataProtectionDataEncryption DataProtectionPACDiagnostic DBusMessage DcBluetoothDeviceConnected DcBluetoothDeviceConnectedDetails DcBluetoothDeviceDisconnected DcBluetoothDeviceProperties DcIdentification DcOffline DcOnline DcRemovableStorageConnected DcRemovableStorageDeviceBlocked DcRemovableStorageDeviceConnected DcRemovableStorageDeviceDisconnected DcRemovableStorageDevicePolicyViolation DcRemovableStorageDisconnected DcStatus DCSyncAttempted DcUsbConfigurationDescriptor DcUsbDeviceBlocked DcUsbDeviceConnected DcUsbDeviceDisconnected DcUsbDevicePolicyViolation DcUsbDeviceWhitelisted DcUsbEndpointDescriptor DcUsbHIDDescriptor DcUsbInterfaceDescriptor DebFileWritten DeliverLocalFXToCloud DeliverRulesEngineResultsToCloud DetectionExcluded DirectoryCreate DirectoryTraversalOverSMB DiskCapacity DiskUtilization DllInjection DmgFileWritten DmpFileWritten DnsRequest DNSRequestDetectInfo DnsServerSigRedExploitAttemptEtw DocumentProgramInjectedThread DotnetModuleLoadDetectInfo DriverLoad DriverLoadBlocked DriverLoadedV2DetectInfo DriverPreventFailed DriverPreventionStatus DwgFileWritten DwmCompositionResourceExploitAttempt DxfFileWritten EarlyExploitPivotDetect ECBDownloadComplete EddScanStart EddScanStatus ELFFileWritten EmailFileWritten EndOfProcess EnumeratedAgenticArtifacts EnvironmentVariablesChanged ErrorEvent EseFileWritten EtwComponentResponse EtwErrorEvent EventLogCleared ExcelDocumentOpened ExecutableDeleted ExtendedExploitMitigationViolatedDetectInfo FalconHostFileTamperingInfo FalconHostRegTamperingInfo""".split()
EXISTING = set(NAMES) - EVENTS


def graph(name, **fields):
    event = {"#event_simpleName": name, "ComputerName": "WIN1", **fields}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, name, **describe_event(event, FALCON))
    return builder, builder.build_cytoscape_elements()


@pytest.mark.parametrize("name", NAMES)
def test_all_requested_names_map_with_relevant_fields(name):
    assert len(NAMES) == len(set(NAMES)) == 72
    builder, payload = graph(name, ContextProcessId="42", TargetFileName="C:\\test.txt",
                             DomainName="example.org", DeviceInstanceId="usb-1", ImageFileName="driver.sys")
    assert not builder.unmapped_events
    assert payload["elements"]["nodes"]


def test_existing_handlers_are_not_replaced():
    assert EXISTING == {"DebFileWritten", "DirectoryCreate", "DmgFileWritten", "DmpFileWritten",
                        "DnsRequest", "DriverLoad", "DwgFileWritten", "DxfFileWritten",
                        "ELFFileWritten", "EmailFileWritten", "EseFileWritten", "ExecutableDeleted"}


@pytest.mark.parametrize("name", ["DataProtectionArchiveAssessed", "DcUsbDevicePolicyViolation",
                                  "DcBluetoothDeviceConnected", "DBusMessage", "DCSyncAttempted",
                                  "DriverLoadBlocked", "EnvironmentVariablesChanged", "DiskCapacity"])
def test_sensitive_payload_remains_in_evidence(name):
    _, payload = graph(name, ContextProcessId="42", DeviceInstanceId="device",
                       DBusPayload="PRIVATE_SECRET", EnvironmentVariablesString="PRIVATE_SECRET",
                       FeatureVector="PRIVATE_SECRET", ArchiveContents="PRIVATE_SECRET",
                       DiagnosticBuffer="PRIVATE_SECRET", RawData="PRIVATE_SECRET")
    assert "PRIVATE_SECRET" not in json.dumps(payload["elements"])
    assert any("PRIVATE_SECRET" in str(log) for logs in payload["raw_logs"].values() for log in logs)


def test_device_identity_scoped_and_policy_report_distinct():
    _, connected = graph("DcUsbDeviceConnected", DeviceInstanceId="dev1")
    _, blocked = graph("DcUsbDeviceBlocked", DeviceInstanceId="dev1")
    _, violation = graph("DcUsbDevicePolicyViolation", DeviceInstanceId="dev1")
    def ids(payload):
        return {node["data"]["id"] for node in payload["elements"]["nodes"]}
    assert ids(connected) != ids(blocked) != ids(violation)
    assert "Policy Decision" in str(blocked["elements"]["edges"])
    assert "Reports Policy Violation" in str(violation["elements"]["edges"])


def test_ad_sync_uses_context_pid_not_upid():
    _, payload = graph("DCSyncAttempted", ContextProcessId="42", ContextProcessId_UPID="999",
                       SubjectDomainNameEtw="example.org", ObjectNameEtw="CN=Directory")
    ids = {node["data"]["id"] for node in payload["elements"]["nodes"]}
    assert "42@WIN1" in ids
    assert "999@WIN1" not in ids
    assert "SubjectDomainNameEtw" in str(payload["elements"])


def test_bluetooth_identity_stable_and_host_scoped():
    identities = []
    for name in ("DcBluetoothDeviceConnected", "DcBluetoothDeviceDisconnected",
                 "DcBluetoothDeviceConnectedDetails", "DcBluetoothDeviceProperties"):
        _, payload = graph(name, BluetoothDeviceAddress="AB:CD", BluetoothDeviceAddressType="public",
                           BluetoothDeviceType="keyboard", BluetoothDeviceName="Keyboard")
        identities.append({n["data"]["id"] for n in payload["elements"]["nodes"]
                           if "DcBluetooth" in n["data"]["label"]})
    assert all(item == identities[0] for item in identities)
    _, other = graph("DcBluetoothDeviceConnected", ComputerName="WIN2",
                     BluetoothDeviceAddress="AB:CD", BluetoothDeviceAddressType="public")
    assert not identities[0].intersection({n["data"]["id"] for n in other["elements"]["nodes"]})


def test_usb_device_identity_and_descriptor_fallback():
    _, connected = graph("DcUsbDeviceConnected", DeviceInstanceId="USB\\1", DeviceSerialNumber="serial",
                         DeviceVendorId="123", DeviceProductId="456")
    _, disconnected = graph("DcUsbDeviceDisconnected", DeviceInstanceId="USB\\1")
    assert {n["data"]["id"] for n in connected["elements"]["nodes"]} == {
        n["data"]["id"] for n in disconnected["elements"]["nodes"]}
    _, desc = graph("DcUsbEndpointDescriptor", DeviceDescriptorUniqueIdentifier="descriptor-1",
                    DeviceDescriptorSetHash="hash-1")
    assert "descriptor-1" in str(desc["elements"])
    _, missing = graph("DcUsbEndpointDescriptor")
    assert not any("DcUsbEndpointDescriptor: device" in n["data"]["label"]
                   for n in missing["elements"]["nodes"])


@pytest.mark.parametrize("name", ["DataProtectionBrowserConnect", "EndOfProcess", "DetectionExcluded"])
def test_target_upid_uses_process_identity_not_raw_pid(name):
    _, payload = graph(name, TargetProcessId="UPID-123", RawTargetProcessId="42")
    ids = {n["data"]["id"] for n in payload["elements"]["nodes"]}
    assert "42@WIN1" not in ids
    assert "UPID-123@WIN1" in ids
    assert "UPID-123" in str(payload["elements"])


def test_assessment_correlates_with_data_egress():
    _, assessed = graph("DataProtectionArchiveAssessed", AssessmentEventId="assessment-1")
    _, egress = graph("DataEgress", AssessmentEventId="assessment-1")
    def ids(payload):
        return {n["data"]["id"] for n in payload["elements"]["nodes"]}
    assert ids(assessed).intersection(ids(egress))
