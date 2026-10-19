"""Regression coverage for the exact Falcon event-name block."""

import json

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_user_block import EVENTS, NETWORK
from app.parsers.vendor import FALCON

NAMES = """IoSessionLoggedOn IPCDetectInfo IsoExtensionFileWritten JarFileWritten JavaAgentAttachInfo JavaAgentErrorNotification JavaAgentStatistics JavaAPIVisibilityActorTelemetry JavaClassFileWritten JavaFunctionExecuted JavaInjectedThread JpegFileWritten KernelCallbackTablePatch KernelCallbackTableUpdate KernelModeExecImage KernelModeLoadImage KernelServiceStarted KillProcessError LFODownloadComplete LFODownloadConfirmation LfoUploadDataComplete LfoUploadDataFailed LfoUploadDataUnneeded LfoUploadStart LhaFileWritten LightningLatencyInfo LightningUnresponsiveStatus LnkFileWritten LoadImage LocalIpAddressIP4 LocalIpAddressIP6 LocalIpAddressRemovedIP4 LocalIpAddressRemovedIP6 LocalWindowsUserUpdate LogCollectorDeploymentStatus LogonBehaviorCompositionDetectInfo LowILModuleLoadAttempt LRZipFileWritten LsassHandleFromUnsignedModule LZ4FileWritten LzfseFileWritten LZipFileWritten LzmaFileWritten LZOFileWritten MachOFileWritten MacroContentInfo MacroDetectInfo ManifestDownloadComplete MbrOverwriteRawDetectInfo MemoryAdvise MemoryLocked MemoryMapped MemoryProtectionChanged MemoryProtectionUpdated MemoryScanEnabled MemoryScanErrorEvent ModifyServiceBinary ModuleBlockedEvent ModuleBlockedEventWithPatternId ModuleCertificateInfo2 ModuleDetectInfo ModuleDownloadComplete ModuleLoadV3DetectInfo MotwWritten MountedVolume MSDocxFileWritten MsiFileWritten MsiTransactionExecuted MSPptxFileWritten MSVsdxFileWritten MSXlsxFileWritten NamedMutantHandleClosedTelemetry NamedPipeDetectInfo NamedSemaphoreHandleClosedTelemetry NamespaceChanged NeighborListIP4 NeighborListIP6 NetShareAdd NetShareDelete NetShareSecurityModify NetworkCloseIP4 NetworkCloseIP6 NetworkConnectIP4 NetworkConnectIP4Blocked NetworkConnectIP6 NetworkConnectIP6Blocked NetworkContainmentCompleted NetworkIcmpDataIP4 NetworkIcmpDataIP6 NetworkLinkConfigGetAddress NetworkLinkConfigGetLink NetworkListenIP4 NetworkListenIP6 NetworkModuleLoadAttempt NetworkOutboundPortScanDetectInfo NetworkReceiveAcceptIP4 NetworkReceiveAcceptIP6 NetworkSummary NetworkUncontainmentCompleted NewExecutableRenamed""".split()


def graph(name, **fields):
    event = {"#event_simpleName": name, "ComputerName": "WIN1", **fields}
    builder = GraphBuilder()
    parse_falcon_event(builder, event, name, **describe_event(event, FALCON))
    return builder, builder.build_cytoscape_elements()


@pytest.mark.parametrize("name", NAMES)
def test_exact_names_map(name):
    assert len(NAMES) == len(set(NAMES)) == 100
    builder, payload = graph(name, ContextProcessId="42", TargetProcessId="43",
                             TargetFileName="C:\\example.txt", RemoteAddressIP4="1.2.3.4",
                             RemoteAddressIP6="2001:db8::1", LocalAddressIP4="127.0.0.1",
                             LocalAddressIP6="::1", LocalPort="123", RemotePort="456")
    assert not builder.unmapped_events
    assert payload["elements"]["nodes"]


def test_remaining_names_are_explicit():
    assert len(EVENTS) == 71
    assert NETWORK <= set(NAMES)


@pytest.mark.parametrize("name,relation", [("NetworkConnectIP4Blocked", "Connection Blocked"),
                                            ("NetworkCloseIP6", "Connection Closed"),
                                            ("NetworkListenIP6", "Listens On"),
                                            ("NetworkReceiveAcceptIP4", "Accepts Connection")])
def test_network_semantics_and_address_family(name, relation):
    _, payload = graph(name, ContextProcessId="42", RawProcessId="999",
                       RemoteAddressIP4="1.2.3.4", RemoteAddressIP6="2001:db8::1",
                       LocalAddressIP6="::1", LocalPort="80", RemotePort="443")
    nodes = {node["data"]["id"] for node in payload["elements"]["nodes"]}
    assert "42@WIN1" in nodes and "999@WIN1" not in nodes
    assert any(edge["data"]["label"] == relation for edge in payload["elements"]["edges"])
    assert ("2001:db8::1" in str(payload["elements"])) == ("IP6" in name and "Listen" not in name)


@pytest.mark.parametrize("name", ["IoSessionLoggedOn", "JavaAgentStatistics", "LfoUploadDataFailed",
                                  "NetworkContainmentCompleted", "NeighborListIP6"])
def test_host_status_does_not_invent_process_or_success(name):
    _, payload = graph(name, RawProcessId="999", TargetProcessId="43", NeighborList="SECRET")
    assert all(node["data"].get("group") != "process" for node in payload["elements"]["nodes"])
    assert "SECRET" not in json.dumps(payload["elements"])
    assert "Auth Action" not in str(payload["elements"])


def test_sensitive_java_and_macro_content_is_raw_only():
    for name in ("JavaFunctionExecuted", "MacroContentInfo"):
        _, payload = graph(name, ContextProcessId="42", ScriptContent="SECRET",
                           Arguments="SECRET", Certificate="SECRET", HttpHeaders="SECRET")
        assert "SECRET" not in json.dumps(payload["elements"])
        assert "SECRET" in str(payload["raw_logs"])
