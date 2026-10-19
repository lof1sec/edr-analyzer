"""Field-aware mappings for Falcon device, protection and diagnostic events."""

from app.parsers.builder import as_text, string_hash

EVENTS = frozenset("""DataProtectionArchiveAssessed DataProtectionBrowserConnect DataProtectionDataEncryption DataProtectionPACDiagnostic DBusMessage DcBluetoothDeviceConnected DcBluetoothDeviceConnectedDetails DcBluetoothDeviceDisconnected DcBluetoothDeviceProperties DcIdentification DcOffline DcOnline DcRemovableStorageConnected DcRemovableStorageDeviceBlocked DcRemovableStorageDeviceConnected DcRemovableStorageDeviceDisconnected DcRemovableStorageDevicePolicyViolation DcRemovableStorageDisconnected DcStatus DCSyncAttempted DcUsbConfigurationDescriptor DcUsbDeviceBlocked DcUsbDeviceConnected DcUsbDeviceDisconnected DcUsbDevicePolicyViolation DcUsbDeviceWhitelisted DcUsbEndpointDescriptor DcUsbHIDDescriptor DcUsbInterfaceDescriptor DeliverLocalFXToCloud DeliverRulesEngineResultsToCloud DetectionExcluded DirectoryTraversalOverSMB DiskCapacity DiskUtilization DllInjection DNSRequestDetectInfo DnsServerSigRedExploitAttemptEtw DocumentProgramInjectedThread DotnetModuleLoadDetectInfo DriverLoadBlocked DriverLoadedV2DetectInfo DriverPreventFailed DriverPreventionStatus DwmCompositionResourceExploitAttempt EarlyExploitPivotDetect ECBDownloadComplete EddScanStart EddScanStatus EndOfProcess EnumeratedAgenticArtifacts EnvironmentVariablesChanged ErrorEvent EtwComponentResponse EtwErrorEvent EventLogCleared ExcelDocumentOpened ExtendedExploitMitigationViolatedDetectInfo FalconHostFileTamperingInfo FalconHostRegTamperingInfo""".split())

DEVICE_EVENTS = frozenset(name for name in EVENTS if name.startswith(("DcUsb", "DcBluetooth", "DcRemovable")))
PROTECTION_EVENTS = frozenset(name for name in EVENTS if name.startswith("DataProtection"))
DETECTION_EVENTS = frozenset(name for name in EVENTS if name.endswith("DetectInfo") or name in {
    "DetectionExcluded", "DnsServerSigRedExploitAttemptEtw", "DwmCompositionResourceExploitAttempt",
    "EarlyExploitPivotDetect", "FalconHostFileTamperingInfo", "FalconHostRegTamperingInfo",
    "DocumentProgramInjectedThread", "DllInjection", "EventLogCleared"})


def _first(event, *keys):
    return next((as_text(event.get(key)).strip() for key in keys if as_text(event.get(key)).strip()), "")


def parse_falcon_next(builder, event, kind, username, hostname):
    host = as_text(hostname).strip()
    pid = _first(event, "ContextProcessId", "SourceProcessId")
    if kind in {"DataProtectionBrowserConnect", "EndOfProcess", "DetectionExcluded"}:
        # TargetProcessId is the Falcon process identifier; RawTargetProcessId is not.
        pid = _first(event, "TargetProcessId")
    owner = builder.get_or_create_process_node(
        pid, _first(event, "ContextBaseFileName"), username, hostname, kind, event) if pid else None
    group, relation = "alert", "Reports"
    fields = ("Status", "Result", "Reason", "ErrorCode")
    subject = ""

    if kind in DEVICE_EVENTS:
        group = "network"
        if "Bluetooth" in kind:
            address = _first(event, "BluetoothDeviceAddress")
            address_type = _first(event, "BluetoothDeviceAddressType")
            subject = f"{address}/{address_type}" if address else ""
            fields = ("BluetoothDeviceAddress", "BluetoothDeviceAddressType", "BluetoothDeviceType",
                      "BluetoothDeviceName")
        else:
            subject = _first(event, "DeviceInstanceId")
            if not subject:
                subject = _first(event, "DeviceDescriptorUniqueIdentifier", "DeviceDescriptorSetHash")
            fields = ("DeviceInstanceId", "DeviceSerialNumber", "DeviceVendorId", "DeviceProductId",
                      "DeviceDescriptorUniqueIdentifier", "DeviceDescriptorSetHash", "DcPolicyId",
                      "DcPolicyAction", "DcPolicyFlags", "DcPolicyMatchMethod")
        relation = ("Reports Policy Violation" if "PolicyViolation" in kind else
                    "Policy Decision" if kind.endswith(("Blocked", "Whitelisted")) else "Device Observation")
        # Decisions and violation reports remain separate from the device identity.
        identity = (("device-report", kind, host, subject,
                     builder.current_event_id if builder.current_event_id is not None else string_hash(event))
                    if relation != "Device Observation" else ("device", host, subject))
        if not subject:
            # No identity means an observation, not a device shared across events.
            identity = (kind, host, builder.current_event_id if builder.current_event_id is not None else string_hash(event))
    elif kind in PROTECTION_EVENTS:
        assessment = _first(event, "AssessmentEventId")
        subject = _first(event, "AssessedFileName", "TargetFileName", "DomainName", "AssessmentEventId", "DataEncryptionEventId")
        fields = ("AssessmentEventId", "DataEncryptionEventId", "AssessedFileName", "TargetFileName",
                  "DataProtectionPolicyRuleAction", "DomainName", "EncryptionType")
        relation = "Protection Assessment" if kind == "DataProtectionArchiveAssessed" else "Protection Observation"
        if kind == "DataProtectionBrowserConnect":
            relation = "Browser Connection Observation"
        identity = ("assessment", host, assessment) if assessment else (kind, host, subject)
    elif kind == "DCSyncAttempted":
        subject = _first(event, "SubjectDomainNameEtw", "ObjectNameEtw")
        fields = ("SubjectDomainNameEtw", "ObjectNameEtw", "RemoteAddressIP4")
        relation = "AD Replication Attempt"
        identity = (kind, host, subject)
    elif kind in DETECTION_EVENTS:
        subject = _first(event, "PatternId", "DetectName", "TargetFileName", "RegObjectName")
        fields = ("PatternId", "DetectName", "DetectSeverity", "TargetFileName",
                  "RegObjectName", "TargetProcessId", "RemoteAddressIP4")
        relation = "Detection Observation"
        identity = (kind, host, subject)
    elif kind in {"DirectoryTraversalOverSMB", "DBusMessage", "DNSRequestDetectInfo"}:
        group = "network"
        subject = _first(event, "RemoteAddressIP4", "DomainName", "TargetFileName", "DBusInterface")
        fields = ("RemoteAddressIP4", "RemotePort", "DomainName", "TargetFileName", "DBusInterface", "DBusMember")
        relation = "Network Observation"
        identity = (kind, host, subject)
    elif kind in {"EnvironmentVariablesChanged", "ExcelDocumentOpened", "EnumeratedAgenticArtifacts"}:
        group = "file" if kind == "ExcelDocumentOpened" else "registry"
        subject = _first(event, "TargetFileName", "FileName", "EnvironmentVariableName", "AgenticSessionId")
        fields = ("TargetFileName", "FileName", "EnvironmentVariableName", "AgenticSessionId")
        relation = "Opens Document" if kind == "ExcelDocumentOpened" else "Process Activity"
        identity = (kind, host, subject)
    elif kind.startswith("Driver") or kind == "DotnetModuleLoadDetectInfo":
        group = "module"
        subject = _first(event, "ImageFileName", "ModuleName", "DriverName", "SHA256HashData")
        fields = ("ImageFileName", "ModuleName", "DriverName", "SHA256HashData", "Status")
        relation = "Driver Prevention" if "Prevent" in kind or "Blocked" in kind else "Module Observation"
        identity = (kind, host, subject)
    else:
        subject = _first(event, "TargetFileName", "ComponentName", "DiskName", "EddScanId")
        fields = ("TargetFileName", "ComponentName", "DiskName", "EddScanId", "Status", "Result")
        relation = "Sensor Status" if kind in {"DcStatus", "DcOnline", "DcOffline", "DcIdentification", "EddScanStatus", "EddScanStart"} else "Telemetry Observation"
        identity = (kind, host, subject)

    if not subject:
        identity = (kind, host, builder.current_event_id if builder.current_event_id is not None else string_hash(event))
    node_id = f"falcon_{string_hash(identity)}"
    details = [f"[{kind}]", f"Host: {host}"]
    details.extend(f"{field}: {as_text(event[field])[:160]}" for field in fields if as_text(event.get(field)))
    builder.add_or_update_artifact_node(node_id, f"{kind}: {(subject or 'observation')[:72]}",
                                        "\n".join(details), group, event)
    if not owner and host:
        owner = f"falcon_{string_hash(('device-host', host))}"
        builder.add_or_update_artifact_node(owner, f"Host: {host}", f"Host: {host}", "network", event)
    if owner and owner != node_id:
        builder.add_edge(owner, node_id, relation, "#b366ff", kind, raw_event=event)
