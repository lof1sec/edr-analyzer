"""Conservative Falcon process-to-I/O observations (never infer causality from status)."""

from urllib.parse import urlsplit

from app.parsers.builder import as_text, string_hash

FILE = frozenset("""FileAccessOperationOverSMB FileContentsChanged FileCreateInfo FileDeleted FileDeleteInfo FileDetectInfo FileIntegrityMonitorRuleMatched FileOfInterestBasicInfo FileOpenInfo FileRenameInfo FileSetMode FileStatFsInfo FileSystemContainmentStatus FileSystemOperationBlocked FileSystemOperationDetectInfo FileTimestampsModified FileWrittenAndExecutedInContainer FileWrittenWithEntropyHigh FreeArcFileWritten FsPostCreate FsPostOpen FsPostOpenSnapshotFile FsPostOpenUpImpersonating FsVolumeMounted FsVolumeReadInfo FsVolumeUnmounted GenericFileWritten GifFileWritten GzipFileWritten IdwFileWritten ImgExtensionFileWritten""".split())
FIREWALL = frozenset("""FirewallChangeOption FirewallDeleteRule FirewallRuleApplicationFailed FirewallRuleIP4Matched FirewallRuleIP6Matched FirewallSetRule""".split())
HTTP = frozenset("""FtpCommand HttpRequest HttpRequestDetect HttpRequestV2Detect HttpResponse HttpVisibilityStatus ImapCommand InboundHttpHeader InboundHttpParsingStatus""".split())
FIRMWARE = frozenset("""FirmwareAnalysisErrorEvent FirmwareAnalysisHardwareData FirmwareAnalysisStatus FirmwareImageAnalyzed FirmwareRegionMeasured""".split())
IDP = frozenset("""IdpCloudHealthCheck IdpCloudHealthConfigurationsGetResponse IdpCloudHealthConfigurationsSetResponse IdpCloudHealthStatus IdpConnectionsOverloadNotification IdpContainerRestarted IdpDcPerfReport IdpDcTiConfiguration IdpIdaasCorrelate IdpPacketDiversionConnectionsOverloadNotification IdpPacketDiversionLdapsConnectionsOverloadNotification IdpPolicyAccessRuleMatch IdpTelemetryData IdpWatchdogAuditReport IdpWatchdogConfigurationsGetResponse IdpWatchdogConfigurationsSetResponse IdpWatchdogControlResponse IdpWatchdogMonitorStatusReport IdpWatchdogReEnabled IdpWatchdogRemediationActionRequest IdpWatchdogRemediationActionTaken IdpWatchdogRemediationActionTakenForCpu IdpWatchdogRemediationActionTakenForMemory IdpWatchdogRemediatorStatusReport IdpWatchdogStatusReport""".split())
SERVICE = frozenset("""FalconServiceStatus HostedServiceStarted HostedServiceStopped InstallBundleDownloadComplete InstallServiceDownloadComplete InstalledApplication InstalledBrowserExtension InstalledUpdates""".split())
PROCESS = frozenset("""FalconProcessHandleOpDetectInfo FlashThreadCreateProcess GetAsyncKeyStateEtwBatch HeapSprayAttempt HookedDriverObject IBEBChannelFileEnforcementResponse ImageHash ImpersonationTokenInfo InjectedThreadFromUnsignedModule""".split())
HOST = frozenset("""HostInfo HostnameChanged HostTimeModified InstanceMetadata InternetExposureData IoSessionConnected""".split())
EVENTS = FILE | FIREWALL | HTTP | FIRMWARE | IDP | SERVICE | PROCESS | HOST


def _first(event, *names):
    return next((as_text(event.get(name)).strip() for name in names if as_text(event.get(name)).strip()), "")


def _artifact(builder, key, label, group, event, kind):
    node = f"falcon_{string_hash(key)}"
    builder.add_or_update_artifact_node(node, label[:100], f"[{kind}]\n{label[:160]}", group, event)
    return node


def parse_falcon_process_to_io(builder, event, kind, username, hostname):
    """Only link a real UPID to an observation; retain sensitive fields in raw evidence."""
    host = as_text(hostname).strip()
    pid = _first(event, "ContextProcessId", "SourceProcessId")
    if kind in {"FalconProcessHandleOpDetectInfo", "InjectedThreadFromUnsignedModule"}:
        pid = _first(event, "ContextProcessId", "SourceProcessId")
    if kind == "HostedServiceStopped":
        pid = ""  # A stopped service's target is not its initiator.
    owner = (builder.get_or_create_process_node(pid, _first(event, "ContextBaseFileName"),
                                                username, hostname, kind, event) if pid else None)
    if kind in FILE:
        group, relation = "file", "File Observation"
        subject = _first(event, "TargetFileName", "ObjectName", "FileName", "SourceFileName")
        fields = ("TargetFileName", "SourceFileName", "ObjectName", "ObjectType",
                  "ObjectAccessOperationType", "FileName", "SHA256HashData", "FileSize")
        if kind.startswith("FsVolume"):
            subject = _first(event, "VolumeSessionUUID", "VolumeMountPoint")
            fields = ("VolumeSessionUUID", "VolumeMountPoint")
        if kind == "FileOpenInfo":
            relation = "Opens File"
        elif kind == "FileRenameInfo":
            relation = "Renames File"
            source = _first(event, "SourceFileName")
            target = _first(event, "TargetFileName")
            if source and target and source != target:
                before = _artifact(builder, ("file", host, source), f"File: {source}", "file", event, kind)
                after = _artifact(builder, ("file", host, target), f"File: {target}", "file", event, kind)
                builder.add_edge(before, after, "Renamed To", "#b366ff", kind, raw_event=event)
                if owner:
                    builder.add_edge(owner, before, "Renames File", "#b366ff", kind, raw_event=event)
        elif kind == "FileIntegrityMonitorRuleMatched":
            relation = "FIM Rule Matched"
        elif "Written" in kind:
            relation = "Writes File"
    elif kind in FIREWALL:
        group, relation = "network", "Firewall Observation"
        subject = _first(event, "FirewallRuleId", "HbfwRuleId", "RemoteAddressIP4", "RemoteAddressIP6")
        fields = ("FirewallRuleId", "HbfwRuleId", "RuleAction", "ConnectionDirection",
                  "RuleMatchCountSinceLastReport", "RemoteAddressIP4", "RemoteAddressIP6")
        if kind.endswith("Matched"):
            relation = "Aggregated Rule Matches"
    elif kind in HTTP:
        group, relation = "network", "Protocol Observation"
        subject = _first(event, "HttpHost", "DomainName", "RemoteAddressIP4", "RemoteAddressIP6")
        fields = ("HttpHost", "DomainName", "HttpMethod", "HttpStatus", "RemoteAddressIP4", "RemotePort")
        if kind == "HttpRequestDetect" and not subject:
            url = _first(event, "HttpUrl")
            try:
                subject = urlsplit(url).hostname or ""
            except ValueError:
                subject = ""
            # URL-derived hosts may contain userinfo-like data: never display the raw URL.
            subject = subject if subject and "@" not in subject else ""
    elif kind in FIRMWARE:
        group, relation = "alert", "Firmware Observation"
        subject = _first(event, "SHA256HashData", "BiosId", "ImageAnalysisRequestTimestamp")
        fields = ("SHA256HashData", "BiosId", "ImageAnalysisRequestTimestamp", "ErrorCode")
    elif kind in IDP:
        group, relation = "alert", "Identity Protection Observation"
        subject = _first(event, "IdpPolicyRuleId", "IdpWatchdogRemediationId", "IdpCloudConnectivityState")
        fields = ("IdpPolicyRuleId", "IdpPolicyRuleAction", "IdpPolicyRuleActionStatus",
                  "SimulationMode", "IdpWatchdogRemediationId", "IdpCloudConnectivityState")
        if kind == "IdpPolicyAccessRuleMatch":
            mode = _first(event, "SimulationMode").lower()
            relation = ("Simulated Policy Match" if mode in {"true", "1", "simulation", "simulate", "audit"}
                        else "Policy Match Observation")
    elif kind in SERVICE:
        group, relation = "registry", "Service Observation"
        subject = _first(event, "FalconServiceComponent", "ServiceDisplayName", "AppProductId",
                         "BrowserExtensionId")
        fields = ("FalconServiceComponent", "State", "SubState", "ServiceDisplayName",
                  "AppProductId", "AppName", "BrowserExtensionId", "BrowserName", "UserSid")
        if kind in {"HostedServiceStarted", "HostedServiceStopped"}:
            relation = "Service Started" if kind.endswith("Started") else "Service Stopped Observation"
            service_pid = _first(event, "TargetProcessId")
            if service_pid:
                owner = builder.get_or_create_process_node(service_pid, None, username, hostname, kind, event)
    elif kind in PROCESS:
        group, relation = "alert", "Process Observation"
        subject = _first(event, "TargetProcessId", "PatternId", "SHA256HashData")
        fields = ("TargetProcessId", "PatternId", "SHA256HashData", "ImageFileName",
                  "HandleOperation", "Status")
        if kind in {"FalconProcessHandleOpDetectInfo", "InjectedThreadFromUnsignedModule"}:
            target = _first(event, "TargetProcessId")
            if target:
                target_node = builder.get_or_create_process_node(target, None, username, hostname, kind, event)
                if owner and target_node and owner != target_node:
                    action = (_first(event, "HandleOperation") or "Handle Operation") if kind.startswith("Falcon") else "Injected Thread"
                    builder.add_edge(owner, target_node, action[:80], "#b366ff", kind, raw_event=event)
        if kind == "ImageHash":
            target = _first(event, "TargetProcessId")
            if target:
                owner = builder.get_or_create_process_node(target, None, username, hostname, kind, event)
            image = _first(event, "ImageFileName")
            digest = _first(event, "SHA256HashData")
            if image or digest:
                module = _artifact(builder, ("image", host, image, digest),
                                   f"Image: {image or digest}", "module", event, kind)
                if owner:
                    builder.add_edge(owner, module, "Image Hash", "#b366ff", kind, raw_event=event)
    else:
        group, relation = "network", "Host Observation"
        subject = _first(event, "ComputerName", "InstanceId")
        fields = ("ComputerName", "InstanceId", "Status", "Result")

    occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
    # Status and decision events represent occurrences, not durable entities.
    identity = (kind, host, subject, occurrence)
    node_id = f"falcon_{string_hash(identity)}"
    details = [f"[{kind}]", f"Host: {host}"]
    details.extend(f"{field}: {as_text(event[field])[:160]}" for field in fields if as_text(event.get(field)))
    builder.add_or_update_artifact_node(node_id, f"{kind}: {(subject or 'observation')[:72]}",
                                        "\n".join(details), group, event)
    if not owner and host:
        owner = f"falcon_{string_hash(('io-host', host))}"
        builder.add_or_update_artifact_node(owner, f"Host: {host}", f"Host: {host}", "network", event)
    if owner and owner != node_id:
        builder.add_edge(owner, node_id, relation, "#b366ff", kind, raw_event=event)
