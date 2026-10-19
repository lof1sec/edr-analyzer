"""Exact-name mappings for the remaining Falcon I/O, sensor and detection records."""

from app.parsers.builder import as_text, string_hash

EVENTS = frozenset("""IPCDetectInfo JavaAgentAttachInfo JavaAgentErrorNotification JavaAgentStatistics JavaAPIVisibilityActorTelemetry JavaFunctionExecuted JavaInjectedThread KernelCallbackTablePatch KernelCallbackTableUpdate KernelModeExecImage KernelModeLoadImage KernelServiceStarted KillProcessError LFODownloadComplete LfoUploadDataComplete LfoUploadDataFailed LfoUploadDataUnneeded LfoUploadStart LightningLatencyInfo LightningUnresponsiveStatus LoadImage LocalIpAddressIP4 LocalIpAddressIP6 LocalIpAddressRemovedIP4 LocalIpAddressRemovedIP6 LocalWindowsUserUpdate LogCollectorDeploymentStatus LogonBehaviorCompositionDetectInfo LowILModuleLoadAttempt LsassHandleFromUnsignedModule MacroContentInfo MacroDetectInfo ManifestDownloadComplete MbrOverwriteRawDetectInfo MemoryAdvise MemoryLocked MemoryMapped MemoryProtectionChanged MemoryProtectionUpdated MemoryScanEnabled MemoryScanErrorEvent ModifyServiceBinary ModuleBlockedEvent ModuleBlockedEventWithPatternId ModuleDetectInfo ModuleDownloadComplete ModuleLoadV3DetectInfo MountedVolume MsiTransactionExecuted NamedMutantHandleClosedTelemetry NamedPipeDetectInfo NamedSemaphoreHandleClosedTelemetry NamespaceChanged NeighborListIP6 NetShareAdd NetShareDelete NetShareSecurityModify NetworkCloseIP4 NetworkCloseIP6 NetworkConnectIP4Blocked NetworkConnectIP6Blocked NetworkContainmentCompleted NetworkIcmpDataIP4 NetworkIcmpDataIP6 NetworkLinkConfigGetLink NetworkListenIP6 NetworkModuleLoadAttempt NetworkOutboundPortScanDetectInfo NetworkReceiveAcceptIP6 NetworkSummary NetworkUncontainmentCompleted""".split())

NETWORK = frozenset("""NetworkCloseIP4 NetworkCloseIP6 NetworkConnectIP4 NetworkConnectIP6 NetworkConnectIP4Blocked NetworkConnectIP6Blocked NetworkListenIP4 NetworkListenIP6 NetworkReceiveAcceptIP4 NetworkReceiveAcceptIP6 NetworkIcmpDataIP4 NetworkIcmpDataIP6""".split())

HOST_ONLY = frozenset("""JavaAgentErrorNotification JavaAgentStatistics LightningLatencyInfo LightningUnresponsiveStatus LogCollectorDeploymentStatus MemoryScanEnabled MemoryScanErrorEvent NetworkContainmentCompleted NetworkUncontainmentCompleted NetworkSummary LocalIpAddressIP4 LocalIpAddressIP6 LocalIpAddressRemovedIP4 LocalIpAddressRemovedIP6 NeighborListIP6 LFODownloadComplete LfoUploadDataComplete LfoUploadDataFailed LfoUploadDataUnneeded LfoUploadStart ManifestDownloadComplete ModuleDownloadComplete""".split())

PRIVATE = ("ScriptContent", "MacroContent", "Arguments", "JavaArguments", "HttpHeader",
           "Header", "Certificate", "Signature", "NeighborList", "Password", "Token",
           "Payload", "Output", "Body", "Raw", "Secret")


def _first(event, *keys):
    return next((as_text(event.get(key)).strip() for key in keys if as_text(event.get(key)).strip()), "")


def parse_falcon_user_block(builder, event, kind, username, hostname):
    """Keep evidence in raw logs, never turn a status or attempt into a success."""
    host = as_text(hostname).strip() or "UnknownHost"
    pid = _first(event, "ContextProcessId", "SourceProcessId")
    if kind in HOST_ONLY or kind == "IoSessionLoggedOn":
        pid = ""
    elif not pid and kind in {"LoadImage", "ModuleBlockedEvent", "ModuleBlockedEventWithPatternId",
                              "ModuleDetectInfo", "ModuleLoadV3DetectInfo", "JavaAgentAttachInfo"}:
        pid = _first(event, "TargetProcessId")
    owner = (builder.get_or_create_process_node(pid, _first(event, "ImageFileName", "ContextBaseFileName"),
                                                username, hostname, kind, event) if pid else None)
    group, relation = "network", "Reports Observation"
    if kind in NETWORK:
        family = "IP6" if kind.endswith("IP6") or kind.endswith("IP6Blocked") else "IP4"
        remote = _first(event, f"RemoteAddress{family}")
        local = _first(event, f"LocalAddress{family}")
        port = _first(event, "RemotePort")
        local_port = _first(event, "LocalPort")
        subject = local if "Listen" in kind else remote or local
        if "Blocked" in kind:
            relation = "Connection Blocked"
        elif "Close" in kind:
            relation = "Connection Closed"
        elif "Listen" in kind:
            relation = "Listens On"
        elif "Accept" in kind:
            relation = "Accepts Connection"
        elif "Icmp" in kind:
            relation = "ICMP Observation"
        else:
            relation = "Connects To"
        details = [f"Family: {family}", f"Local: {local}:{local_port}"]
        if "Listen" not in kind:
            details.append(f"Remote: {remote}:{port}")
        subject = f"{subject}:{local_port if 'Listen' in kind else port}" if subject else kind
    else:
        subject = _first(event, "TargetFileName", "ModuleName", "ImageFileName", "ServiceObjectName",
                         "ShareName", "NamedPipeName", "RemoteAddressIP4", "RemoteAddressIP6",
                         "PatternId", "JavaClassName", "JavaFunctionName", "ComputerName") or kind
        if "DetectInfo" in kind or "Blocked" in kind or kind in {"MacroDetectInfo", "MbrOverwriteRawDetectInfo"}:
            group, relation = "alert", "Reports Detection"
        elif kind.startswith(("Java", "Memory", "Kernel", "Module", "LoadImage", "LowIL")):
            group, relation = "module", "Reports Module or Memory Event"
        elif kind.startswith(("NetShare", "ModifyService", "KernelService", "LocalWindowsUser")):
            group, relation = "registry", "Reports Configuration Change"
        elif kind.startswith("Lfo") or kind.startswith("LFO"):
            group, relation = "file", "LFO Transfer State"
        elif kind == "IoSessionLoggedOn":
            relation = "I/O Session Observation"
        details = []
    # Explicit allowlist: diagnostic buffers, credentials, headers, code, lists,
    # certificates and signatures remain accessible exclusively through raw evidence.
    for key in ("PatternId", "TemplateDisposition", "Status", "Result", "ErrorCode",
                "SHA256HashData", "FileSize", "ModuleSize", "JavaAgentId", "ClassName",
                "FunctionName", "StatisticCount", "Count", "RemotePort", "LocalPort",
                "ServiceObjectName", "ShareName", "AuthenticationId"):
        if not any(word.lower() in key.lower() for word in PRIVATE):
            value = _first(event, key)
            if value:
                details.append(f"{key}: {value[:160]}")
    occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
    node = f"falcon_block_{string_hash((host, kind, subject, occurrence))}"
    builder.add_or_update_artifact_node(node, f"{kind}: {subject[:70]}",
                                        f"[{kind}]\n" + "\n".join(details), group, event)
    if not owner:
        owner = f"host_{string_hash(host)}"
        builder.add_or_update_artifact_node(owner, f"Host: {host}", f"Host: {host}", "network", event)
    builder.add_edge(owner, node, relation, "#b366ff", kind, raw_event=event)
