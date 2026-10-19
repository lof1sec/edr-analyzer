"""Conservative mappings for Falcon process, sensor and container observations."""

from app.parsers.builder import as_text, string_hash

EVENTS = frozenset("""NonExecDetectInfo NtfsLinkCreatedDetectInfo NtfsQueryEaExploitAttempt NullPageProtectionModificationAttempt NullPageUnmapAttempt ObservedAgenticArtifacts OciContainerComplianceInfo OciContainerEngineInfo OciContainerHeartbeat OciContainerInfo OciContainerPlumbingSummary OciContainerStarted OciContainerStopped OciContainerTelemetry OciImageHeartbeat OciImageInfo OdsActionStatus OdsCancelRequestReceived OdsMaliciousFileFound OdsProfileReceived OdsScheduleCanceled OdsScheduleCancelRequestReceived OdsScheduleRequestReceived OdsStarted OdsStartRequestReceived OdsStatus OsfmDownloadComplete OsVersionInfo PackageManagerDownloadComplete PacketDiversionConnectionsOverloadConfigurationResponse PacketFilterAttached PatternHandlingError PeFileWrittenDetectInfo PeHeaderInfo PeVersionInfo PhpBase64Decode PhpEvalString PhpExecuteScript PodInfo PodProductConfig Pop3Command PrimaryTokenInfo PrivilegedProcessHandle PrivilegedProcessHandleFromUnsignedModule ProcessActivitySummary ProcessBlocked ProcessControl ProcessEnvironmentEmpty ProcessExecOnPackedExecutable ProcessExecOnRDPFile ProcessExecOnSMBFile ProcessExecOnWinRMFile ProcessHandleOpDetectInfo ProcessHandleOpDowngraded ProcessPatternTelemetry ProcessRollup ProcessRollup2Stats ProcessRollup2StatsLRU ProcessSelfDeleted ProcessSessionCreated ProcessSignal ProcessTokenPrivilegesEdited ProcessTokenStolen ProcessTrace ProcessTreeCompositionPatternTelemetry PromiscuousBindIP4 PromiscuousBindIP6 ProtectVmEtw ProvisioningChannelVersionRequired ProvisioningEnded ProvisioningStarted ProvisioningStatusUpdate ProxyConnectionInfo PtActivationStatus PtTelemetry PtyAttached PtyDetached QuarantineActionResult QuarantinedFile QuarantinedFileState QueueApcEtw RansomwareCreateFile RansomwareFileAccessPattern RansomwareOpenFile RansomwareRenameFile RawBindIP4""".split())

FILE_EVENTS = frozenset("""NtfsLinkCreatedDetectInfo OsfmDownloadComplete PackageManagerDownloadComplete PeFileWrittenDetectInfo PeHeaderInfo PeVersionInfo ProcessExecOnPackedExecutable ProcessExecOnRDPFile ProcessExecOnSMBFile ProcessExecOnWinRMFile ProcessSelfDeleted QuarantinedFile QuarantinedFileState RansomwareCreateFile RansomwareFileAccessPattern RansomwareOpenFile RansomwareRenameFile""".split())
CONTAINER_EVENTS = frozenset(name for name in EVENTS if name.startswith(("Oci", "Pod")))
NETWORK_EVENTS = frozenset("""PacketDiversionConnectionsOverloadConfigurationResponse PacketFilterAttached PromiscuousBindIP4 PromiscuousBindIP6 ProxyConnectionInfo RawBindIP4 Pop3Command""".split())
PROCESS_ONLY = frozenset("""ProcessActivitySummary ProcessBlocked ProcessControl ProcessEnvironmentEmpty ProcessRollup ProcessSelfDeleted ProcessSessionCreated ProcessSignal ProcessTrace ProcessRollup2Stats ProcessRollup2StatsLRU""".split())


def _first(event, *keys):
    return next((as_text(event[key]) for key in keys if as_text(event.get(key))), "")


def parse_falcon_current(builder, event, kind, username, hostname):
    """Map observed entities only; never infer execution, traffic or remediation."""
    host = as_text(hostname).strip()
    pid = _first(event, "ContextProcessId", "SourceProcessId", "TargetProcessId")
    # Aggregated rollup statistics describe a sensor, not an individual process.
    if kind in {"ProcessRollup2Stats", "ProcessRollup2StatsLRU"}:
        pid = ""
    owner = builder.get_or_create_process_node(
        pid, _first(event, "ContextBaseFileName", "ImageFileName"),
        username, hostname, kind, event) if pid else None
    identity = ""
    group = "alert"
    if kind in FILE_EVENTS:
        identity = _first(event, "TargetFileName", "FilePath", "FileName", "SourceFileName")
        group = "file"
    elif kind in CONTAINER_EVENTS:
        identity = _first(event, "ContainerId", "ContainerID", "PodId", "PodUid", "ImageId", "ImageID")
        group = "network"
    elif kind in NETWORK_EVENTS:
        identity = _first(event, "LocalAddressIP4", "LocalAddressIP6", "ProxyHost")
        group = "network"
    elif kind.startswith("Ods"):
        identity = _first(event, "ScanId", "RequestId", "ProfileId", "ScheduleId")
    elif kind not in PROCESS_ONLY:
        identity = _first(event, "PatternId", "DetectionId", "SessionId")

    # An observation without a stable subject gets its own occurrence; no unrelated
    # rows should merge into a generic host/status node.
    occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
    scope = (host, _first(event, "CustomerId", "cid"))
    node_id = f"falcon_{string_hash((kind, scope, identity or ('event', occurrence)))}"
    if kind in FILE_EVENTS and identity:
        label = identity.replace("\\", "/").rstrip("/").split("/")[-1][:100]
    else:
        label = f"{kind}: {identity[:80] if identity else 'observation'}"
    # Sensitive payloads (scripts, credentials, PE blobs, pod specs, token and
    # proxy details) remain exclusively in the server-side raw evidence.
    builder.add_or_update_artifact_node(node_id, label, f"[{kind}]\nObservation", group, event)
    if owner:
        builder.add_edge(owner, node_id, "Observed", "#a6a6a6", kind, raw_event=event)
