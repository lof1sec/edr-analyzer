"""Exact Falcon R-S event mappings with conservative actor and outcome semantics."""

from app.parsers.builder import as_text, string_hash

EVENTS = frozenset("""RawBindIP6 RecentlyModifiedFileExecutedInContainer RecoveryActionDeleteFilesComplete RecoveryActionDeleteFilesReply RecoveryActionGetModuleTableRecordComplete RecoveryActionGetRuntimeSystemTagsComplete RecoveryActionGetSystemTagsComplete RecoveryActionKillProcessesComplete RecoveryActionKillProcessesReply RecoveryActionManipulateModuleTableComplete RecoveryActionRegistryCreateKeyComplete RecoveryActionRegistryCreateKeyReply RecoveryActionRegistryDeleteKeyComplete RecoveryActionRegistryDeleteKeyReply RecoveryActionRegistryDeleteValueKeyComplete RecoveryActionRegistryDeleteValueKeyReply RecoveryActionRegistrySetValueKeyComplete RecoveryActionRegistrySetValueKeyReply RecoveryActionSetRuntimeSystemTagsComplete RecoveryActionSetSystemTagsComplete ReflectiveDllLoaded ReflectiveDllOpenProcess RegCredAccessDetectInfo RegCrowdstrikeKeyUpdate RegCrowdstrikeValueUpdate RegGenericKeyUpdate RegGenericValueUpdate RegisterRawInputDevicesEtw RegistryOperationBlocked RegistryOperationDetectInfo RegKeySecurityDecreasedFromUnsignedModule RegNtPostOpenKeyEx RegNtPostOpenKeyExUpImpersonating RegSystemConfigKeyUpdate RegValueQueryDetectInfo RemediationActionKillProcess RemediationActionQuarantineFile RemediationActionQuarantineMacroFile RemediationActionQuarantineOfficeMacroFile RemediationActionRegistryRemoval RemediationActionScheduledTaskRemoval RemediationActionServiceRemoval RemediationMonitorKillProcess RemediationMonitorQuarantineFile RemediationMonitorRegistryRemoval RemediationMonitorScheduledTaskRemoval RemediationMonitorServiceRemoval RemoteBruteForceDetectInfo RemoteProcessMemoryRead RemoteProcessMemoryWrite RemovableDiskModuleLoadAttempt RemovableMediaVolumeMounted ResourceLimit ResourceUtilization RootkitDetectionResponse SAMHashDumpFromUnsignedModule ScheduledTaskDeleted ScheduledTaskRegistered ScheduledTaskTamperingRegistryOperation ScheduledTaskTemplateDetectInfo ScreenshotTakenEtw ScriptControlBlocked ScriptControlDetectInvalidInfo ScriptControlDotNetMetadata ScriptControlErrorEvent ScriptControlScanTelemetry ScriptFileContentsDetectInfo SEHOverWriteAttempt SensorAntiTamperState SensorEnteredSafemode SensorGroupingTagsUpdate SensorHeartbeat SensorMetadataUpdate SensorSelfDiagnosticAlert SensorSelfDiagnosticTelemetry SensorSettingsUpdate SensorTampering ServicesStatusInfo ServiceStarted ServiceStopped SessionPatternTelemetry SetThreadCtxEtw SetWindowsHook SetWindowsHookExEtw SetWinEventHookEtw SharedObjectLoaded ShellCommandLineInfo SignInfo""".split())

REGISTRY = frozenset(name for name in EVENTS if name.startswith(("Reg", "RecoveryActionRegistry", "RemediationActionRegistry", "RemediationMonitorRegistry", "ScheduledTaskTamperingRegistry")))
FILE = frozenset(name for name in EVENTS if "Quarantine" in name or name in {"RecentlyModifiedFileExecutedInContainer", "RemovableDiskModuleLoadAttempt", "ScriptFileContentsDetectInfo"})
MODULE = frozenset({"ReflectiveDllLoaded", "RemovableDiskModuleLoadAttempt", "SharedObjectLoaded", "SignInfo", "ScriptControlDotNetMetadata"})
NETWORK = frozenset({"RawBindIP6", "RemovableMediaVolumeMounted", "RemoteBruteForceDetectInfo"})
HOST_ONLY = frozenset(name for name in EVENTS if name.startswith(("RecoveryAction", "RemediationMonitor", "Sensor", "Resource", "ServicesStatus"))) | {"RootkitDetectionResponse", "ServiceStopped", "SignInfo"}
SENSITIVE = frozenset({"ShellCommandLineInfo", "ScriptFileContentsDetectInfo", "RegCredAccessDetectInfo", "SignInfo"})


def _first(event, *fields):
    return next((as_text(event.get(field)) for field in fields if as_text(event.get(field))), "")


def parse_falcon_rs(builder, event, kind, username, hostname):
    """Only connect explicitly identified processes; never turn raw OS PIDs into UPIDs."""
    host = as_text(hostname) or "UnknownHost"
    pid = _first(event, "ContextProcessId", "SourceProcessId")
    if kind == "RecentlyModifiedFileExecutedInContainer":
        pid = _first(event, "TargetProcessId")
    elif kind in HOST_ONLY or kind.startswith("RemediationAction"):
        pid = ""
    owner = builder.get_or_create_process_node(
        pid, _first(event, "ImageFileName", "ContextBaseFileName"),
        username, hostname, kind, event) if pid else None
    if not owner:
        owner = f"host_{host}"
        builder.add_or_update_artifact_node(owner, f"Host:\n{host}",
                                            "Central Context Node", "network", event)

    if kind == "RawBindIP6":
        identity = _first(event, "LocalAddressIP6", "LocalPort")
        label = f"Local IPv6 bind: {identity[:80]}" if identity else kind
        group, relation = "network", "Binds Local Address"
    elif kind in REGISTRY:
        identity = _first(event, "RegObjectName")
        label = f"Registry: {identity.replace(chr(92), '/')[-80:]}" if identity else kind
        group, relation = "registry", "Registry Observation"
    elif kind in FILE:
        identity = _first(event, "TargetFileName", "FilePath", "FileName")
        label = identity.replace("\\", "/").split("/")[-1][:80] if identity else kind
        group, relation = "file", "File Observation"
    elif kind in MODULE:
        identity = _first(event, "ModuleName", "ModulePath", "ImageFileName")
        label = identity.replace("\\", "/").split("/")[-1][:80] if identity else kind
        group, relation = "module", "Module Observation"
    elif kind == "ShellCommandLineInfo":
        command = event.get("ReconstructedCommandLine")
        identity = command if isinstance(command, str) else ""
        label = identity[:160] if identity else kind
        group, relation = "shell-command", "Observed"
    else:
        identity = _first(event, "TaskName", "ServiceName", "DetectionId", "CommandSequenceNumber")
        label = kind if kind in SENSITIVE else f"{kind}: {identity[:80]}" if identity else kind
        group, relation = ("network" if kind in NETWORK else "alert"), "Observed"

    if kind.startswith("RemediationMonitor"):
        relation = "Remediation Monitor (hypothetical)"
    elif kind.startswith("RemediationAction"):
        relation = "Remediation Action Attempt"
    elif kind.startswith("RecoveryAction"):
        relation = "Recovery Reply" if kind.endswith("Reply") else "Recovery Completion Report"
    elif kind == "RecentlyModifiedFileExecutedInContainer":
        relation = "Recently Modified File Executed"
    elif kind == "ServiceStopped":
        relation = "Service Stop Observed"

    occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
    # Recovery counts and replies do not identify individual affected objects.
    if kind.startswith("RecoveryAction") or kind.startswith("Remediation") or not identity:
        identity = ("event", occurrence)
    node_id = f"falcon_rs_{string_hash((kind, host, identity))}"
    builder.add_or_update_artifact_node(node_id, label, f"[{kind}]\n{relation}; see raw evidence", group, event)
    builder.add_edge(owner, node_id, relation, "#a6a6a6", kind, raw_event=event)
