"""Conservative mappings for the exact Falcon S-V telemetry block."""

from app.parsers.builder import as_text, string_hash

EVENTS = frozenset("""SignInfoWithCertAndContext SignInfoWithContext SldFileWritten SmbClientNamedPipeConnectEtw SmbClientShareClosedEtw SmbClientShareLogonBruteForceLowThreshold SmbClientShareLogonBruteForceSuspected SmbClientShareOpenedEtw SmbServerLocalNamedPipeOpenedEtw SmbServerShareOpenedEtw SmbServerV1AuditEtw SmtpAttachment SmtpCommand SmtpEmailMessage SnapshotVolumeMounted SourceCodeFileWritten SpotlightEntityBatch SpotlightEntityBatchHeader SpotlightEntitySystemState SSHClientAuthenticated SSHTunnelCreated StaticAnalysisContainerTelemetry StaticConfigurationError SuspectCreateProcessStack SuspectCreateThreadStack SuspendProcessError SuspiciousCreateSymbolicLink SuspiciousCredentialModuleLoad SuspiciousDnsRequest SuspiciousEseFileWritten SuspiciousLackOfProcessRollupEvents SuspiciousPeFileWritten SuspiciousPrivilegedProcessHandle SuspiciousRawDiskRead SuspiciousRawDiskReadFromUnsignedModule SuspiciousRegAsepUpdate SuspiciousUserFontLoad SuspiciousUserRemoteAPCAttempt SyntheticProcessRollup2 SyntheticProcessTrace SyntheticSharedObjectLoaded SyntheticSystemdServiceCreated SyntheticSystemdTimerCreated SyntheticVirtualMemoryArea SysConfigInfo SystemCapacity SystemdServiceCreated SystemdServiceDeleted SystemdServicePropertiesChanged SystemdTimerCreated SystemdTimerDeleted SystemdTimerPropertiesChanged SystemTokenStolen TarFileWritten TcgPcrInfo TelemetryCounters TelemetryCounters2 TelemetryNetworkConnections TelemetryStats TerminateProcess TerminateRemoteProcessEtw ThreadBlocked ThreadPreviousModeMismatch TiffFileWritten TlsClientHello TokenImpersonated TriggeredMemoryDumpResponse UACAxisElevation UACCOMElevation UACCredentialCaptureElevation UACExeElevation UACMSIElevation UmppaErrorEvent UmppcDetectInfo UmppcEntryAnomaly UnclassifiedRegValueUpdate UnixName UnsignedModuleLoad UpdateManifestDownloadComplete UserAccountAddedToGroup UserAccountCreated UserAccountDeleted UserAccountRemovedFromGroup UserEatAccessMonitoring UserExceptionDEP UserFontLoad UserGroupCreated UserGroupDeleted UserIdentity UserInformationEtw UserLogoff UserLogon UserLogonFailed UserLogonFailed2 UserSetProcessBreakOnTermination VdiFileWritten VirtualMemoryArea VmdkFileWritten VolumeSnapshotCreated VolumeSnapshotDeleted""".split())

FILE_EVENTS = frozenset(name for name in EVENTS if name.endswith("FileWritten")) | {"SuspiciousCreateSymbolicLink", "SuspiciousEseFileWritten", "SuspiciousPeFileWritten"}
IDENTITY_EVENTS = frozenset(name for name in EVENTS if name.startswith(("User", "SpotlightEntity")) or name in {"SignInfoWithCertAndContext", "SignInfoWithContext"})
NETWORK_EVENTS = frozenset(name for name in EVENTS if name.startswith(("Smb", "Smtp", "SSH", "Tls")) or name in {"SuspiciousDnsRequest", "TelemetryNetworkConnections"})
REGISTRY_EVENTS = frozenset({"SuspiciousRegAsepUpdate", "UnclassifiedRegValueUpdate"})
SENSITIVE_EVENTS = frozenset(name for name in EVENTS if name.startswith(("Smtp", "SpotlightEntity", "SignInfoWith")))


def _first(event, *keys):
    return next((as_text(event.get(key)) for key in keys if as_text(event.get(key))), "")


def parse_falcon_current_block(builder, event, kind, username, hostname):
    """Represent recorded observations, without inferred causal or success edges."""
    host = as_text(hostname).strip()
    pid = "" if kind in IDENTITY_EVENTS or kind.startswith(("Synthetic", "Telemetry")) else _first(
        event, "ContextProcessId", "SourceProcessId")
    owner = builder.get_or_create_process_node(
        pid, _first(event, "ContextBaseFileName", "ImageFileName"),
        username, hostname, kind, event) if pid else None

    if kind in FILE_EVENTS:
        identity = _first(event, "TargetFileName", "FilePath", "FileName")
        group = "file"
    elif kind in REGISTRY_EVENTS:
        identity = _first(event, "RegObjectName")
        group = "registry"
    elif kind in NETWORK_EVENTS and kind not in SENSITIVE_EVENTS:
        identity = _first(event, "RemoteAddressIP4", "RemoteAddressIP6", "DomainName")
        group = "network"
    else:
        identity = ""
        group = "alert"
    # Each row is its own observation: shared names do not prove causality or
    # identity. Avoid shipping mail, cert, signature and entity payload fields.
    occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
    node_id = f"falcon_block_{string_hash((kind, host, occurrence))}"
    label = (identity.replace("\\", "/").split("/")[-1][:80]
             if identity and kind in FILE_EVENTS else kind)
    builder.add_or_update_artifact_node(
        node_id, label, f"[{kind}]\nObservation; see raw evidence", group, event)
    if owner:
        builder.add_edge(owner, node_id, "Observed", "#a6a6a6", kind, raw_event=event)
