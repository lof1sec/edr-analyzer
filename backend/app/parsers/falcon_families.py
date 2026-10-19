"""Field-aware mappings for Falcon identity, cloud, file and sensor telemetry."""

from app.parsers.builder import as_text, string_hash

AD_EVENTS = frozenset("""ActiveDirectoryAccountCreated ActiveDirectoryAccountDepartmentUpdate ActiveDirectoryAccountDirectContainingGroupEntitiesUpdate ActiveDirectoryAccountDisabled ActiveDirectoryAccountEnabled ActiveDirectoryAccountFlattenedContainingGroupEntitiesUpdate ActiveDirectoryAccountLocked ActiveDirectoryAccountNameUpdate ActiveDirectoryAccountOuUpdate ActiveDirectoryAccountPasswordUpdate ActiveDirectoryAccountUnlocked ActiveDirectoryAuditGpoModified ActiveDirectoryAuditGroupMemberModified ActiveDirectoryAuditGroupModified ActiveDirectoryAuditPasswordModificationAttempt ActiveDirectoryAuditUserModified ActiveDirectoryAuthentication ActiveDirectoryAuthenticationFailure ActiveDirectoryIncomingAdwsLdapSearchRequest ActiveDirectoryIncomingDceRpcEpmRequest ActiveDirectoryIncomingDceRpcRequest ActiveDirectoryIncomingLdapSearchRequest ActiveDirectoryIncomingPsExecExecution2 ActiveDirectoryInteractiveDomainLogon ActiveDirectoryServiceAccessRequest ActiveDirectoryServiceAccessRequestFailure ActiveDirectPrivilegeEscalation""".split())
CLOUD_EVENTS = frozenset("""AwsEc2Image AwsEc2Instance AwsEc2NetworkAcl AwsEc2NetworkAclEntry AwsEc2NetworkInterface AwsEc2NetworkInterfacePrivateIP AwsEc2SecurityGroup AwsEc2SecurityGroupRule AwsEc2Subnet AwsEc2Volume AwsEc2Vpc AwsIamAccountAlias""".split())
FILE_EVENTS = frozenset("""ADExplorerFileWritten AgenticFileCreateInfo AgenticFileDeleteInfo AgenticFileOpen AgenticFileRenameInfo AgenticGenericFileWritten AppleScriptFileWritten ArcFileWritten ArchiveFileContent ArjFileWritten Base64PeFileWritten BcmFileWritten BmpFileWritten BlakHoleFileWritten BlfFileWritten BrotliFileWritten BZip2FileWritten CabFileWritten""".split())
AGENT_EVENTS = frozenset("""AgenticSessionEnd AgenticSessionStart AgenticSessionUpdate AgenticSubagentStart AgenticToolRequest AgenticToolResponse AgenticUserPromptSubmit AiAgentClassifyChildTelemetry AiAgentClassifyRootTelemetry""".split())
SENSOR_EVENTS = frozenset("""AbnormalTerminationNotification AcUninstallConfirmation AcUnloadConfirmation AdditionalHostInfo AgentConnect AgentOnline AllocVmEtw AmsBytePatternScanResult AmsBytePatternScanTelemetry AmsiRegistrationStatus AsepKeyUpdate AsepValueUpdate ASLRBypassAttempt AspmCollectionStatusUpdate AssociateIndicator AssociateTreeIdWithRoot AuditCveKmEtw AuditCveUmEtw BehaviorWhitelisted BillingInfo BITSJobCreated BlockThreadFailed BMLFeatureData BootLoopProtectionTelemetry BPFCommandIssued BrowserInjectedThread ChannelActive ChannelDataDownloadComplete ChannelVersionRequired CidMigrationComplete CidMigrationConfirmation CidMigrationError CidMigrationManifestDownloadComplete""".split())
FAMILY_EVENTS = AD_EVENTS | CLOUD_EVENTS | FILE_EVENTS | AGENT_EVENTS | SENSOR_EVENTS


def _first(event, *keys):
    return next((as_text(event[key]) for key in keys if as_text(event.get(key))), "")


def _node(builder, namespace, scope, identity, label, group, event, kind):
    if not identity:
        return None
    node_id = f"falcon_{string_hash((namespace, scope, identity))}"
    builder.add_or_update_artifact_node(node_id, label[:100], f"[{kind}]\n{namespace}: {identity[:240]}", group, event)
    return node_id


def _link(builder, source, target, label, kind, event):
    if source and target and source != target:
        builder.add_edge(source, target, label, "#b366ff", kind, raw_event=event)


def parse_falcon_family(builder, event, kind, username, hostname):
    """Represent an observation without inventing a process when no PID exists."""
    host = as_text(hostname).strip()
    tenant = _first(event, "AwsAccountId", "CustomerId", "cid")
    domain = _first(event, "AccountDomain", "DomainName", "DomainDnsName", "DomainGuid")
    scope = (tenant, domain, host)
    pid = _first(event, "ContextProcessId", "SourceProcessId", "RpcClientProcessId")
    owner = (builder.get_or_create_process_node(
        pid, _first(event, "ContextBaseFileName", "ImageFileName"),
        username, hostname, kind, event) if pid else None)
    if not owner and host:
        owner = _node(builder, "host", (tenant, domain), host, f"Host: {host}", "network", event, kind)

    if kind in AD_EVENTS:
        # SID and GUID are stable within the directory; do not promote names to identities.
        actor = _first(event, "PerformedByAccountObjectSid", "PerformedByAccountObjectGuid",
                       "SourceAccountObjectSid", "SourceAccountObjectGuid")
        target = _first(event, "PerformedOnAccountObjectSid", "PerformedOnAccountObjectGuid",
                        "AccountObjectSid", "AccountObjectGuid", "GroupMemberAccountObjectSid",
                        "GroupMemberAccountObjectGuid")
        ad_scope = (tenant, domain)
        actor_id = _node(builder, "ad-account", ad_scope, actor, f"AD actor: {actor}", "registry", event, kind)
        target_id = _node(builder, "ad-account", ad_scope, target, f"AD account: {target}", "registry", event, kind)
        auth = "Authentication" in kind or "Logon" in kind or "ServiceAccess" in kind
        if auth:
            _link(builder, actor_id or target_id, owner, kind, kind, event)
        else:
            _link(builder, actor_id, target_id, kind, kind, event)
            _link(builder, owner, actor_id or target_id, "Observed On", kind, event)
        subject, group, relationship = target or actor, "registry", "AD Observation"
        fields = ("AccountObjectSid", "AccountObjectGuid", "SourceAccountObjectSid",
                  "SourceAccountObjectGuid", "PerformedByAccountObjectSid", "PerformedByAccountObjectGuid",
                  "PerformedOnAccountObjectSid", "PerformedOnAccountObjectGuid",
                  "GroupMemberAccountObjectSid", "GroupMemberAccountObjectGuid", "DomainName", "Status")
    elif kind in CLOUD_EVENTS:
        aws_scope = (_first(event, "AwsAccountId"), _first(event, "AwsRegion"))
        resource_fields = {"AwsEc2Instance": "AwsInstanceId", "AwsEc2Vpc": "AwsVpcId",
                           "AwsEc2SecurityGroup": "AwsGroupId", "AwsEc2SecurityGroupRule": "AwsGroupId"}
        identity = _first(event, resource_fields[kind]) if kind in resource_fields else ""
        subject = identity
        resource = _node(builder, kind, aws_scope, identity, f"AWS {kind}: {identity}", "network", event, kind)
        vpc = _node(builder, "AwsEc2Vpc", aws_scope, _first(event, "AwsVpcId"),
                    f"AWS VPC: {_first(event, 'AwsVpcId')}", "network", event, kind)
        if kind == "AwsEc2Instance":
            _link(builder, resource, vpc, "In VPC", kind, event)
        elif kind == "AwsEc2SecurityGroup":
            _link(builder, resource, vpc, "In VPC", kind, event)
        _link(builder, owner, resource, "Observed On", kind, event)
        group, relationship = "network", "Cloud Observation"
        fields = ("AwsInstanceId", "AwsVpcId", "AwsGroupId", "AwsRegion", "AwsAccountId")
    elif kind in FILE_EVENTS:
        path = _first(event, "TargetFileName", "FilePath", "FileName", "ObjectName", "SourceFileName")
        subject = path
        filename = subject.replace("\\", "/").split("/")[-1]
        group, label, key, relationship = "file", f"File: {filename[:100]}", (host, subject, kind), "File Activity"
        fields = ("TargetFileName", "SourceFileName", "FilePath", "FileName", "SHA256HashData", "FileSize")
    elif kind in AGENT_EVENTS:
        session = _first(event, "AgenticSessionId")
        tool = _first(event, "AgenticToolUseId")
        product = _first(event, "AgenticProduct")
        subject = tool or session
        session_id = _node(builder, "agent-session", (tenant, host, product), session,
                           f"Agent session: {session}", "commandline", event, kind)
        tool_id = _node(builder, "agent-tool", (tenant, host, product, session), tool,
                        f"Agent tool: {tool}", "commandline", event, kind)
        _link(builder, session_id, tool_id, "Uses Tool", kind, event)
        _link(builder, owner, session_id or tool_id, "Observed On", kind, event)
        group, relationship = "commandline", "Agent Activity"
        fields = ("AgenticSessionId", "AgenticToolUseId", "AgenticProduct")
    else:
        subject = _first(event, "RegistryPath", "RegObjectName", "JobId", "ChannelId",
                         "IndicatorId", "TreeId", "PatternId", "TargetProcessId")
        group = "registry" if kind.startswith("Asep") else "alert"
        relationship = "Sensor Activity"
        fields = ("RegistryPath", "RegObjectName", "JobId", "ChannelId", "IndicatorId",
                  "TreeId", "PatternId", "TargetProcessId", "Status", "Result")

    # Without a real identity, use the stored row id rather than merging all
    # observations of one kind. Direct parser callers have no row id: use a
    # deterministic digest of the complete record in that case.
    occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
    key = (kind, scope, subject) if subject else (kind, scope, "event", occurrence)
    label = f"{kind}: {(subject or 'observation')[:80]}"
    details = [f"[{kind}]", f"Host: {host}"]
    details.extend(f"{field}: {as_text(event[field])[:240]}" for field in fields
                   if as_text(event.get(field)))
    node_id = f"falcon_{string_hash(key)}"
    builder.add_or_update_artifact_node(node_id, label, "\n".join(details), group, event)
    # An observation can be standalone if neither a process nor a host is known.
    _link(builder, owner, node_id, relationship, kind, event)
