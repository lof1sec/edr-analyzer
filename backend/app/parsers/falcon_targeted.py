"""Conservative Falcon classification, detection and sensor observations."""

from app.parsers.builder import as_text, string_hash

TARGETED_EVENTS = frozenset("""ClassifiedProcessStart ClassifiedSensitiveFileAccess CLIUnderListen CloudAssociateTreeIdWithRoot ConfigDownloadComplete ConfigStateUpdate ConfigurationProvisioningState CrashNotification CreateThreadKernelNoStartImage CreateThreadNoStartImage CreateThreadReflectiveDll CriticalFileModified CSAResultsGenericDetectInfo CsKmCrashSummaryEvent CsUmProcessCrashAuxiliaryEvent CsUmProcessCrashSummaryEvent CurrentSystemTags CustomIOABasicProcessDetectionInfoEvent CustomIOADomainNameDetectionInfoEvent CustomIOAFileWrittenDetectionInfoEvent CustomIOANetworkConnectionDetectionInfoEvent DataEgress""".split())
THREAD_EVENTS = frozenset(("CreateThreadKernelNoStartImage", "CreateThreadNoStartImage", "CreateThreadReflectiveDll"))
CUSTOM_EVENTS = frozenset(("CustomIOABasicProcessDetectionInfoEvent", "CustomIOADomainNameDetectionInfoEvent", "CustomIOAFileWrittenDetectionInfoEvent", "CustomIOANetworkConnectionDetectionInfoEvent"))
HOST_EVENTS = frozenset(("ConfigDownloadComplete", "ConfigStateUpdate", "ConfigurationProvisioningState", "CrashNotification", "CsKmCrashSummaryEvent", "CsUmProcessCrashAuxiliaryEvent", "CsUmProcessCrashSummaryEvent", "CurrentSystemTags"))


def _field(event, key):
    return as_text(event.get(key)).strip()


def parse_targeted_falcon_event(builder, event, kind, username, hostname):
    """Only explicit process roles produce processes; sensitive content stays in evidence."""
    host = as_text(hostname).strip()

    def process(key, name=None):
        pid = _field(event, key)
        return builder.get_or_create_process_node(pid, name, username, hostname, kind, event) if pid else None

    def observation(group, subject="", fields=(), owner=None, relation="Observed"):
        occurrence = builder.current_event_id if builder.current_event_id is not None else string_hash(event)
        identity = (kind, host, subject) if subject else (kind, host, occurrence)
        node_id = f"falcon_{string_hash(identity)}"
        label = f"{kind}: {subject[:80] if subject else 'observation'}"
        details = [f"[{kind}]", f"Host: {host}"]
        details.extend(f"{key}: {_field(event, key)[:240]}" for key in fields if _field(event, key))
        builder.add_or_update_artifact_node(node_id, label, "\n".join(details), group, event)
        if not owner and host:
            host_id = f"falcon_{string_hash(('host-observation', host))}"
            builder.add_or_update_artifact_node(host_id, f"Host: {host}",
                                                f"Host: {host}", "network", event)
            owner = host_id
        if owner and owner != node_id:
            builder.add_edge(owner, node_id, relation, "#b366ff", kind, raw_event=event)
        return node_id

    if kind == "ClassifiedProcessStart":
        target = process("TargetProcessId", _field(event, "TargetImageFileName") or None)
        parent = process("ParentProcessId", _field(event, "ParentBaseFileName") or None)
        if parent and target and parent != target:
            builder.add_edge(parent, target, "Parent Of", "#ff4d4d", kind, raw_event=event)
        observation("alert", _field(event, "TreeId"), ("Classification", "PatternId", "TreeId"),
                    target, "Classified RMM Process")
    elif kind in THREAD_EVENTS:
        source = process("ContextProcessId", _field(event, "ContextBaseFileName") or None)
        target = process("TargetProcessId", _field(event, "TargetImageFileName") or None)
        if source and target and source != target:
            builder.add_edge(source, target, "Thread Activity", "#ff4d4d", kind, raw_event=event)
        observation("alert", "", ("TargetThreadId", "ThreadStartAddress"), target or source,
                    "Thread Observation")
    elif kind == "ClassifiedSensitiveFileAccess":
        owner = process("ContextProcessId")
        observation("file", _field(event, "TargetFileName"),
                    ("TargetFileName", "Classification"), owner, "Accesses Classified File")
    elif kind == "CriticalFileModified":
        owner = process("ContextProcessId")
        observation("file", _field(event, "TargetFileName"), ("TargetFileName",), owner,
                    "Modifies Critical File")
    elif kind == "CloudAssociateTreeIdWithRoot":
        owner = process("TargetProcessId")
        observation("alert", _field(event, "TreeId"), ("TreeId", "PatternId"), owner,
                    "Cloud Tree Detection")
    elif kind in CUSTOM_EVENTS or kind == "CSAResultsGenericDetectInfo":
        owner = process("ContextProcessId") or process("TargetProcessId")
        fields = ("PatternId", "DomainName", "TargetFileName", "RemoteAddressIP4", "RemotePort",
                  "DetectName", "DetectSeverity")
        subject = _field(event, "PatternId") or _field(event, "DomainName")
        observation("alert", subject, fields, owner, "Triggers Alert")
    elif kind == "DataEgress":
        owner = process("ContextProcessId")
        # DataEgress is an assessment, not proof of successful transfer.
        assessment = _field(event, "AssessmentEventId")
        if assessment:
            node_id = f"falcon_{string_hash(('assessment', host, assessment))}"
            builder.add_or_update_artifact_node(
                node_id, f"Assessment: {assessment[:80]}",
                f"[{kind}]\nAssessmentEventId: {assessment[:160]}", "alert", event)
            if owner:
                builder.add_edge(owner, node_id, "Egress Assessment", "#b366ff", kind, raw_event=event)
        else:
            observation("alert", _field(event, "DataEgressId"),
                        ("DataEgressId", "AssessedFileName", "DataProtectionPolicyRuleAction"),
                        owner, "Egress Assessment")
    elif kind == "CLIUnderListen":
        owner = process("ContextProcessId")
        observation("network", "", ("LocalAddressIP4", "LocalPort", "Protocol"), owner,
                    "Listen Observation")
    elif kind in HOST_EVENTS:
        # Status/crash payloads can contain dumps and stacks: do not copy them.
        observation("alert", "", ("Status", "Result", "ConfigState", "ProvisioningState"))
