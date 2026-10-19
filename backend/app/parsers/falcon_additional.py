"""Additional Falcon event mappings; raw evidence remains on demand."""

from app.parsers.builder import as_text, string_hash

_INJECTED_THREAD_FLAGS = {
    0x1: "PREV_MODE_KERNEL", 0x2: "START_ADDRESS_IN_NAMED_PE",
    0x4: "START_ADDRESS_IN_SYS_RANGE", 0x8: "SYSTEM_THREAD",
    0x10: "SOURCE_PROCESS_IS_SYSTEM", 0x20: "TARGET_ANALYSIS_FAILED",
    0x40: "CONTEXT_ANALYSIS_FAILED", 0x80: "START_ADDRESS_IN_NTDLL",
    0x100: "START_ADDRESS_IN_WIN_DLL", 0x200: "START_ADDRESS_PRIVATE_MEM",
}
_EXECUTION_TYPES = dict(enumerate((
    "THREAD_INJECT", "THREAD_INJECT_MASQUERADE", "THREAD_HIJACK",
    "PROCESS_HOLLOWING", "WINDOWS_HOOK", "PROCESS_OVERWRITE_HOLLOWING",
    "REMOTE_APC", "REMOTE_ATOM_BOMB", "PROCESS_HOLLOWING_APC",
    "SET_WINDOW_LONG", "SET_PROP", "LOCAL_CLASSIFIED_MEMORY_OPERATION",
    "REMOTE_CLASSIFIED_MEMORY_OPERATION",
)))
_PAYLOAD_CLASSIFICATIONS = dict(enumerate((
    "UNKNOWN", "ANTIVIRUS", "GENERIC_MALWARE", "RAT",
)))
_PAYLOAD_FLAGS = {
    1: "KNOWN_BENIGN", 2: "SUSPICIOUS", 4: "KNOWN_MALICIOUS",
    8: "ENABLE_VISIBILITY", 16: "LARGE_VISIBILITY", 32: "EXPERIMENTAL",
}
_ASSEMBLY_FLAGS = {
    1: "ASSEMBLY_DOMAIN_NEUTRAL", 2: "ASSEMBLY_DYNAMIC",
    4: "ASSEMBLY_HAS_NATIVE_IMAGE", 8: "ASSEMBLY_COLLECTIBLE",
}
# Falcon documents two overlapping .NET-module flag namespaces (DOTNET and
# PRF). Keep the numeric value rather than claiming an ambiguous bit's meaning.
_HOST_PROCESS_TYPES = dict(enumerate((
    "OTHERS", "POWERSHELL", "POWERSHELL_ISE", "WSCRIPT", "CSCRIPT", "OFFICEEXE",
)))
_SCRIPT_SOURCES = dict(enumerate((
    "INCONCLUSIVE", "FILE", "COMMAND", "ENCODEDCOMMAND", "STDIN",
    "DYNAMIC", "INTERACTIVE", "EXECUTEMODE",
)))
_SCRIPT_LANGUAGES = dict(enumerate((
    "SCINTERNAL", "UNKNOWN", "POWERSHELL", "VBA", "VBSCRIPT", "JSCRIPT",
    "DOTNET", "EXCEL", "DOTNETCORE",
)))
_SCRIPT_TYPES = dict(enumerate((
    "UNKNOWN", "ACTIONSCRIPT", "APPLESCRIPT", "ASP", "ASSEMBLY", "BATCHFILE",
    "C_FAMILY", "CLOJURE", "CMAKE", "COBOL", "COFFEESCRIPT", "COLDFUSION",
    "COMMONLISP", "CSHARP", "CSS", "CSV", "DART", "DOCKERFILE",
    "DREAMMAKER", "ELIXIR", "ERLANG", "FORTRAN", "GO", "HASKELL",
    "HTML", "JAVA_FAMILY", "JAVASCRIPT_FAMILY", "JAVASERVERPAGES", "JSON",
    "JULIA", "KOTLIN", "MAKEFILE", "MATLAB", "OBJECTIVE_CPP", "OCAML",
    "PASCAL", "PERL", "PHP", "POWERSHELL", "PYTHON", "R", "RUBY",
    "RUST", "SCALA", "SHELL", "SQL", "SWIFT", "TEX", "TEXT", "TOML",
    "VERILOG", "VHDL", "VISUALBASIC", "XML", "YAML",
)))
_DISPOSITIONS = {
    0: "NOACTION", 3: "ANALYSIS", 4: "SENSOR_ONLY", 10: "INDICATOR",
    20: "DETECT", 25: "OPERATION_BLOCK", 30: "PREVENT",
    60: "PREVENT_KILLPARENT", 61: "PREVENT_KILLSOURCE",
    70: "CONTAINMENT_FS_SERVER",
}
_SERVICE_STARTS = {
    0: "BOOT_START", 1: "SYSTEM_START", 2: "AUTO_START",
    3: "DEMAND_START", 4: "DISABLED",
}
_SERVICE_TYPES = {
    1: "KERNEL_DRIVER", 2: "FILE_SYSTEM_DRIVER", 4: "ADAPTER",
    8: "RECOGNIZER_DRIVER", 16: "WIN32_OWN_PROCESS",
    32: "WIN32_SHARE_PROCESS", 256: "INTERACTIVE_PROCESS",
}
_SERVICE_ERRORS = dict(enumerate(("IGNORE", "NORMAL", "SEVERE", "CRITICAL")))
_COMMAND_CODES = {
    1: "SCRIPT", 2: "GET", 3: "GDD", 4: "XMEMDUMP", 5: "DOWNLOAD_RENAME",
    6: "EXEC", 7: "CUSTOM_SCRIPT", 8: "PUT_RUN_DIRECTORY",
    9: "CUSTOM_SCRIPT_WITH_GUARDRAILS", 10: "CUSTOM_PYTHON_SCRIPT",
    11: "CUSTOM_TOAST_NOTIFICATION", 12: "DEFERRED_DIALOG",
}
_ERROR_CODES = dict(enumerate((
    "RR_INITIALIZATION_ERROR", "RR_INSTANTIATION_ERROR", "RR_EXECUTION_ERROR",
    "RR_EXCEPTION_ERROR", "RR_ENTITLEMENT_ERROR", "RR_INVALID_COMMAND_ERROR",
    "RR_DISABLED_ERROR", "RR_NOT_IMPLEMENTED_ERROR", "RR_DISABLED_LOCALLY_ERROR",
    "RR_EXECUTION_MEMORY_LIMIT_EXCEEDED_ERROR", "RR_EXECUTION_TIMEOUT_ERROR",
    "RR_INVALID_GUARDRAILS_ERROR", "RR_EXECUTION_EXCESSIVE_OUTPUT_ERROR",
    "RR_GUARDRAILS_SETUP_ERROR", "RR_NO_PYTHON_PACKAGE_ERROR",
    "RR_PS_SCRIPT_FATAL_EXCEPTION_ERROR", "RR_FFIT_DISABLED_ERROR",
    "RR_INVALID_ORIGIN_ERROR", "RR_PYTHON_PIPE_CREATION_ERROR",
    "RR_PYTHON_PROCESS_CREATION_ERROR", "RR_PYTHON_PROCESS_MANAGEMENT_ERROR",
    "RR_PYTHON_IO_ERROR", "RR_SHELL_NOT_FOUND_ERROR",
    "RR_DIRECTORY_CREATION_ERROR", "RR_EXECUTION_OUTPUT_ERROR",
    "RR_EXECUTION_IDLE_TIMEOUT_ERROR", "RR_TASK_IO_ERROR",
    "RR_PYTHON_PERMISSIONS_ERROR", "RR_PYTHON_PACKAGE_INVALID_ERROR",
    "RR_GUARDRAILS_MEMORY_NOTIFY_ERROR", "RR_GUARDRAILS_CGROUP_CREATION_ERROR",
    "RR_TASK_RUN_ERROR",
), start=1))

ADDITIONAL_EVENTS = frozenset({
    "InjectedThread", "DllInjection", "NewExecutableRenamed",
    "ReflectiveDotnetModuleLoad", "ScriptControlDetectInfo",
    "SensitiveWmiQuery", "CreateService", "ProcessInjection",
    "RemoteCommandResponse",
    "VolumeSnapshotOperationBlocked", "VulnerableDriverDetectInfo",
    "WfpFilterTamperingFilterAdded", "WfpFilterTamperingFilterDeleted",
    "WmiCreateProcess", "WmiFilterConsumerBindingEtw", "WmiProviderRegistrationEtw",
    "WmiQueryDetectInfo", "WroteExeAndGeneratedServiceEvent",
    "WSLDistributionRegistered", "WSLDistributionStarted", "WSLDistributionStopping",
    "WSLDistributionUnregistered", "WSLMetadata", "WSLVMStarted", "WSLVMStopping",
    "XumdHookEvent", "XumdStatus", "ZerologonExploitAttempt",
})


def _short(value, limit=240):
    text = as_text(value)
    return text[:limit] + "…" if len(text) > limit else text


def _basename(value):
    return as_text(value).replace("\\", "/").rstrip("/").split("/")[-1]


def _code(value, choices, flags=False):
    text = as_text(value)
    if not text:
        return ""
    try:
        number = int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError:
        return _short(text)
    if flags:
        names = [name for bit, name in choices.items() if number & bit]
        unknown = number & ~sum(choices)
        if unknown:
            names.append(hex(unknown))
        return f"{', '.join(names) or 'NONE'} ({text})"
    return f"{choices[number]} ({text})" if number in choices else text


def _details(evt_type, event, fields=(), codes=()):
    lines = [f"[{evt_type}]"]
    for label, field in fields:
        if field in event and event[field] is not None:
            value = _short(event[field])
            if value:
                lines.append(f"{label}: {value}")
    for label, field, choices, flags in codes:
        value = _code(event.get(field), choices, flags)
        if value:
            lines.append(f"{label}: {value}")
    return "\n".join(lines)


def _process(builder, pid, name, username, hostname, evt_type, event):
    return builder.get_or_create_process_node(
        pid, _basename(name) or None, username, hostname, evt_type, event)


def _artifact(builder, process_id, node_id, label, details, group, edge_label, evt_type, event,
              color="#b366ff"):
    builder.add_or_update_artifact_node(node_id, label, details, group, event)
    builder.add_edge(process_id, node_id, edge_label, color, evt_type, raw_event=event)


def _host(builder, hostname, event):
    host = as_text(hostname) or "UnknownHost"
    node_id = f"host_{host}"
    builder.add_or_update_artifact_node(node_id, f"Host:\n{host}",
                                        "Central Context Node", "network", event)
    return node_id


def parse_additional_falcon_event(builder, event, evt_type, username, hostname):
    context = event.get("ContextProcessId")
    target = event.get("TargetProcessId")

    if evt_type in ADDITIONAL_EVENTS - {
        "InjectedThread", "DllInjection", "NewExecutableRenamed", "ReflectiveDotnetModuleLoad",
        "ScriptControlDetectInfo", "SensitiveWmiQuery", "CreateService", "ProcessInjection",
            "RemoteCommandResponse",
    }:
        host_only = evt_type.startswith(("WfpFilterTampering", "WSL"))
        pid = (event.get("TargetProcessId") if evt_type == "WmiCreateProcess"
               else event.get("ContextProcessId"))
        owner = (_process(builder, pid, event.get("ImageFileName"), username, hostname,
                          evt_type, event) if pid and not host_only else _host(builder, hostname, event))
        fields = (
            ("Operation", "Operation"), ("Snapshot", "VolumeSnapshotId"),
            ("Driver", "DriverName"), ("Driver Path", "DriverPath"),
            ("Filter", "FilterName"), ("Filter ID", "FilterId"),
            ("Namespace", "WmiNamespaceName"), ("Consumer", "ConsumerName"),
            ("Provider", "ProviderName"), ("Distribution", "DistributionName"),
            ("Distribution ID", "DistributionId"), ("Service", "ServiceObjectName"),
            ("Disposition", "TemplateDisposition"), ("Status", "Status"),
        )
        # Commands, WMI queries, scripts and XUMD parameters can contain large or
        # sensitive payloads; they remain available exclusively in raw evidence.
        key = (hostname, evt_type, pid if not host_only else None,
               event.get("timestamp"), event.get("EventCorrelationId"),
               event.get("DistributionId"), event.get("FilterId"),
               event.get("ServiceObjectName"))
        labels = {
            "VolumeSnapshotOperationBlocked": "Blocked snapshot operation",
            "VulnerableDriverDetectInfo": "Vulnerable driver detection",
            "WmiCreateProcess": "WMI process creation",
            "WmiQueryDetectInfo": "WMI query detection",
            "WroteExeAndGeneratedServiceEvent": "Executable and service detection",
            "XumdHookEvent": "XUMD hook event", "XumdStatus": "XUMD status",
            "ZerologonExploitAttempt": "Zerologon exploit attempt",
        }
        label = labels.get(evt_type, evt_type)
        _artifact(builder, owner, f"falcon_{string_hash(key)}", label,
                  _details(evt_type, event, fields), "alert",
                  label, evt_type, event, "#ff9933")
        return

    if evt_type in ("InjectedThread", "DllInjection", "ProcessInjection"):
        source = _process(builder, context, event.get("InjectorImageFileName"),
                          username, hostname, evt_type, event) if context else None
        destination = _process(builder, target, event.get("InjecteeImageFileName"),
                               username, hostname, evt_type, event) if target else None
        fields = (
            ("Target Thread", "TargetThreadId"), ("Start Address", "ThreadStartAddress"),
            ("Start Context", "ThreadStartContext"), ("Source Start Address", "SourceThreadStartAddress"),
            ("Source Module", "SourceThreadModule"), ("Target Module", "TargetThreadModule"),
            ("Memory Flags", "MemoryDescriptionFlags"),
            ("Start Memory Flags", "ThreadStartAddressMemoryDescriptionFlags"),
            ("Target Function", "WellKnownTargetFunction"),
            ("Pattern ID", "PatternId"), ("Tree ID", "TreeId"),
            ("Module", "ModuleName"), ("Injected DLL", "InjectedDll"),
        )
        codes = (
            ("Thread Flags", "InjectedThreadFlag", _INJECTED_THREAD_FLAGS, True),
            ("Execution Type", "ThreadExecutionControlType", _EXECUTION_TYPES, False),
            ("Payload Classification", "PayloadClassification", _PAYLOAD_CLASSIFICATIONS, False),
            ("Payload Flags", "PayloadClassificationFlags", _PAYLOAD_FLAGS, True),
            ("Disposition", "TemplateDisposition", _DISPOSITIONS, False),
        )
        if source and destination:
            builder.add_edge(source, destination, evt_type, "#ff4d4d", evt_type, raw_event=event)
        # A process edge cannot carry a title; keep concise evidence on an
        # event-specific artifact, attached to the target when it exists.
        owner = destination or source
        if owner:
            identity = (hostname, context, target, event.get("timestamp"),
                        event.get("TargetThreadId"), event.get("ThreadStartAddress"),
                        event.get("InjectedDll"), evt_type)
            _artifact(builder, owner, f"injection_{string_hash(identity)}", evt_type,
                      _details(evt_type, event, fields, codes), "alert", "Injection Details",
                      evt_type, event, "#ff4d4d")
            dll = as_text(event.get("InjectedDll"))
            if evt_type == "DllInjection" and dll:
                _artifact(builder, owner, f"module_{string_hash(dll)}", _basename(dll),
                          f"[{evt_type}]\nInjected DLL: {_short(dll)}", "module",
                          "Injects DLL", evt_type, event)

    elif evt_type == "NewExecutableRenamed":
        source = as_text(event.get("SourceFileName"))
        destination = as_text(event.get("TargetFileName"))
        owner = _process(builder, context, event.get("ImageFileName"),
                         username, hostname, evt_type, event) if context else None
        if owner and destination:
            details = _details(evt_type, event, (
                ("Source", "SourceFileName"), ("Destination", "TargetFileName"),
                ("Symbolic Target", "SymLinkTargetFileName"),
                ("File Identifier", "FileIdentifier"),
                ("New File Identifier", "NewFileIdentifier"),
            ))
            _artifact(builder, owner, f"file_{string_hash(destination)}", _basename(destination),
                      details, "file", "Renames Executable", evt_type, event, "#4da6ff")
            if source:
                source_node = f"file_{string_hash(source)}"
                builder.add_or_update_artifact_node(
                    source_node, _basename(source), f"[{evt_type}]\nSource: {_short(source)}", "file", event)
                builder.add_edge(owner, source_node, "Renames From", "#4da6ff",
                                 evt_type, raw_event=event)

    elif evt_type == "ReflectiveDotnetModuleLoad":
        owner = _process(builder, context, event.get("ImageFileName"),
                         username, hostname, evt_type, event) if context else None
        name = as_text(event.get("AssemblyName") or event.get("ModuleILPath")
                       or event.get("ModuleNativePath"))
        module_id = as_text(event.get("DotnetModuleId"))
        assembly_id = as_text(event.get("AssemblyId"))
        if owner:
            key = (hostname, context, module_id, assembly_id, name)
            details = _details(evt_type, event, (
                ("Assembly", "AssemblyName"), (".NET Module ID", "DotnetModuleId"),
                ("Assembly ID", "AssemblyId"), ("IL Path", "ModuleILPath"),
                ("Native Path", "ModuleNativePath"), ("App Domain", "AppDomainId"),
                ("Managed PDB", "ManagedPdbBuildPath"), ("Native PDB", "NativePdbBuildPath"),
                (".NET Module Flags (raw, overlapping namespaces)", "DotnetModuleFlags"),
            ), (("Assembly Flags", "AssemblyFlags", _ASSEMBLY_FLAGS, True),
                ("ETW Provider", "EtwProviderType", {0: "NONE", 1: "MOF", 2: "MANIFEST", 3: "WPP"}, False)))
            _artifact(builder, owner, f"dotnet_{string_hash(key)}", _basename(name) or "Reflective .NET module",
                      details, "module", "Loads .NET Module", evt_type, event)

    elif evt_type == "ScriptControlDetectInfo":
        owner = _process(builder, context, event.get("ImageFileName"),
                         username, hostname, evt_type, event) if context else None
        if owner:
            name = as_text(event.get("ScriptContentName"))
            digest = as_text(event.get("ContentSHA256HashData"))
            correlation = as_text(event.get("EventCorrelationId"))
            # Do not put ScriptContent in titles or IDs: it may be very large.
            key = (hostname, context, correlation, name, digest,
                   as_text(event.get("PatternId")), as_text(event.get("timestamp")))
            fields = (("Script", "ScriptContentName"), ("Content SHA256", "ContentSHA256HashData"),
                      ("Image SHA256", "SHA256HashData"), ("Pattern ID", "PatternId"),
                      ("Pattern IDs", "PatternIdList"), ("Template Instance", "TemplateInstanceId"),
                      ("Original Content Length", "OriginalContentLength"),
                      ("Event Correlation ID", "EventCorrelationId"),
                      ("Match Confidence", "MatchConfidence"))
            codes = (("Disposition", "TemplateDisposition", _DISPOSITIONS, False),
                     ("Script Source", "ScriptContentSource", _SCRIPT_SOURCES, False),
                     ("Host Process", "HostProcessType", _HOST_PROCESS_TYPES, False),
                     ("Scripting Language", "ScriptingLanguageId", _SCRIPT_LANGUAGES, False),
                     ("Script Type", "ScriptType", _SCRIPT_TYPES, False))
            _artifact(builder, owner, f"script_detect_{string_hash(key)}",
                      f"Script detection: {_basename(name) or as_text(event.get('PatternId')) or 'unknown'}",
                      _details(evt_type, event, fields, codes), "alert",
                      "Detects Script", evt_type, event, "#ff4d4d")

    elif evt_type == "SensitiveWmiQuery":
        owner = _process(builder, context, None, username, hostname, evt_type, event) if context else None
        namespace = as_text(event.get("WmiNamespaceName"))
        if owner:
            key = (hostname, context, namespace, event.get("WmiQuery"))
            _artifact(builder, owner, f"wmi_{string_hash(key)}", "WMI: sensitive query",
                       _details(evt_type, event, (("Namespace", "WmiNamespaceName"),
                                                ("Client", "ClientComputerName"))),
                      "commandline", "Queries WMI", evt_type, event, "#ff9933")

    elif evt_type == "CreateService":
        # RPC client is the creator; ContextProcessId only reports telemetry origin.
        creator = event.get("RpcClientProcessId") or context
        owner = _process(builder, creator, None, username, hostname, evt_type, event) if creator else None
        name = as_text(event.get("ServiceObjectName") or event.get("ServiceDisplayName"))
        if owner:
            key = (hostname, name or event.get("ServiceImagePath") or event.get("timestamp"))
            fields = (("Service", "ServiceObjectName"), ("Display Name", "ServiceDisplayName"),
                      ("Description", "ServiceDescription"), ("Image Path", "ServiceImagePath"),
                      ("Service DLL", "ServiceServiceDll"), ("Group", "ServiceGroup"),
                      ("Start Account", "UserName"), ("Client", "ClientComputerName"),
                      ("Client IPv4", "RemoteAddressIP4"), ("Client IPv6", "RemoteAddressIP6"),
                      ("Required Privileges", "ServiceRequiredPrivileges"))
            codes = (("Start Type", "ServiceStart", _SERVICE_STARTS, False),
                     ("Service Type", "ServiceType", _SERVICE_TYPES, True),
                     ("Error Control", "ServiceErrorControl", _SERVICE_ERRORS, False))
            _artifact(builder, owner, f"service_{string_hash(key)}", f"Service: {_short(name, 70) or 'unknown'}",
                      _details(evt_type, event, fields, codes), "registry", "Creates Service",
                      evt_type, event, "#ff9933")

    elif evt_type == "RemoteCommandResponse":
        # These records have no UPID. Anchor them to a host, not a fictitious process.
        host = as_text(hostname) or "UnknownHost"
        host_id = f"host_{host}"
        builder.add_or_update_artifact_node(host_id, f"Host:\n{host}",
                                            "Central Context Node", "network", event)
        key = (host, event.get("CommandName"), event.get("CommandSequenceNumber"),
               event.get("CommandStartTimeStamp"), event.get("CommandEndTimeStamp"),
               event.get("timestamp"))
        details = _details(evt_type, event, (
            ("Command", "CommandName"), ("Sequence", "CommandSequenceNumber"),
            ("Sequence Total", "CommandSequenceTotal"), ("Start", "CommandStartTimeStamp"),
            ("End", "CommandEndTimeStamp"), ("Cloud Time", "CommandCloudTimeStamp"),
        ), (("Command Code", "CommandCode", _COMMAND_CODES, False),
            ("Cloud Error", "CloudErrorCode", _ERROR_CODES, False)))
        # stdout/stderr are retained in raw evidence, never copied into element data.
        _artifact(builder, host_id, f"remote_response_{string_hash(key)}",
                   "Remote response",
                  details, "commandline", "Remote Command Response", evt_type, event, "#a6a6a6")
