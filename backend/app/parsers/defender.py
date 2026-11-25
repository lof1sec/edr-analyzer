"""Conservative Defender Advanced Hunting graph mappings.

Microsoft's ``Type`` field identifies the Advanced Hunting table directly when
present. For older exports without ``Type``, known ``ActionType`` values,
``TableName``/``SourceTable`` markers, and exclusive columns are used instead.
"""

from app.parsers.builder import GraphBuilder, as_text, get_additional_fields_dict, string_hash
from app.parsers.defender_catalog import (
    ACTION_TABLES,
    ACTION_TO_TABLE,
    DEFENDER_TABLES,
    EXCLUSIVE_FIELDS,
)
from app.parsers.defender_legacy import parse_defender_event as parse_legacy_defender_event

TABLES = DEFENDER_TABLES
_UNKNOWN_TYPE = "unknown type"


def defender_type_table(event):
    """Return the Defender table from ``Type``, or ``None`` when absent.

    Returns ``_UNKNOWN_TYPE`` when ``Type`` is a non-empty string outside
    ``TABLES`` so unsupported tables do not fall back to legacy heuristics.
    """
    if not isinstance(event, dict):
        return None
    value = event.get("Type")
    if isinstance(value, str):
        table = value.strip()
        if table:
            return table if table in TABLES else _UNKNOWN_TYPE
    return None


def device_events_table(event):
    """Return the declared table; ``Type`` takes precedence over legacy markers."""
    typed = defender_type_table(event)
    if typed is not None:
        return None if typed == _UNKNOWN_TYPE else typed
    tables = {value.strip() for key in ("TableName", "SourceTable")
              if isinstance(value := event.get(key), str) and value.strip()}
    if len(tables) == 1:
        return tables.pop()
    if tables:
        return "conflicting table markers"
    return None


FILE_ACTIONS = frozenset({"FileCreated", "FileModified", "FileDeleted", "FileRenamed"})
REGISTRY_ACTIONS = ACTION_TABLES["DeviceRegistryEvents"]
NETWORK_ACTIONS = ACTION_TABLES["DeviceNetworkEvents"]
INVALID_CERTIFICATE_DATES = frozenset({
    "CertificateCreationTime", "CertificateExpirationTime", "CertificateCountersignatureTime",
})


def classify_defender_table(event):
    """Identify the Defender Advanced Hunting table for an event.

    When Microsoft's ``Type`` field is present, it is trusted directly without
    cross-checking ``ActionType`` or exclusive columns (and unknown ``Type``
    values are left unmapped). When ``Type`` is absent or empty, fall back to
    ``TableName``/``SourceTable``, ``ActionType``, and exclusive columns.
    """
    typed = defender_type_table(event)
    if typed is not None:
        return None if typed == _UNKNOWN_TYPE else typed

    declared = device_events_table(event)
    if declared == "conflicting table markers":
        return None
    action = as_text(event.get("ActionType")).strip()
    action_table = ACTION_TO_TABLE.get(action)
    signatures = {table for table, fields in EXCLUSIVE_FIELDS.items()
                  if any(event.get(field) not in (None, "")
                         and not (field in INVALID_CERTIFICATE_DATES and event.get(field) == "Invalid date")
                         for field in fields)}
    if len(signatures) > 1 or (declared and signatures and declared not in signatures):
        return None
    if action and (declared and action_table and declared != action_table
                   or action_table and signatures and action_table not in signatures):
        return None
    if action and not action_table and not declared:
        return None
    if declared:
        return declared if declared in TABLES else None
    if action_table:
        return action_table
    if signatures:
        return next(iter(signatures))
    return None


def is_confirmed_device_event(event):
    """Only an explicit table marker (``Type``/``TableName``/``SourceTable``) proves DeviceEvents provenance."""
    return device_events_table(event) == "DeviceEvents"


def _field(event, key):
    return as_text(event.get(key)).strip()


def _truncate_field(value: str, limit: int = 60) -> str:
    if len(value) <= limit:
        return value
    return value[:limit - 1] + "…"


def _dns_connection_artifact(event, endpoint):
    """Build ``(identity, label, detail)`` for ``DnsConnectionInspected``.

    Combines ``RemoteIP:RemotePort`` (or ``RemoteUrl``) with ``query``,
    ``qtype_name``, ``rcode_name``, and ``direction`` from ``AdditionalFields``.
    """
    details = get_additional_fields_dict(event)
    query = as_text(details.get("query")).strip()
    qtype = as_text(details.get("qtype_name")).strip()
    rcode = as_text(details.get("rcode_name")).strip()
    direction = as_text(details.get("direction")).strip()

    if not endpoint and not query:
        return "", "", ""

    if not any((query, qtype, rcode, direction)):
        return endpoint, _truncate_field(endpoint, 80), endpoint

    label_lines = []
    detail_lines = []
    if endpoint:
        label_lines.append(_truncate_field(endpoint, 60))
        detail_lines.append(f"Remote: {endpoint}")
    if query:
        label_lines.append(f"Query: {_truncate_field(query, 60)}")
        detail_lines.append(f"Query: {query}")
    dns_meta = []
    if qtype:
        dns_meta.append(f"QType: {_truncate_field(qtype, 24)}")
        detail_lines.append(f"QType: {qtype}")
    if rcode:
        dns_meta.append(f"RCode: {_truncate_field(rcode, 24)}")
        detail_lines.append(f"RCode: {rcode}")
    if dns_meta:
        label_lines.append(" | ".join(dns_meta))
    if direction:
        label_lines.append(f"Direction: {_truncate_field(direction, 24)}")
        detail_lines.append(f"Direction: {direction}")

    identity = "\x1f".join((endpoint, query, qtype, rcode, direction))
    return identity, "\n".join(label_lines), "\n".join(detail_lines)


def _http_connection_artifact(event):
    """Build ``(identity, label, detail)`` for ``HttpConnectionInspected``.

    Combines ``RemoteIP:RemotePort``, optional ``RemoteUrl``, and ``host``,
    ``method``, ``direction``, and ``status_code`` from ``AdditionalFields``.
    """
    remote_ip = _field(event, "RemoteIP")
    port = _field(event, "RemotePort")
    remote_url = _field(event, "RemoteUrl")
    ip_endpoint = remote_ip + (":" + port if port else "") if remote_ip else ""

    details = get_additional_fields_dict(event)
    host = as_text(details.get("host")).strip()
    method = as_text(details.get("method")).strip()
    direction = as_text(details.get("direction")).strip()
    status_code = as_text(details.get("status_code")).strip()

    if not any((ip_endpoint, remote_url, host)):
        return "", "", ""

    if not any((host, method, direction, status_code)):
        if ip_endpoint and not remote_url:
            return ip_endpoint, _truncate_field(ip_endpoint, 80), ip_endpoint
        if remote_url and not ip_endpoint:
            endpoint = remote_url + (":" + port if port else "")
            return endpoint, _truncate_field(endpoint, 80), endpoint

    label_lines = []
    detail_lines = []
    if ip_endpoint:
        label_lines.append(_truncate_field(ip_endpoint, 60))
        detail_lines.append(f"Remote: {ip_endpoint}")
    if remote_url:
        label_lines.append(f"URL: {_truncate_field(remote_url, 60)}")
        detail_lines.append(f"RemoteUrl: {remote_url}")
    if host:
        label_lines.append(f"Host: {_truncate_field(host, 60)}")
        detail_lines.append(f"Host: {host}")
    http_meta = []
    if method:
        http_meta.append(f"Method: {_truncate_field(method, 24)}")
        detail_lines.append(f"Method: {method}")
    if status_code:
        http_meta.append(f"Status: {_truncate_field(status_code, 24)}")
        detail_lines.append(f"Status: {status_code}")
    if http_meta:
        label_lines.append(" | ".join(http_meta))
    if direction:
        label_lines.append(f"Direction: {_truncate_field(direction, 24)}")
        detail_lines.append(f"Direction: {direction}")

    identity = "\x1f".join((ip_endpoint, remote_url, host, method, status_code, direction))
    return identity, "\n".join(label_lines), "\n".join(detail_lines)


def _network_signature_artifact(event, endpoint):
    """Build ``(identity, label, detail)`` for ``NetworkSignatureInspected``.

    Combines ``RemoteIP:RemotePort``, ``LocalIP:LocalPort``, and
    ``SignatureName`` / ``SignatureMatchedContent`` from ``AdditionalFields``.
    """
    local_ip = _field(event, "LocalIP")
    local_port = _field(event, "LocalPort")
    local_endpoint = local_ip + (":" + local_port if local_port else "") if local_ip else ""

    details = get_additional_fields_dict(event)
    sig_name = as_text(details.get("SignatureName")).strip()
    matched = as_text(details.get("SignatureMatchedContent")).strip()

    if not any((endpoint, local_endpoint, sig_name, matched)):
        return "", "", ""

    if endpoint and not any((local_endpoint, sig_name, matched)):
        return endpoint, _truncate_field(endpoint, 80), endpoint

    label_lines = []
    detail_lines = []
    if endpoint:
        label_lines.append(f"Remote: {_truncate_field(endpoint, 60)}")
        detail_lines.append(f"Remote: {endpoint}")
    if local_endpoint:
        label_lines.append(f"Local: {_truncate_field(local_endpoint, 60)}")
        detail_lines.append(f"Local: {local_endpoint}")
    if sig_name:
        label_lines.append(f"Signature: {_truncate_field(sig_name, 60)}")
        detail_lines.append(f"SignatureName: {sig_name}")
    if matched:
        matched_line = " ".join(matched.split())
        label_lines.append(f"Matched: {_truncate_field(matched_line, 60)}")
        detail_lines.append(f"SignatureMatchedContent: {matched}")

    identity = "\x1f".join((endpoint, local_endpoint, sig_name, matched))
    return identity, "\n".join(label_lines), "\n".join(detail_lines)


def _ntlm_authentication_artifact(event, endpoint):
    """Build ``(identity, label, detail)`` for ``NtlmAuthenticationInspected``.

    Combines ``RemoteIP:RemotePort`` with ``username``, ``hostname``,
    ``server_nb_computer_name``, ``success``, and ``direction`` from
    ``AdditionalFields``.
    """
    details = get_additional_fields_dict(event)
    username = as_text(details.get("username")).strip()
    hostname = as_text(details.get("hostname")).strip()
    server_nb = as_text(details.get("server_nb_computer_name")).strip()
    success = as_text(details.get("success")).strip()
    direction = as_text(details.get("direction")).strip()

    if not any((endpoint, username, hostname, server_nb)):
        return "", "", ""

    if endpoint and not any((username, hostname, server_nb, success, direction)):
        return endpoint, _truncate_field(endpoint, 80), endpoint

    label_lines = []
    detail_lines = []
    if endpoint:
        label_lines.append(_truncate_field(endpoint, 60))
        detail_lines.append(f"Remote: {endpoint}")
    if username:
        label_lines.append(f"User: {_truncate_field(username, 60)}")
        detail_lines.append(f"Username: {username}")
    if hostname:
        label_lines.append(f"Host: {_truncate_field(hostname, 60)}")
        detail_lines.append(f"Hostname: {hostname}")
    if server_nb:
        label_lines.append(f"Server: {_truncate_field(server_nb, 60)}")
        detail_lines.append(f"Server NB: {server_nb}")
    ntlm_meta = []
    if success:
        ntlm_meta.append(f"Success: {_truncate_field(success, 24)}")
        detail_lines.append(f"Success: {success}")
    if direction:
        ntlm_meta.append(f"Direction: {_truncate_field(direction, 24)}")
        detail_lines.append(f"Direction: {direction}")
    if ntlm_meta:
        label_lines.append(" | ".join(ntlm_meta))

    identity = "\x1f".join((endpoint, username, hostname, server_nb, success, direction))
    return identity, "\n".join(label_lines), "\n".join(detail_lines)


def _ssl_connection_artifact(event, endpoint):
    """Build ``(identity, label, detail)`` for ``SslConnectionInspected``.

    Combines ``RemoteIP:RemotePort`` (or ``RemoteUrl``) with ``server_name``,
    ``version``, and ``direction`` from ``AdditionalFields``.
    """
    details = get_additional_fields_dict(event)
    server_name = as_text(details.get("server_name")).strip()
    version = as_text(details.get("version")).strip()
    direction = as_text(details.get("direction")).strip()

    if not endpoint and not server_name:
        return "", "", ""

    if endpoint and not any((server_name, version, direction)):
        return endpoint, _truncate_field(endpoint, 80), endpoint

    label_lines = []
    detail_lines = []
    if endpoint:
        label_lines.append(_truncate_field(endpoint, 60))
        detail_lines.append(f"Remote: {endpoint}")
    if server_name:
        label_lines.append(f"Server: {_truncate_field(server_name, 60)}")
        detail_lines.append(f"Server Name: {server_name}")
    ssl_meta = []
    if version:
        ssl_meta.append(f"Version: {_truncate_field(version, 24)}")
        detail_lines.append(f"Version: {version}")
    if direction:
        ssl_meta.append(f"Direction: {_truncate_field(direction, 24)}")
        detail_lines.append(f"Direction: {direction}")
    if ssl_meta:
        label_lines.append(" | ".join(ssl_meta))

    identity = "\x1f".join((endpoint, server_name, version, direction))
    return identity, "\n".join(label_lines), "\n".join(detail_lines)


def _artifact(builder, actor, event, kind, value, label, group, relation, color, detail=None, max_label=80):
    if not actor or not value:
        return
    node_id = f"defender_{kind}_{string_hash(value)}"
    display = label if max_label is None else label[:max_label]
    builder.add_or_update_artifact_node(
        node_id, display, f"[{event.get('ActionType', '')}]\n{detail or value}", group, event,
    )
    builder.add_edge(actor, node_id, relation, color, as_text(event.get("ActionType")), raw_event=event)


def _event_node(builder, event, evt_type, table, hostname, actor_id, actor_name, username):
    """Represent each observation without inventing a causal relationship."""
    import json

    row_id = builder.current_event_id
    if row_id is None:
        row_id = f"content_{string_hash(json.dumps(event, sort_keys=True, default=str))}_{len(builder.nodes_dict)}"
    node_id = f"defender_event_{row_id}"
    device = _field(event, "DeviceName")
    title = f"{table}\n{evt_type}" + (f"\nDeviceName: {device}" if device else "")
    builder.add_or_update_artifact_node(node_id, evt_type[:80], title, "event", event)
    if actor_id:
        actor = builder.get_or_create_process_node(actor_id, actor_name, username, hostname, evt_type, event)
        builder.add_edge(actor, node_id, "Reported by", "#64748b", evt_type, raw_event=event)
    return node_id


def _context(builder, event_node, event, evt_type, field, group, relation, color):
    value = _field(event, field)
    if value:
        node_id = f"defender_{group}_{string_hash(value)}"
        builder.add_or_update_artifact_node(node_id, value[:80], value, group, event)
        builder.add_edge(event_node, node_id, relation, color, evt_type, raw_event=event)


def parse_defender_event(builder: GraphBuilder, event: dict, evt_type: str, actor_id: str,
                         actor_name: str, target_id: str, target_name: str, username: str, hostname: str):
    table = classify_defender_table(event)
    if table is None:
        builder.unmapped_events.append(evt_type)
        return
    if table == "DisruptionAndResponseEvents":
        actor_id = None  # Reporter is not the blocked subject.
    node = _event_node(builder, event, evt_type, table, hostname, actor_id, actor_name, username)
    if table == "DeviceLogonEvents":
        _context(builder, node, event, evt_type, "AccountSid", "account", "Logon account", "#a78bfa")
    elif table == "DisruptionAndResponseEvents":
        for field, group, relation in (("SourceDeviceName", "host", "Source device"),
                                       ("TargetDeviceName", "host", "Target device"),
                                       ("SourceUserSid", "account", "Source account"),
                                       ("PolicyId", "policy", "Policy")):
            _context(builder, node, event, evt_type, field, group, relation, "#a78bfa")
    elif table == "DeviceEvents" and evt_type.startswith(("AppControl", "Asr", "ExploitGuard", "ControlledFolderAccess")):
        _context(builder, node, event, evt_type, "FolderPath", "file", "Controlled file", "#4da6ff")
        _context(builder, node, event, evt_type, "RemoteUrl", "network", "Controlled URL", "#00ffff")
    # Unmarked, minimal legacy file exports used the filename as their node ID.
    # Keep that narrow representation compatible without accepting unknown actions.
    if (table == "DeviceFileEvents" and evt_type in FILE_ACTIONS
            and device_events_table(event) is None and not event.get("FolderPath")
            and not event.get("PreviousFolderPath") and not event.get("PreviousFileName")):
        return parse_legacy_defender_event(
            builder, event, evt_type, actor_id, actor_name, target_id,
            target_name, username, hostname,
        )
    if table == "DeviceProcessEvents":
        if evt_type == "ProcessCreated" and actor_id and target_id:
            parent = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event)
            child = builder.get_or_create_process_node(
                target_id, target_name, username, hostname, evt_type, event)
            if parent and child and parent != child:
                builder.add_edge(parent, child, "Spawns", "#ff4d4d", evt_type, raw_event=event)
                command = _field(event, "ProcessCommandLine")
                if command:
                    _artifact(builder, child, event, "cmd", f"{child}:{command}", command,
                              "commandline", "Args", "#ffcc00")
                return
        return
    if table in {"DeviceFileEvents", "DeviceRegistryEvents", "DeviceNetworkEvents",
                 "DeviceImageLoadEvents"}:
        if not actor_id:
            return
        label = None
        detail = None
        max_label = 80
        if table == "DeviceFileEvents" and evt_type in FILE_ACTIONS:
            value = _field(event, "FolderPath") or _field(event, "FileName")
            kind, group, relation, color = "file", "file", evt_type, "#4da6ff"
        elif table == "DeviceRegistryEvents" and evt_type in REGISTRY_ACTIONS:
            key = _field(event, "RegistryKey")
            value = key + ("\\" + _field(event, "RegistryValueName")
                           if _field(event, "RegistryValueName") else "") if key else ""
            kind, group, relation, color = "registry", "registry", evt_type, "#ff9933"
        elif table == "DeviceNetworkEvents" and evt_type in NETWORK_ACTIONS:
            remote = _field(event, "RemoteIP") or _field(event, "RemoteUrl")
            port = _field(event, "RemotePort")
            endpoint = remote + (":" + port if port else "") if remote else ""
            if evt_type == "DnsConnectionInspected":
                value, label, detail = _dns_connection_artifact(event, endpoint)
                max_label = None
            elif evt_type == "HttpConnectionInspected":
                value, label, detail = _http_connection_artifact(event)
                max_label = None
            elif evt_type == "ListeningConnectionCreated":
                local_ip = _field(event, "LocalIP")
                local_port = _field(event, "LocalPort")
                value = local_ip + (":" + local_port if local_port else "") if local_ip else ""
            elif evt_type == "NetworkSignatureInspected":
                value, label, detail = _network_signature_artifact(event, endpoint)
                max_label = None
            elif evt_type == "NtlmAuthenticationInspected":
                value, label, detail = _ntlm_authentication_artifact(event, endpoint)
                max_label = None
            elif evt_type == "SslConnectionInspected":
                value, label, detail = _ssl_connection_artifact(event, endpoint)
                max_label = None
            else:
                value = endpoint
            kind, group, relation, color = "network", "network", evt_type, "#00ffff"
        elif table == "DeviceImageLoadEvents" and evt_type == "ImageLoaded":
            value = _field(event, "FolderPath")
            kind, group, relation, color = "module", "module", "Loads Module", "#b366ff"
        else:
            value = ""
        if value:
            actor = builder.get_or_create_process_node(actor_id, actor_name, username, hostname, evt_type, event)
            _artifact(builder, actor, event, kind, value, label or value, group, relation, color,
                      detail=detail, max_label=max_label)
            return
        return
    if table != "DeviceEvents":
        return

    if evt_type == "OtherAlertRelatedActivity":
        # This is an observation, not evidence of an alert or an alert target.
        return

    # InitiatingProcessId is the observed actor. ProcessId is not generally a
    # target: its meaning varies by action, so never infer a process relationship.
    # For DeviceEvents, file/network/registry observations are linked only to
    # an explicitly identified initiating process and an actual observed value.
    mappings = {
        "BrowserLaunchedToOpenUrl": ("RemoteUrl", "url", "network", "Launches URL", "#00ffff"),
        "DriverLoad": ("FolderPath", "module", "module", "Loads Driver", "#b366ff"),
    }
    mapping = mappings.get(evt_type)
    details = get_additional_fields_dict(event)
    if evt_type == "PowerShellCommand":
        value = as_text(details.get("Command")).strip()
        mapping = (None, "pscmd", "commandline-exec", "Executes PS", "#c2410c")
    elif evt_type == "NamedPipeEvent":
        value = as_text(details.get("PipeName")).strip()
        mapping = (None, "pipe", "file", "Named Pipe", "#4da6ff")
    elif evt_type == "LdapSearch":
        value = as_text(details.get("SearchFilter")).strip()
        mapping = (None, "ldap", "commandline", "LDAP Query", "#ffcc00")
    elif evt_type == "ClrUnbackedModuleLoaded":
        module = details.get("ModuleILPathOrName")
        value = module.strip() if isinstance(module, str) else ""
        mapping = (None, "module", "module", "Loads Module", "#b366ff")
    elif mapping:
        value = _field(event, mapping[0])
    else:
        value = ""
    if mapping and actor_id and value:
        actor = builder.get_or_create_process_node(actor_id, actor_name, username, hostname, evt_type, event)
        _artifact(builder, actor, event, mapping[1], value, value, mapping[2], mapping[3], mapping[4])
