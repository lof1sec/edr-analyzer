"""Conservative Defender Advanced Hunting graph mappings.

Known ActionType values identify their Advanced Hunting table. Only genuinely
exclusive columns can contradict that provenance; shared columns cannot.
"""

from app.parsers.builder import GraphBuilder, as_text, get_additional_fields_dict, string_hash
from app.parsers.defender_catalog import ACTION_TABLES, ACTION_TO_TABLE, EXCLUSIVE_FIELDS
from app.parsers.defender_legacy import parse_defender_event as parse_legacy_defender_event


def device_events_table(event):
    """Return the declared table; conflicting declarations are not trusted."""
    tables = {value.strip() for key in ("TableName", "SourceTable")
              if isinstance(value := event.get(key), str) and value.strip()}
    if len(tables) == 1:
        return tables.pop()
    if tables:
        return "conflicting table markers"
    return None


TABLES = frozenset(ACTION_TABLES)

FILE_ACTIONS = frozenset({"FileCreated", "FileModified", "FileDeleted", "FileRenamed"})
REGISTRY_ACTIONS = ACTION_TABLES["DeviceRegistryEvents"]
NETWORK_ACTIONS = ACTION_TABLES["DeviceNetworkEvents"]


def classify_defender_table(event):
    """Trust an explicit table unless its fields identify a different family.

    Shared process and device columns never establish provenance on their own.
    A contradictory action/column signature is left unmapped.
    """
    declared = device_events_table(event)
    if declared == "conflicting table markers":
        return None
    action = as_text(event.get("ActionType")).strip()
    action_table = ACTION_TO_TABLE.get(action)
    signatures = {table for table, fields in EXCLUSIVE_FIELDS.items()
                  if any(event.get(field) not in (None, "") for field in fields)}
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
    """Only an explicit source table currently proves DeviceEvents provenance."""
    return device_events_table(event) == "DeviceEvents"


def _field(event, key):
    return as_text(event.get(key)).strip()


def _artifact(builder, actor, event, kind, value, label, group, relation, color, detail=None):
    if not actor or not value:
        return
    node_id = f"defender_{kind}_{string_hash(value)}"
    builder.add_or_update_artifact_node(
        node_id, label[:80], f"[{event.get('ActionType', '')}]\n{detail or value}", group, event,
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
            value = remote + (":" + port if port else "") if remote else ""
            kind, group, relation, color = "network", "network", evt_type, "#00ffff"
        elif table == "DeviceImageLoadEvents" and evt_type == "ImageLoaded":
            value = _field(event, "FolderPath")
            kind, group, relation, color = "module", "module", "Loads Module", "#b366ff"
        else:
            value = ""
        if value:
            actor = builder.get_or_create_process_node(actor_id, actor_name, username, hostname, evt_type, event)
            _artifact(builder, actor, event, kind, value, value, group, relation, color)
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
