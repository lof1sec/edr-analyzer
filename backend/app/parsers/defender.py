import json
import textwrap

from app.parsers.builder import GraphBuilder, as_text, get_additional_fields_dict, hash_str


def parse_defender_event(builder: GraphBuilder, event: dict, evt_type: str, actor_id: str,
                         actor_name: str, target_id: str, target_name: str, username: str, hostname: str):
    if evt_type == "ProcessCreated":
        cmdline = event.get("ProcessCommandLine", "No CommandLine")
        if actor_id and target_id:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            target_id = builder.get_or_create_process_node(
                target_id, target_name, username, hostname, evt_type, event) or target_id
            builder.add_edge(
                actor_id,
                target_id,
                "Spawns",
                "#ff4d4d",
                evt_type,
                raw_event=event)

            if cmdline and cmdline != "No CommandLine":
                cmd_node_id = f"cmd_{target_id}"
                wrapped_cmd = textwrap.fill(as_text(cmdline), width=60)
                builder.add_or_update_artifact_node(
                    cmd_node_id, wrapped_cmd, f"[{evt_type}]\nRaw Command Line:\n{cmdline}", "commandline", event)
                builder.add_edge(
                    target_id,
                    cmd_node_id,
                    "Args",
                    "#ffcc00",
                    evt_type,
                    dashed=True,
                    raw_event=event)

    elif evt_type == "PowerShellCommand":
        add_fields = get_additional_fields_dict(event)
        ps_command = add_fields.get("Command") or str(
            event.get("AdditionalFields", ""))
        if actor_id and ps_command:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            cmd_node_id = f"pscmd_{actor_id}_{hash_str(ps_command)}"
            wrapped_cmd = textwrap.fill(as_text(ps_command), width=60)
            builder.add_or_update_artifact_node(cmd_node_id,
                                                wrapped_cmd,
                                                f"[{evt_type}]\nRaw PowerShell Command:\n{ps_command}",
                                                "commandline-exec",
                                                event)
            builder.add_edge(
                actor_id,
                cmd_node_id,
                "Executes PS",
                "#c2410c",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "ClrUnbackedModuleLoaded":
        add_fields = get_additional_fields_dict(event)
        module_name = add_fields.get(
            "ModuleILPathOrName",
            "Unbacked CLR Assembly")
        if actor_id:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            clr_node_id = f"clr_{actor_id}_{hash_str(module_name)}"
            display_clr = f"Unbacked CLR\n{as_text(module_name)[:30]}"
            clr_info = f"[{evt_type}]\nAssembly / Module Name: {module_name}\nDetails:\n{event.get('AdditionalFields', '')}"
            builder.add_or_update_artifact_node(
                clr_node_id, display_clr, clr_info, "module", event)
            builder.add_edge(
                actor_id,
                clr_node_id,
                "Loads Unbacked CLR",
                "#b366ff",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "LdapSearch":
        add_fields = get_additional_fields_dict(event)
        search_filter = as_text(add_fields.get("SearchFilter", "Unknown Filter"))
        attributes = str(add_fields.get("AttributeList", ""))
        if actor_id:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            ldap_node_id = f"ldap_{actor_id}_{hash_str(search_filter)}"
            display_ldap = f"LDAP Search\n{search_filter[:30]}..." if len(
                search_filter) > 30 else f"LDAP Search\n{search_filter}"
            ldap_info = f"[{evt_type}]\nFilter: {search_filter}\nAttributes: {attributes}"
            builder.add_or_update_artifact_node(
                ldap_node_id, display_ldap, ldap_info, "commandline", event)
            builder.add_edge(
                actor_id,
                ldap_node_id,
                "LDAP Query",
                "#ffcc00",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type in ["PnpDeviceAllowed", "PnpDeviceConnected"]:
        add_fields = get_additional_fields_dict(event)
        device_id = add_fields.get("DeviceInstanceId", "Unknown Device")
        driver_name = add_fields.get("DriverName", "Unknown Driver")
        pnp_actor = actor_id if actor_id else "SYSTEM_PNP"
        pnp_actor_name = actor_name if actor_id else "Plug and Play Manager"
        pnp_actor = builder.get_or_create_process_node(
            pnp_actor, pnp_actor_name, username, hostname, evt_type, event) or pnp_actor
        pnp_node_id = f"pnp_{hash_str(device_id)}"
        display_pnp = f"PnP Device\n{driver_name}"
        pnp_info = f"[{evt_type}]\nDevice ID: {device_id}\nDriver: {driver_name}\nDetails: {event.get('AdditionalFields', '')}"
        builder.add_or_update_artifact_node(
            pnp_node_id, display_pnp, pnp_info, "module", event)
        builder.add_edge(
            pnp_actor,
            pnp_node_id,
            "Loads Device",
            "#b366ff",
            evt_type,
            dashed=True,
            raw_event=event)

    elif evt_type == "GetClipboardData":
        if actor_id:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            clip_node_id = f"clip_{actor_id}"
            clip_info = f"[{evt_type}]\nProcess accessed system clipboard contents."
            builder.add_or_update_artifact_node(
                clip_node_id, "📋 Clipboard Data", clip_info, "commandline", event)
            builder.add_edge(
                actor_id,
                clip_node_id,
                "Reads Clipboard",
                "#ffcc00",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "ProcessCreatedUsingWmiQuery":
        add_fields = get_additional_fields_dict(event)
        client_machine = add_fields.get("ClientMachine", "Local")
        wmi_actor = actor_id if actor_id else "WMI_Subsystem"
        wmi_actor_name = actor_name if actor_id else "WMI Engine"
        wmi_actor = builder.get_or_create_process_node(
            wmi_actor, wmi_actor_name, username, hostname, evt_type, event) or wmi_actor
        wmi_node_id = f"wmi_query_{hash_str(str(add_fields))}"
        wmi_info = f"[{evt_type}]\nClient Machine: {client_machine}\nDetails:\n{event.get('AdditionalFields', '')}"
        builder.add_or_update_artifact_node(
            wmi_node_id,
            f"WMI Query\n({client_machine})",
            wmi_info,
            "commandline",
            event)
        builder.add_edge(
            wmi_actor,
            wmi_node_id,
            "WMI Query",
            "#ffcc00",
            evt_type,
            dashed=True,
            raw_event=event)

    elif evt_type == "NamedPipeEvent":
        add_fields = get_additional_fields_dict(event)
        pipe_name = add_fields.get("PipeName")
        file_op = add_fields.get("FileOperation", "NamedPipeEvent")
        if actor_id and pipe_name:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            pipe_name_text = as_text(pipe_name)
            display_pipe = pipe_name_text.split(
                '\\')[-1] if '\\' in pipe_name_text else pipe_name_text
            if len(display_pipe) > 50:
                display_pipe = display_pipe[:50] + "..."
            pipe_info = f"[{evt_type}]\nPipe Name: {pipe_name}\nOperation: {file_op}"
            builder.add_or_update_artifact_node(
                pipe_name, display_pipe, pipe_info, "file", event)
            builder.add_edge(
                actor_id,
                pipe_name,
                file_op,
                "#4da6ff",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "DpapiAccessed":
        add_fields = get_additional_fields_dict(event)
        operation_type = add_fields.get("OperationType", "Unknown DPAPI Op")
        master_key_guid = add_fields.get("MasterKeyGUID", "Unknown GUID")
        flags = add_fields.get("Flags", "")
        if actor_id:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            dpapi_node_id = f"dpapi_{master_key_guid}"
            display_name = f"DPAPI\n{operation_type}"
            dpapi_info = f"[{evt_type}]\nOperation: {operation_type}\nMasterKey GUID: {master_key_guid}\nFlags: {flags}"
            builder.add_or_update_artifact_node(
                dpapi_node_id, display_name, dpapi_info, "module", event)
            builder.add_edge(
                actor_id,
                dpapi_node_id,
                operation_type,
                "#b366ff",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "BrowserLaunchedToOpenUrl":
        launched_url = event.get("RemoteUrl", "")
        if actor_id and launched_url:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            url_text = as_text(launched_url)
            url_node_id = f"url_{hash_str(url_text)}"
            display_url = url_text[:50] + \
                "..." if len(url_text) > 50 else url_text
            url_info = f"[{evt_type}]\nLaunched URL/URI:\n{launched_url}"
            builder.add_or_update_artifact_node(
                url_node_id, display_url, url_info, "network", event)
            builder.add_edge(
                actor_id,
                url_node_id,
                "Launches URL",
                "#00ffff",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "AntivirusReport":
        file_name = event.get("FileName", "Unknown Threat")
        sha1 = event.get("SHA1", "N/A")
        add_fields_raw = event.get("AdditionalFields", "")
        if isinstance(add_fields_raw, dict):
            add_fields_raw = json.dumps(add_fields_raw)
        av_actor = actor_id if actor_id else "SYSTEM_AV"
        av_actor_name = actor_name if actor_id else "Windows Defender Engine"
        av_actor = builder.get_or_create_process_node(
            av_actor, av_actor_name, username, hostname, evt_type, event) or av_actor
        alert_node_id = f"av_alert_{file_name}_{sha1}"
        display_name = f"⚠️ AV ALERT\n{as_text(file_name)[:25]}"
        alert_info = f"[{evt_type}]\nTarget Payload: {file_name}\nSHA1: {sha1}\nDetails: {add_fields_raw}"
        builder.add_or_update_artifact_node(
            alert_node_id, display_name, alert_info, "alert", event)
        builder.add_edge(
            av_actor,
            alert_node_id,
            "Detection",
            "#ff0000",
            evt_type,
            dashed=True,
            raw_event=event)

    elif evt_type in ["FileCreated", "FileModified", "FileDeleted", "FileRenamed", "ShellLinkCreateFileEvent"]:
        folder_path = as_text(event.get("FolderPath", ""))
        file_name = as_text(event.get("FileName", ""))
        full_path = folder_path if folder_path else file_name
        if actor_id and full_path:
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            display_file = file_name[:50] + \
                "..." if len(file_name) > 50 else file_name
            if not display_file:
                display_file = full_path[:50] + \
                    "..." if len(full_path) > 50 else full_path
            sha256 = event.get("SHA256", "N/A")
            add_fields_raw = event.get("AdditionalFields", "")
            if isinstance(add_fields_raw, dict):
                add_fields_raw = json.dumps(add_fields_raw)
            file_info = f"[{evt_type}]\nPath: {full_path}\nSHA256: {sha256}"
            if add_fields_raw:
                file_info += f"\nDetails: {add_fields_raw}"
            builder.add_or_update_artifact_node(
                full_path, display_file, file_info, "file", event)
            builder.add_edge(
                actor_id,
                full_path,
                evt_type,
                "#4da6ff",
                evt_type,
                raw_event=event)

    elif evt_type in ["ImageLoaded", "DriverLoad"]:
        dll_path = as_text(event.get("FolderPath", ""))
        dll_name = as_text(event.get("FileName", ""))
        if actor_id and dll_path:
            short_dll = dll_name if dll_name else dll_path.split('\\')[-1]
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            builder.add_or_update_artifact_node(
                dll_path, short_dll, f"[{evt_type}]\nLoaded Module/Driver:\n{dll_path}", "module", event)
            builder.add_edge(
                actor_id,
                dll_path,
                "Loads Module",
                "#b366ff",
                evt_type,
                raw_event=event)

    elif evt_type in ["RegistryKeyCreated", "RegistryValueCreated", "RegistryValueSet", "RegistryKeyDeleted", "RegistryValueDeleted"]:
        reg_key = as_text(event.get("RegistryKey") or event.get(
            "PreviousRegistryKey", ""))
        reg_value = as_text(event.get("RegistryValueName") or event.get(
            "PreviousRegistryValueName", ""))
        reg_data = event.get("RegistryValueData", "")
        if actor_id and reg_key:
            reg_node_id = f"{reg_key}\\{reg_value}" if reg_value else reg_key
            raw_reg = reg_value if reg_value else reg_key.split('\\')[-1]
            display_reg = raw_reg[:50] + \
                "..." if len(raw_reg) > 50 else raw_reg
            actor_id = builder.get_or_create_process_node(
                actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            full_reg_info = f"[{evt_type}]\nKey: {reg_key}\nValue: {reg_value}\nData:\n{reg_data}"
            builder.add_or_update_artifact_node(
                reg_node_id, display_reg, full_reg_info, "registry", event)
            builder.add_edge(
                actor_id,
                reg_node_id,
                evt_type,
                "#ff9933",
                evt_type,
                raw_event=event)

    elif evt_type in ["ConnectionSuccess", "ConnectionFailed", "NetworkConnectionEvents", "NetworkCommunicationEvents", "ListeningPortCreated", "ListeningConnectionCreated", "InboundConnectionAccepted", "RemoteDesktopConnection", "HttpConnectionInspected", "ConnectionAcknowledged", "ConnectionDropped", "DnsConnectionInspected", "SslConnectionInspected"]:
        remote_ip = event.get("RemoteIP", "")
        remote_port = event.get("RemotePort", "")
        local_ip = event.get("LocalIP", "")
        local_port = event.get("LocalPort", "")

        add_fields = get_additional_fields_dict(event)

        # Extract domain specifically for DnsConnectionInspected
        if evt_type == "DnsConnectionInspected":
            remote_url = add_fields.get("query", "")
            target_net = remote_url
        else:
            remote_url = event.get("RemoteUrl", "")
            if not remote_url:
                remote_url = add_fields.get(
                    "host", "") or add_fields.get(
                    "uri", "")
            target_net = remote_ip if remote_ip else remote_url

        protocol = event.get("Protocol", "")
        if not protocol:
            protocol = add_fields.get("Protocol", "")

        if not target_net and local_ip:
            target_net = f"Local_Listen:{local_ip}" if evt_type in [
                "ListeningPortCreated", "ListeningConnectionCreated"] else f"Local:{local_ip}"

        target_port = remote_port if remote_port else local_port
        net_actor = actor_id
        net_actor_name = actor_name

        if not net_actor:
            if evt_type in ["DnsConnectionInspected",
                            "SslConnectionInspected"]:
                net_actor = f"host_{hostname if hostname else 'UnknownHost'}"
                net_actor_name = f"Host:\n{
                    hostname if hostname else 'Unknown'}"
                if net_actor not in builder.nodes_dict:
                    builder.add_or_update_artifact_node(
                        net_actor, net_actor_name, "Central Context Node", "network", event)
            else:
                net_actor = "SYSTEM_NETWORK"
                net_actor_name = "Network Subsystem"

        if target_net:
            net_node_id = f"{target_net}:{target_port}" if target_port else target_net

            if not str(net_actor).startswith("host_"):
                net_actor = builder.get_or_create_process_node(
                    net_actor, net_actor_name, username, hostname, evt_type, event) or net_actor

            if evt_type == "DnsConnectionInspected":
                ips = ""
                answers = add_fields.get("answers", "")
                if isinstance(answers, str) and answers.startswith("["):
                    try:
                        answers = ", ".join(json.loads(answers))
                    except BaseException:
                        pass
                ips = answers if answers else ""

                full_net_info = f"[{evt_type}]\nDomain: {target_net}"
                if ips:
                    full_net_info += f"\nResolved IPs: {ips}"
                builder.add_or_update_artifact_node(
                    f"dns_{target_net}", target_net, full_net_info, "network", event)
                builder.add_edge(
                    net_actor,
                    f"dns_{target_net}",
                    "DNS Query",
                    "#00ffff",
                    evt_type,
                    raw_event=event)

            else:
                full_net_info = f"[{evt_type}]\nRemote: {remote_ip}:{remote_port}\nLocal: {local_ip}:{local_port}\nProtocol: {protocol}"
                if remote_url:
                    full_net_info += f"\nURL/Host: {remote_url}"

                if evt_type == "HttpConnectionInspected" and add_fields:
                    method = add_fields.get("method", "UNKNOWN")
                    status = add_fields.get("status_code", "N/A")
                    full_net_info += f"\nHTTP Method: {method}\nStatus: {status}"
                    if add_fields.get("direction"):
                        full_net_info += f"\nDirection: {add_fields.get('direction')}"

                elif evt_type == "ConnectionAcknowledged" and add_fields:
                    if "Tcp Flags" in add_fields:
                        full_net_info += f"\nTCP Flags: {add_fields.get('Tcp Flags')}"
                    if "direction" in add_fields:
                        full_net_info += f"\nDirection: {add_fields.get('direction')}"
                    if "Packet Size" in add_fields:
                        full_net_info += f"\nPacket Size: {add_fields.get('Packet Size')} bytes"

                elif evt_type == "SslConnectionInspected" and add_fields:
                    server_name = add_fields.get("server_name", "Unknown Server")
                    version = add_fields.get("version", "")
                    ja3 = add_fields.get("ja3", "")
                    ja4 = add_fields.get("ja4", "")
                    full_net_info += f"\nServer Name: {server_name}"
                    if version:
                        full_net_info += f"\nTLS Version: {version}"
                    if ja3:
                        full_net_info += f"\nJA3: {ja3}"
                    if ja4:
                        full_net_info += f"\nJA4: {ja4}"

                builder.add_or_update_artifact_node(net_node_id, net_node_id, full_net_info, "network", event)
                builder.add_edge(net_actor, net_node_id, evt_type, "#00ffff", evt_type, raw_event=event)

    else:
        builder.unmapped_events.append(evt_type)
        if actor_id and target_id and actor_id != target_id:
            actor_id = builder.get_or_create_process_node(actor_id, actor_name, username, hostname, evt_type, event) or actor_id
            target_id = builder.get_or_create_process_node(target_id, target_name, username, hostname, evt_type, event) or target_id
            builder.add_edge(actor_id, target_id, evt_type, "#a6a6a6", evt_type, raw_event=event)
