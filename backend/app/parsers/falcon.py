import textwrap

from app.parsers.builder import GraphBuilder, as_text, hash_str, string_hash

# CrowdStrike CreateSocket enum values (numeric code -> readable label). Kept
# minimal and defensive: unknown codes fall back to the raw value.
_SOCKET_TYPES = {
    "1": "STREAM",
    "2": "DGRAM",
    "3": "RAW",
    "4": "RDM",
    "5": "SEQPACKET",
    "6": "DCCP",
    "10": "PACKET",
}
_SOCKET_PROTOCOLS = {
    "0": "IP",
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "41": "IPV6",
    "47": "GRE",
    "58": "ICMPV6",
    "255": "UNKNOWN",
}
_CONNECTION_DIRECTIONS = {
    "0": "OUTBOUND",
    "1": "INBOUND",
    "2": "NEITHER",
    "3": "BOTH",
    "4": "UNKNOWN",
}


def _decode_enum(table: dict, value) -> str:
    """Decode a numeric enum to its label, falling back to the raw value."""
    if value in (None, ""):
        return "?"
    return table.get(str(value), str(value))


def parse_falcon_event(builder: GraphBuilder, event: dict, evt_type: str, actor_id: str,
                       actor_name: str, target_id: str, target_name: str, username: str, hostname: str):
    parent_id = event.get("ParentProcessId")
    context_id = event.get("ContextProcessId")
    source_id = event.get("SourceProcessId")

    if evt_type == "ProcessRollup2":
        cmdline = event.get("CommandLine", "No CommandLine")
        image_file = as_text(event.get("ImageFileName",
                               "Unknown Process")).split('\\')[-1]

        if parent_id and target_id:
            source_differs_from_parent = bool(source_id) and str(source_id) != str(parent_id)
            parent_id = builder.get_or_create_process_node(
                parent_id,
                event.get("ParentBaseFileName"),
                username,
                hostname,
                evt_type=evt_type,
                raw_event=event) or parent_id
            target_id = builder.get_or_create_process_node(
                target_id, image_file, username, hostname, evt_type, raw_event=event) or target_id

            builder.add_edge(
                parent_id,
                target_id,
                "Spawns",
                "#ff4d4d",
                evt_type,
                raw_event=event)

            if source_differs_from_parent:
                source_id = builder.get_or_create_process_node(
                    source_id, None, username, hostname, evt_type=evt_type, raw_event=event) or source_id
                builder.add_edge(
                    source_id,
                    target_id,
                    "True Source",
                    "#ff33cc",
                    evt_type,
                    dashed=True,
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

    elif evt_type == "ProcessAncestryInformation":
        base_file = as_text(event.get("BaseFileName", "")).split('\\')[-1]
        p_name = event.get("ParentBaseFileName", "")
        gp_name = event.get("GrandParentBaseFileName", "")
        ggp_name = event.get("GreatGrandParentBaseFileName", "")

        actor_ident = context_id or target_id

        if actor_ident:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, base_file, username, hostname, evt_type, event) or actor_ident

            ancestry_text = (
                f"[{evt_type}]\n"
                f"Process Ancestry Chain:\n"
                f" - Target: {base_file} (PID: {actor_ident})\n"
                f" - Parent: {p_name}\n"
                f" - Grandparent: {gp_name}\n"
                f" - Great-Grandparent: {ggp_name}"
            )
            builder.add_or_update_artifact_node(
                f"ancestry_{actor_ident}",
                "Ancestry Chain",
                ancestry_text,
                "commandline",
                event)
            builder.add_edge(
                actor_ident,
                f"ancestry_{actor_ident}",
                "Ancestry",
                "#a6a6a6",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "AssociateIndicator":
        actor_ident = target_id or context_id
        if actor_ident:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            detect_name = event.get("DetectName", "Unknown Detection")
            severity = event.get("DetectSeverity", "0")
            tactic = event.get("Tactic", "N/A")
            technique = event.get("Technique", "N/A")
            description = event.get(
                "DetectDescription",
                "No description provided.")

            alert_node_id = f"alert_{actor_ident}_{event.get('timestamp')}"
            display_label = f"ALERT: {detect_name}\nSeverity: {severity}"

            wrapped_desc = textwrap.fill(as_text(description), width=60)
            full_info = (f"[{evt_type}]\nDetection: {detect_name}\nSeverity: {severity}\n"
                         f"Tactic: {tactic}\nTechnique: {technique}\n\nDescription:\n{wrapped_desc}")

            builder.add_or_update_artifact_node(
                alert_node_id, display_label, full_info, "alert", event)
            builder.add_edge(
                actor_ident,
                alert_node_id,
                "Triggers Alert",
                "#ff0000",
                evt_type,
                raw_event=event)

    elif evt_type in ["UserLogon", "UserIdentity", "IoSessionLoggedOn"]:
        actor_ident = context_id or source_id
        if actor_ident:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            logon_type = event.get("LogonType", "Unknown")
            domain = event.get("LogonDomain", "")
            user_logon = event.get("UserName", "Unknown")
            auth_pkg = event.get("AuthenticationPackage", "Unknown")
            remote_ip = event.get("RemoteAddressIP4", "")

            logon_node_id = f"logon_{actor_ident}_{event.get('timestamp')}"
            display_label = f"Session: {evt_type}\nType: {logon_type}\n{domain}\\{user_logon}"

            full_info = (f"[{evt_type}]\nUser: {domain}\\{user_logon}\n"
                         f"Logon Type: {logon_type}\nAuth Package: {auth_pkg}")
            if remote_ip:
                full_info += f"\nRemote IP: {remote_ip}"

            builder.add_or_update_artifact_node(
                logon_node_id, display_label, full_info, "commandline", event)
            builder.add_edge(
                actor_ident,
                logon_node_id,
                "Auth Action",
                "#33cc33",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type in [
        "NewScriptWritten", "ScriptFileWrittenInfo", "DirectoryCreate", "CrxFileWritten", "PngFileWritten", "CabFileWritten",
        "DmpFileWritten", "EseFileWritten", "GifFileWritten", "GzipFileWritten", "JpegFileWritten", "LnkFileWritten", "MotwWritten",
        "NewExecutableWritten", "OleFileWritten", "PeFileWritten", "PythonFileWritten", "RegistryHiveFileWritten", "WebScriptFileWritten",
        "ZipFileWritten", "ELFFileWritten", "ADExplorerFileWritten", "AgenticGenericFileWritten", "AppleScriptFileWritten", "ArcFileWritten",
        "ArjFileWritten", "AsifFileWritten", "BZip2FileWritten", "Base64PeFileWritten", "BcmFileWritten", "BlakHoleFileWritten", "BlfFileWritten",
        "BmpFileWritten", "BrotliFileWritten", "CabFileWritten", "CustomIOAFileWrittenDetectionInfoEvent", "DebFileWritten", "DexFileWritten",
        "DmgFileWritten", "DwgFileWritten", "DxfFileWritten", "EmailArchiveFileWritten", "EmailFileWritten", "FileWrittenAndExecutedInContainer",
        "FileWrittenWithEntropyHigh", "FreeArcFileWritten", "GenericFileWritten", "IdwFileWritten", "ImgExtensionFileWritten", "IsoExtensionFileWritten",
        "JarFileWritten", "JavaClassFileWritten", "LRZipFileWritten", "LZ4FileWritten", "LZOFileWritten", "LZipFileWritten", "LhaFileWritten",
        "LzfseFileWritten", "LzmaFileWritten", "MSDocxFileWritten", "MSPptxFileWritten", "MSVsdxFileWritten", "MSXlsxFileWritten", "MachOFileWritten",
        "MsiFileWritten", "OoxmlFileWritten", "PackedExecutableWritten", "PdfFileWritten", "PeaFileWritten", "PemFileWritten", "PngFileWritten",
        "RarFileWritten", "RemovableMediaFileWritten", "RpmFileWritten", "RtfFileWritten", "SevenZipFileWritten", "SldFileWritten", "SourceCodeFileWritten",
        "SuspiciousEseFileWritten", "SuspiciousPeFileWritten", "TarFileWritten", "TiffFileWritten", "UnixFileWritten", "VdiFileWritten", "VmdkFileWritten",
        "XarFileWritten", "XzFileWritten", "Yz1FileWritten", "ZipFileWritten", "ZpaqFileWritten", "ZstdFileWritten"
    ]:
        file_name = as_text(event.get("TargetFileName") or event.get("FileName", ""))

        if context_id and file_name:
            context_id = builder.get_or_create_process_node(
                context_id, actor_name, username, hostname, evt_type, event) or context_id

            clean_path = file_name.replace('\\', '/')
            short_name = clean_path.rstrip('/').split('/')[-1]
            display_file = short_name[:50] + \
                "..." if len(short_name) > 50 else short_name

            safe_file_id = f"file_{string_hash(file_name)}"

            sha256 = event.get("SHA256HashData", "N/A")
            tactic = event.get("Tactic", "N/A")
            technique = event.get("Technique", "N/A")
            file_size = event.get("Size")

            file_info = (f"[{evt_type}]\nFile: {short_name}\nFull Path: {file_name}\n"
                         f"SHA256: {sha256}\nTactic: {tactic}\nTechnique: {technique}")
            if file_size:
                file_info += f"\nSize: {file_size} bytes"

            builder.add_or_update_artifact_node(
                safe_file_id, display_file, file_info, "file", event)
            builder.add_edge(
                context_id,
                safe_file_id,
                evt_type,
                "#4da6ff",
                evt_type,
                raw_event=event)

    elif evt_type == "ExecutableDeleted":
        file_name = as_text(event.get("TargetFileName") or event.get("FileName", ""))
        actor_ident = context_id or source_id
        if actor_ident and file_name:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            clean_path = file_name.replace('\\', '/')
            short_name = clean_path.rstrip('/').split('/')[-1]
            display_file = short_name[:50] + \
                "..." if len(short_name) > 50 else short_name
            safe_file_id = f"file_{string_hash(file_name)}"

            tactic = event.get("Tactic", "N/A")
            technique = event.get("Technique", "N/A")

            file_info = (f"[{evt_type}]\nDeleted File: {short_name}\nFull Path: {file_name}\n"
                         f"Tactic: {tactic}\nTechnique: {technique}")

            builder.add_or_update_artifact_node(
                safe_file_id, display_file, file_info, "file", event)
            builder.add_edge(
                actor_ident,
                safe_file_id,
                "Deletes File",
                "#ff6666",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "SuspiciousCreateSymbolicLink":
        actor_ident = context_id or source_id
        if actor_ident:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            symlink = as_text(event.get("SymbolicLinkName", ""))
            target = event.get("SymbolicLinkTarget", "")
            tactic = event.get("Tactic", "N/A")
            technique = event.get("Technique", "N/A")

            sym_node_id = f"sym_{string_hash(symlink)}"
            display_label = symlink.replace('\\', '/').split('/')[-1]
            display_label = display_label[:50] + \
                "..." if len(display_label) > 50 else display_label

            full_info = (f"[{evt_type}]\nLink: {symlink}\nTarget: {target}\n"
                         f"Tactic: {tactic}\nTechnique: {technique}")

            builder.add_or_update_artifact_node(
                sym_node_id, f"SymLink:\n{display_label}", full_info, "alert", event)
            builder.add_edge(
                actor_ident,
                sym_node_id,
                "Creates SymLink",
                "#ff0000",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type in ["ScheduledTaskModified", "FirewallSetRule", "FirewallDeleteRule"]:
        actor_ident = event.get(
            "RpcClientProcessId") or context_id or source_id
        if actor_ident:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            tactic = event.get("Tactic", "N/A")
            technique = event.get("Technique", "N/A")

            if evt_type == "ScheduledTaskModified":
                task_name = as_text(event.get("TaskName", "Unknown_Task"))
                task_xml = as_text(event.get("TaskXml", ""))
                node_id = f"task_{string_hash(task_name)}"
                clean_task_name = task_name.replace('\\', '/').split('/')[-1]
                display_label = f"Task:\n{clean_task_name}"

                full_info = f"[{evt_type}]\nTask: {task_name}\nTactic: {tactic}\nTechnique: {technique}\n\nXML Snippet:\n{task_xml[:800]}..."
                builder.add_or_update_artifact_node(
                    node_id, display_label, full_info, "commandline", event)
                builder.add_edge(
                    actor_ident,
                    node_id,
                    "Modifies Task",
                    "#ff9933",
                    evt_type,
                    raw_event=event)

            elif evt_type in ["FirewallSetRule", "FirewallDeleteRule"]:
                rule_id = as_text(event.get("FirewallRuleId", "Unknown_Rule"))
                rule_details = event.get("FirewallRule", "")
                node_id = f"fw_{string_hash(rule_id)}"
                display_label = f"FW Rule:\n{rule_id[:30]}"

                full_info = f"[{evt_type}]\nRule ID: {rule_id}\nDetails: {rule_details}\nTactic: {tactic}\nTechnique: {technique}"
                builder.add_or_update_artifact_node(
                    node_id, display_label, full_info, "network", event)

                action_label = "Sets FW Rule" if evt_type == "FirewallSetRule" else "Deletes FW Rule"
                edge_color = "#ff0000" if evt_type == "FirewallDeleteRule" else "#ff9933"
                builder.add_edge(
                    actor_ident,
                    node_id,
                    action_label,
                    edge_color,
                    evt_type,
                    raw_event=event)

    elif evt_type == "DriverLoad":
        driver_path = as_text(event.get("ImageFileName", ""))
        actor_ident = context_id or source_id
        if actor_ident and driver_path:
            short_driver = driver_path.split('\\')[-1]
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            sha256 = event.get("SHA256HashData", "N/A")
            company = event.get("CompanyName", "Unknown Company")

            driver_info = (
                f"[{evt_type}]\nPath: {driver_path}\nCompany: {company}\nSHA256: {sha256}")
            builder.add_or_update_artifact_node(
                driver_path, short_driver, driver_info, "module", event)
            builder.add_edge(
                actor_ident,
                driver_path,
                "Loads Driver",
                "#b366ff",
                evt_type,
                raw_event=event)

    elif evt_type in ["AsepValueUpdate", "RegKeyCommit", "RegValueCommit", "RegSystemConfigValueUpdate"]:
        reg_key = as_text(event.get("RegObjectName", ""))
        reg_value = as_text(event.get("RegValueName", ""))
        actor_ident = context_id or source_id
        if actor_ident and reg_key:
            reg_node_id = f"{reg_key}\\{reg_value}" if reg_value else reg_key
            raw_reg = reg_value if reg_value else reg_key.split('\\')[-1]
            display_reg = raw_reg[:50] + \
                "..." if len(raw_reg) > 50 else raw_reg

            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident
            full_reg_info = f"[{evt_type}]\nKey: {reg_key}\nValue: {reg_value}"

            builder.add_or_update_artifact_node(
                reg_node_id, display_reg, full_reg_info, "registry", event)
            builder.add_edge(
                actor_ident,
                reg_node_id,
                "Reg Update",
                "#ff9933",
                evt_type,
                raw_event=event)

    elif evt_type in ["NetworkReceiveAcceptIP4", "NetworkConnectIP4", "NetworkConnectIP6", "DnsRequest"]:
        remote_ip = event.get("RemoteAddressIP4", "")
        domain = event.get("DomainName", "")

        actor_ident = context_id or source_id

        if actor_ident and (remote_ip or domain):
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            if evt_type == "DnsRequest":
                dns_node_id = f"dns_{domain}"
                ips = event.get("IP4Records", "")
                cnames = event.get("CNAMERecords", "")

                full_dns_info = f"[{evt_type}]\nDomain: {domain}"
                if ips:
                    full_dns_info += f"\nResolved IPs: {ips}"
                if cnames:
                    full_dns_info += f"\nCNAMEs: {cnames}"

                builder.add_or_update_artifact_node(
                    dns_node_id, domain, full_dns_info, "network", event)
                builder.add_edge(
                    actor_ident,
                    dns_node_id,
                    "DNS Query",
                    "#00ffff",
                    evt_type,
                    raw_event=event)
            else:
                remote_port = event.get("RemotePort", "")
                net_node_id = f"{remote_ip}:{remote_port}"
                display_net = f"{remote_ip}:{remote_port}"
                local_ip = event.get("LocalAddressIP4", "")
                local_port = event.get("LocalPort", "")

                full_net_info = f"[{evt_type}]\nRemote: {remote_ip}:{remote_port}\nLocal: {local_ip}:{local_port}"

                builder.add_or_update_artifact_node(
                    net_node_id, display_net, full_net_info, "network", event)
                builder.add_edge(
                    actor_ident,
                    net_node_id,
                    evt_type,
                    "#00ffff",
                    evt_type,
                    raw_event=event)

    elif evt_type in ["NeighborListIP4", "LFODownloadConfirmation", "ModuleCertificateInfo2", "UserLogoff"]:
        host_node_id = f"host_{event.get('ComputerName', 'UnknownHost')}"

        if host_node_id not in builder.nodes_dict:
            builder.add_or_update_artifact_node(
                host_node_id,
                f"Host:\n{
                    event.get(
                        'ComputerName',
                        'Unknown')}",
                "Central Context Node",
                "network",
                event)

        event_hash = string_hash(str(event.get('timestamp', 'time')))
        node_id = f"floating_{evt_type}_{event_hash}"
        tactic = event.get("Tactic", "N/A")
        technique = event.get("Technique", "N/A")

        if evt_type == "NeighborListIP4":
            neighbors = as_text(event.get("NeighborList", "")).replace('|', ' | ')
            info = f"[{evt_type}]\nARP/Neighbor Data:\n{neighbors}\nTactic: {tactic}\nTechnique: {technique}"
            builder.add_or_update_artifact_node(
                node_id, "ARP Neighbor List", info, "network", event)
            builder.add_edge(
                host_node_id,
                node_id,
                "Network Intel",
                "#00ffff",
                evt_type,
                dashed=True,
                raw_event=event)

        elif evt_type == "LFODownloadConfirmation":
            file_name = event.get("TargetFileName", "")
            server = event.get("DownloadServer", "")
            info = f"[{evt_type}]\nDownloaded: {file_name}\nFrom: {server}"
            builder.add_or_update_artifact_node(
                node_id, f"LFO Download:\n{file_name}", info, "file", event)
            builder.add_edge(
                host_node_id,
                node_id,
                "Service Download",
                "#4da6ff",
                evt_type,
                dashed=True,
                raw_event=event)

        elif evt_type == "ModuleCertificateInfo2":
            sha256 = as_text(event.get("SHA256HashData", ""))
            flags = event.get("AuthenticodeSignatureFlags", "")
            info = f"[{evt_type}]\nSHA256: {sha256}\nSignature Flags: {flags}"
            builder.add_or_update_artifact_node(
                node_id, f"Cert Info\n{sha256[:8]}...", info, "module", event)
            builder.add_edge(
                host_node_id,
                node_id,
                "Cert Telemetry",
                "#b366ff",
                evt_type,
                dashed=True,
                raw_event=event)

        elif evt_type == "UserLogoff":
            logon_type = event.get("LogonType", "")
            auth_id = event.get("AuthenticationId", "")
            info = f"[{evt_type}]\nLogon ID: {auth_id}\nType: {logon_type}"
            builder.add_or_update_artifact_node(
                node_id, f"Session End\nID: {auth_id}", info, "commandline", event)
            builder.add_edge(
                host_node_id,
                node_id,
                "Logoff",
                "#a6a6a6",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "CommandHistory":
        cmd_history = as_text(event.get("CommandHistory", ""))
        actor_ident = target_id or context_id
        if actor_ident and cmd_history:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident
            cmd_node_id = f"cmdhist_{actor_ident}_{hash_str(cmd_history)}"
            wrapped_cmd = textwrap.fill(cmd_history, width=60)

            builder.add_or_update_artifact_node(cmd_node_id,
                                                wrapped_cmd,
                                                f"[{evt_type}]\nCommand History:\n{cmd_history}",
                                                "commandline-exec",
                                                event)
            builder.add_edge(
                actor_ident,
                cmd_node_id,
                "History",
                "#c2410c",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "ScriptControlScanInfo":
        # CrowdStrike ScriptControl scan: a process ran/loaded a script. The
        # script is represented as a file artifact (name + hash); the (possibly
        # large) content is only summarised in the title.
        actor_ident = context_id or source_id
        script_name = as_text(event.get("ScriptContentName", ""))
        script_content = as_text(event.get("ScriptContent", ""))
        if actor_ident and (script_name or script_content):
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            sha256 = as_text(event.get("ContentSHA256HashData", "N/A"))
            short = script_name.replace("\\", "/").split("/")[-1] or "script"
            script_node_id = f"script_{string_hash(script_name or script_content)}"
            snippet = (
                script_content[:200] + "…" if len(script_content) > 200 else script_content
            )
            script_info = f"[{evt_type}]\nScript: {script_name}\nSHA256: {sha256}"
            if snippet:
                script_info += f"\nContent:\n{snippet}"

            builder.add_or_update_artifact_node(
                script_node_id, short, script_info, "file", event)
            builder.add_edge(
                actor_ident,
                script_node_id,
                "Runs Script",
                "#4da6ff",
                evt_type,
                dashed=True,
                raw_event=event)

    elif evt_type == "CreateSocket":
        # A process opened a socket. There is no remote endpoint, so the socket
        # is represented as a network artifact keyed by the owning process and
        # its (family, type, protocol) description.
        actor_ident = context_id or source_id
        if actor_ident:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            family = as_text(event.get("AddressFamily", "?")) or "?"
            socket_type = _decode_enum(_SOCKET_TYPES, event.get("SocketType"))
            protocol = _decode_enum(_SOCKET_PROTOCOLS, event.get("Protocol"))
            socket_node_id = f"socket_{string_hash(f'{actor_ident}|{family}|{socket_type}|{protocol}')}"
            label = f"Socket: {protocol}/{socket_type}"
            socket_info = (
                f"[{evt_type}]\nAddress Family: {family}\n"
                f"Socket Type: {socket_type}\nProtocol: {protocol}"
            )

            builder.add_or_update_artifact_node(
                socket_node_id, label, socket_info, "network", event)
            builder.add_edge(
                actor_ident,
                socket_node_id,
                "Creates Socket",
                "#00ffff",
                evt_type,
                raw_event=event)

    elif evt_type == "CriticalFileAccessed":
        # A process accessed a critical file. The file shares the same id scheme
        # as the other file events, so reads/writes/modifications of the same
        # path collapse into one node.
        actor_ident = context_id or source_id
        file_name = as_text(event.get("TargetFileName") or event.get("FileName", ""))
        if actor_ident and file_name:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            clean_path = file_name.replace("\\", "/")
            short_name = clean_path.rstrip("/").split("/")[-1]
            display_file = short_name[:50] + "..." if len(short_name) > 50 else short_name

            file_node_id = f"file_{string_hash(file_name)}"
            uid = as_text(event.get("UID", ""))
            gid = as_text(event.get("GID", ""))
            unix_mode = as_text(event.get("UnixMode", ""))
            file_info = f"[{evt_type}]\nFile: {file_name}"
            if uid:
                file_info += f"\nUID: {uid}"
            if gid:
                file_info += f"\nGID: {gid}"
            if unix_mode:
                file_info += f"\nUnix Mode: {unix_mode}"

            builder.add_or_update_artifact_node(
                file_node_id, display_file, file_info, "file", event)
            builder.add_edge(
                actor_ident,
                file_node_id,
                "Accesses Critical File",
                "#ff4d4d",
                evt_type,
                raw_event=event)

    elif evt_type == "NetworkLinkConfigGetAddress":
        # Only carries the originating process: register the node (and its
        # action/raw logs) so the event is mapped rather than unmapped.
        actor_ident = context_id or source_id
        if actor_ident:
            builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event)

    elif evt_type == "CriticalEnvironmentVariableChanged":
        actor_ident = context_id or source_id
        env_name = as_text(event.get("EnvironmentVariableName", ""))
        env_value = as_text(event.get("EnvironmentVariableValue", ""))
        if actor_ident and env_name:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            env_node_id = f"env_{string_hash(env_name)}"
            env_info = f"[{evt_type}]\nName: {env_name}\nValue: {env_value}"
            builder.add_or_update_artifact_node(
                env_node_id, f"Env: {env_name}", env_info, "registry", event)
            builder.add_edge(
                actor_ident,
                env_node_id,
                "Sets Env Var",
                "#ff9933",
                evt_type,
                raw_event=event)

    elif evt_type == "NetworkListenIP4":
        # A process opened a socket in listening mode; the endpoint is local.
        actor_ident = context_id or source_id
        local_ip = as_text(event.get("LocalAddressIP4", ""))
        local_port = as_text(event.get("LocalPort", ""))
        if actor_ident and (local_ip or local_port):
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident

            endpoint = f"{local_ip}:{local_port}" if local_port else local_ip
            protocol = _decode_enum(_SOCKET_PROTOCOLS, event.get("Protocol"))
            direction = _decode_enum(_CONNECTION_DIRECTIONS, event.get("ConnectionDirection"))
            listen_info = (
                f"[{evt_type}]\nLocal: {endpoint}\n"
                f"Protocol: {protocol}\nDirection: {direction}"
            )
            builder.add_or_update_artifact_node(
                endpoint, f"Listen {endpoint}", listen_info, "network", event)
            builder.add_edge(
                actor_ident,
                endpoint,
                "Listens On",
                "#00ffff",
                evt_type,
                raw_event=event)

    else:
        builder.unmapped_events.append(evt_type)
        actor_ident = context_id or source_id or parent_id
        if actor_ident and target_id and actor_ident != target_id:
            actor_ident = builder.get_or_create_process_node(
                actor_ident, actor_name, username, hostname, evt_type, event) or actor_ident
            target_id = builder.get_or_create_process_node(
                target_id, target_name, username, hostname, evt_type, event) or target_id
            builder.add_edge(
                actor_ident,
                target_id,
                evt_type,
                "#a6a6a6",
                evt_type,
                raw_event=event)
