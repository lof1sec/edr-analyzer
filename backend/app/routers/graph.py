import json
import hashlib
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import LogEvent, Dataset
import textwrap

router = APIRouter(prefix="/api/graph", tags=["Graph"])

def get_additional_fields_dict(event_data):
    fields = event_data.get("AdditionalFields", "")
    if isinstance(fields, dict):
        return fields
    if isinstance(fields, str) and fields.strip().startswith("{"):
        try:
            return json.loads(fields)
        except json.JSONDecodeError:
            pass
    return {}

def hash_str(val: str) -> str:
    return hashlib.md5(str(val).encode('utf-8')).hexdigest()[:10]

@router.get("/{dataset_id}")
def generate_graph(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    logs = db.query(LogEvent).filter(LogEvent.dataset_id == dataset_id).all()

    nodes_dict = {}
    edges_list = []

    # Helper for adding/updating process nodes
    def get_or_create_process_node(pid, name=None, username=None, evt_type=None, raw_event=None):
        if not pid: return
        pid = str(pid)

        display_name = name if name else "Unknown"
        label = f"{display_name}\n{pid}" if name else f"Process ID:\n{pid}"
        if username:
            icon = "💻" if str(username).endswith("$") else "👤"
            label += f"\n{icon} {username}"

        title = f"Process Name: {display_name}\nPID: {pid}"
        if username:
            icon = "💻" if str(username).endswith("$") else "👤"
            title += f"\nUser: {icon} {username}"

        if pid not in nodes_dict:
            actions_list = [evt_type] if evt_type else []
            if actions_list:
                title += f"\n\nObserved Actions:\n[{'], ['.join(actions_list)}]"

            nodes_dict[pid] = {
                "id": pid,
                "label": label,
                "group": "process",
                "title": title,
                "username": username,
                "process_name": name,
                "actions": actions_list,
                "raw_logs": [raw_event] if raw_event else []
            }
        else:
            node = nodes_dict[pid]
            current_label = node.get("label", "")
            current_username = node.get("username")
            current_title = node.get("title", "")
            current_name = node.get("process_name")
            actions_list = node.get("actions", [])

            if raw_event:
                node["raw_logs"].append(raw_event)

            if evt_type and evt_type not in actions_list:
                actions_list.append(evt_type)
                node["actions"] = actions_list
                if "\n\nObserved Actions:" in current_title:
                    base_title = current_title.split("\n\nObserved Actions:")[0]
                    node["title"] = base_title + f"\n\nObserved Actions:\n[{'], ['.join(actions_list)}]"
                else:
                    node["title"] = current_title + f"\n\nObserved Actions:\n[{'], ['.join(actions_list)}]"
                current_title = node["title"]

            if name and not current_name:
                node["process_name"] = name
                if current_label.startswith("Process ID:"):
                    node["label"] = current_label.replace("Process ID:", name, 1)
                if "Process Name: Unknown" in current_title:
                    node["title"] = current_title.replace("Process Name: Unknown", f"Process Name: {name}", 1)

            if username and not current_username:
                node["username"] = username
                icon = "💻" if str(username).endswith("$") else "👤"
                if "👤" not in node["label"] and "💻" not in node["label"]:
                    node["label"] += f"\n{icon} {username}"
                if "User:" not in current_title:
                    parts = current_title.split('\n\nObserved Actions:')
                    if len(parts) > 1:
                        node["title"] = parts[0] + f"\nUser: {icon} {username}\n\nObserved Actions:" + parts[1]
                    else:
                        node["title"] += f"\nUser: {icon} {username}"

    # Helper for adding/updating artifact nodes
    def add_or_update_artifact_node(node_id, label, new_details, group, raw_event=None):
        if not node_id: return
        node_id = str(node_id)

        if node_id not in nodes_dict:
            nodes_dict[node_id] = {
                "id": node_id,
                "label": label,
                "group": group,
                "title": new_details,
                "raw_logs": [raw_event] if raw_event else []
            }
        else:
            current_title = nodes_dict[node_id].get("title", "")
            if raw_event:
                nodes_dict[node_id].setdefault("raw_logs", []).append(raw_event)

            if new_details not in current_title:
                separator = "\n\n" + "="*40 + "\n\n"
                new_title = f"{current_title}{separator}{new_details}" if current_title else new_details
                nodes_dict[node_id]["title"] = new_title

    def add_edge(source, target, label, color, event_simplename, dashed=False, raw_event=None):
        source_str = str(source)
        target_str = str(target)
        edges_list.append({
            "source": source_str,
            "target": target_str,
            "label": label,
            "color": color,
            "event_simplename": event_simplename,
            "dashed": dashed,
            "id": f"{source_str}_{target_str}_{hash_str(label)}_{hash_str(event_simplename)}_{hash_str(str(raw_event))}",
            "raw_logs": [raw_event] if raw_event else []
        })

    # Process all logs
    for log in logs:
        event = log.data
        evt_type = log.event_type

        # Check if this is a CrowdStrike Falcon event (presence of #event_simpleName)
        is_falcon = "#event_simpleName" in event

        # Normalization of fields
        if is_falcon:
            actor_id = event.get("ContextProcessId") or event.get("SourceProcessId") or event.get("ParentProcessId")
            actor_name = event.get("ContextBaseFileName") or event.get("ParentBaseFileName")

            target_id = event.get("TargetProcessId")
            target_name = event.get("FileName") or event.get("TargetFileName", "")

            username = event.get("UserName", "Unknown")
            if not actor_id and target_id:
               actor_id = target_id
        else:
            actor_id = event.get("InitiatingProcessId")
            actor_name = event.get("InitiatingProcessFileName")
            target_id = event.get("ProcessId")
            target_name = event.get("FileName")

            domain = event.get("AccountDomain", "")
            user = event.get("AccountName", "Unknown")
            username = f"{domain}\\{user}" if domain and user != "Unknown" else user

        # --- FALCON EVENT LOGIC ---
        if is_falcon:
            parent_id = event.get("ParentProcessId")
            context_id = event.get("ContextProcessId")
            source_id = event.get("SourceProcessId")

            if evt_type == "ProcessRollup2":
                cmdline = event.get("CommandLine", "No CommandLine")
                image_file = event.get("ImageFileName", "Unknown Process").split('\\')[-1]

                if parent_id and target_id:
                    get_or_create_process_node(parent_id, event.get("ParentBaseFileName"), evt_type=evt_type, raw_event=event)
                    get_or_create_process_node(target_id, image_file, username, evt_type, raw_event=event)

                    add_edge(parent_id, target_id, "Spawns", "#ff4d4d", evt_type, raw_event=event)

                    if source_id and source_id != parent_id:
                        get_or_create_process_node(source_id, evt_type=evt_type, raw_event=event)
                        add_edge(source_id, target_id, "True Source", "#ff33cc", evt_type, dashed=True, raw_event=event)

                    if cmdline and cmdline != "No CommandLine":
                        cmd_node_id = f"cmd_{target_id}"
                        wrapped_cmd = textwrap.fill(cmdline, width=60)

                        add_or_update_artifact_node(cmd_node_id, wrapped_cmd, f"[{evt_type}]\nRaw Command Line:\n{cmdline}", "commandline", event)
                        add_edge(target_id, cmd_node_id, "Args", "#ffcc00", evt_type, dashed=True, raw_event=event)

            elif evt_type == "ProcessAncestryInformation":
                base_file = event.get("BaseFileName", "").split('\\')[-1]
                p_name = event.get("ParentBaseFileName", "")
                gp_name = event.get("GrandParentBaseFileName", "")
                ggp_name = event.get("GreatGrandParentBaseFileName", "")

                actor_ident = context_id or target_id

                if actor_ident:
                    get_or_create_process_node(actor_ident, base_file, username, evt_type, event)

                    ancestry_text = (
                        f"[{evt_type}]\n"
                        f"Process Ancestry Chain:\n"
                        f" - Target: {base_file} (PID: {actor_ident})\n"
                        f" - Parent: {p_name}\n"
                        f" - Grandparent: {gp_name}\n"
                        f" - Great-Grandparent: {ggp_name}"
                    )
                    add_or_update_artifact_node(f"ancestry_{actor_ident}", "Ancestry Chain", ancestry_text, "commandline", event)
                    add_edge(actor_ident, f"ancestry_{actor_ident}", "Ancestry", "#a6a6a6", evt_type, dashed=True, raw_event=event)

            elif evt_type == "AssociateIndicator":
                actor_ident = target_id or context_id
                if actor_ident:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    detect_name = event.get("DetectName", "Unknown Detection")
                    severity = event.get("DetectSeverity", "0")
                    tactic = event.get("Tactic", "N/A")
                    technique = event.get("Technique", "N/A")
                    description = event.get("DetectDescription", "No description provided.")

                    alert_node_id = f"alert_{actor_ident}_{event.get('timestamp')}"
                    display_label = f"ALERT: {detect_name}\nSeverity: {severity}"

                    wrapped_desc = textwrap.fill(description, width=60)
                    full_info = (f"[{evt_type}]\nDetection: {detect_name}\nSeverity: {severity}\n"
                                 f"Tactic: {tactic}\nTechnique: {technique}\n\nDescription:\n{wrapped_desc}")

                    add_or_update_artifact_node(alert_node_id, display_label, full_info, "alert", event)
                    add_edge(actor_ident, alert_node_id, "Triggers Alert", "#ff0000", evt_type, raw_event=event)

            elif evt_type in ["UserLogon", "UserIdentity", "IoSessionLoggedOn"]:
                actor_ident = context_id or source_id
                if actor_ident:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    logon_type = event.get("LogonType", "Unknown")
                    domain = event.get("LogonDomain", "")
                    user_logon = event.get("UserName", "Unknown")
                    auth_pkg = event.get("AuthenticationPackage", "Unknown")
                    remote_ip = event.get("RemoteAddressIP4", "")

                    logon_node_id = f"logon_{actor_ident}_{event.get('timestamp')}"
                    display_label = f"Session: {evt_type}\nType: {logon_type}\n{domain}\\{user_logon}"

                    full_info = (f"[{evt_type}]\nUser: {domain}\\{user_logon}\n"
                                 f"Logon Type: {logon_type}\nAuth Package: {auth_pkg}")
                    if remote_ip: full_info += f"\nRemote IP: {remote_ip}"

                    add_or_update_artifact_node(logon_node_id, display_label, full_info, "commandline", event)
                    add_edge(actor_ident, logon_node_id, "Auth Action", "#33cc33", evt_type, dashed=True, raw_event=event)

            elif evt_type in [
                "NewScriptWritten", "ScriptFileWrittenInfo", "DirectoryCreate", "CrxFileWritten", "PngFileWritten","CabFileWritten",
                "DmpFileWritten","EseFileWritten","GifFileWritten","GzipFileWritten","JpegFileWritten","LnkFileWritten","MotwWritten",
                "NewExecutableWritten","OleFileWritten","PeFileWritten","PythonFileWritten","RegistryHiveFileWritten","WebScriptFileWritten",
                "ZipFileWritten","ELFFileWritten","ADExplorerFileWritten","AgenticGenericFileWritten","AppleScriptFileWritten","ArcFileWritten",
                "ArjFileWritten","AsifFileWritten","BZip2FileWritten","Base64PeFileWritten","BcmFileWritten","BlakHoleFileWritten","BlfFileWritten",
                "BmpFileWritten","BrotliFileWritten","CabFileWritten","CustomIOAFileWrittenDetectionInfoEvent","DebFileWritten","DexFileWritten",
                "DmgFileWritten","DwgFileWritten","DxfFileWritten","EmailArchiveFileWritten","EmailFileWritten","FileWrittenAndExecutedInContainer",
                "FileWrittenWithEntropyHigh","FreeArcFileWritten","GenericFileWritten","IdwFileWritten","ImgExtensionFileWritten","IsoExtensionFileWritten",
                "JarFileWritten","JavaClassFileWritten","LRZipFileWritten","LZ4FileWritten","LZOFileWritten","LZipFileWritten","LhaFileWritten",
                "LzfseFileWritten","LzmaFileWritten","MSDocxFileWritten","MSPptxFileWritten","MSVsdxFileWritten","MSXlsxFileWritten","MachOFileWritten",
                "MsiFileWritten","OoxmlFileWritten","PackedExecutableWritten","PdfFileWritten","PeaFileWritten","PemFileWritten","PngFileWritten",
                "RarFileWritten","RemovableMediaFileWritten","RpmFileWritten","RtfFileWritten","SevenZipFileWritten","SldFileWritten","SourceCodeFileWritten",
                "SuspiciousEseFileWritten","SuspiciousPeFileWritten","TarFileWritten","TiffFileWritten","UnixFileWritten","VdiFileWritten","VmdkFileWritten",
                "XarFileWritten","XzFileWritten","Yz1FileWritten","ZipFileWritten","ZpaqFileWritten","ZstdFileWritten"
            ]:
                file_name = event.get("TargetFileName") or event.get("FileName", "")

                if context_id and file_name:
                    get_or_create_process_node(context_id, actor_name, username, evt_type, event)

                    clean_path = file_name.replace('\\', '/')
                    short_name = clean_path.rstrip('/').split('/')[-1]
                    display_file = short_name[:50] + "..." if len(short_name) > 50 else short_name

                    safe_file_id = f"file_{abs(hash(file_name))}"

                    sha256 = event.get("SHA256HashData", "N/A")
                    tactic = event.get("Tactic", "N/A")
                    technique = event.get("Technique", "N/A")
                    file_size = event.get("Size")

                    file_info = (f"[{evt_type}]\nFile: {short_name}\nFull Path: {file_name}\n"
                                 f"SHA256: {sha256}\nTactic: {tactic}\nTechnique: {technique}")
                    if file_size: file_info += f"\nSize: {file_size} bytes"

                    add_or_update_artifact_node(safe_file_id, display_file, file_info, "file", event)
                    add_edge(context_id, safe_file_id, evt_type, "#4da6ff", evt_type, raw_event=event)

            elif evt_type == "ExecutableDeleted":
                file_name = event.get("TargetFileName") or event.get("FileName", "")
                actor_ident = context_id or source_id
                if actor_ident and file_name:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    clean_path = file_name.replace('\\', '/')
                    short_name = clean_path.rstrip('/').split('/')[-1]
                    display_file = short_name[:50] + "..." if len(short_name) > 50 else short_name
                    safe_file_id = f"file_{abs(hash(file_name))}"

                    tactic = event.get("Tactic", "N/A")
                    technique = event.get("Technique", "N/A")

                    file_info = (f"[{evt_type}]\nDeleted File: {short_name}\nFull Path: {file_name}\n"
                                 f"Tactic: {tactic}\nTechnique: {technique}")

                    add_or_update_artifact_node(safe_file_id, display_file, file_info, "file", event)
                    add_edge(actor_ident, safe_file_id, "Deletes File", "#ff6666", evt_type, dashed=True, raw_event=event)

            elif evt_type == "SuspiciousCreateSymbolicLink":
                actor_ident = context_id or source_id
                if actor_ident:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    symlink = event.get("SymbolicLinkName", "")
                    target = event.get("SymbolicLinkTarget", "")
                    tactic = event.get("Tactic", "N/A")
                    technique = event.get("Technique", "N/A")

                    sym_node_id = f"sym_{abs(hash(symlink))}"
                    display_label = symlink.replace('\\', '/').split('/')[-1]
                    display_label = display_label[:50] + "..." if len(display_label) > 50 else display_label

                    full_info = (f"[{evt_type}]\nLink: {symlink}\nTarget: {target}\n"
                                 f"Tactic: {tactic}\nTechnique: {technique}")

                    add_or_update_artifact_node(sym_node_id, f"SymLink:\n{display_label}", full_info, "alert", event)
                    add_edge(actor_ident, sym_node_id, "Creates SymLink", "#ff0000", evt_type, dashed=True, raw_event=event)

            elif evt_type in ["ScheduledTaskModified", "FirewallSetRule", "FirewallDeleteRule"]:
                actor_ident = event.get("RpcClientProcessId") or context_id or source_id
                if actor_ident:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    tactic = event.get("Tactic", "N/A")
                    technique = event.get("Technique", "N/A")

                    if evt_type == "ScheduledTaskModified":
                        task_name = event.get("TaskName", "Unknown_Task")
                        task_xml = event.get("TaskXml", "")
                        node_id = f"task_{abs(hash(task_name))}"
                        display_label = f"Task:\n{task_name.replace('\\', '/').split('/')[-1]}"

                        full_info = f"[{evt_type}]\nTask: {task_name}\nTactic: {tactic}\nTechnique: {technique}\n\nXML Snippet:\n{task_xml[:800]}..."
                        add_or_update_artifact_node(node_id, display_label, full_info, "commandline", event)
                        add_edge(actor_ident, node_id, "Modifies Task", "#ff9933", evt_type, raw_event=event)

                    elif evt_type in ["FirewallSetRule", "FirewallDeleteRule"]:
                        rule_id = event.get("FirewallRuleId", "Unknown_Rule")
                        rule_details = event.get("FirewallRule", "")
                        node_id = f"fw_{abs(hash(rule_id))}"
                        display_label = f"FW Rule:\n{rule_id[:30]}"

                        full_info = f"[{evt_type}]\nRule ID: {rule_id}\nDetails: {rule_details}\nTactic: {tactic}\nTechnique: {technique}"
                        add_or_update_artifact_node(node_id, display_label, full_info, "network", event)

                        action_label = "Sets FW Rule" if evt_type == "FirewallSetRule" else "Deletes FW Rule"
                        edge_color = "#ff0000" if evt_type == "FirewallDeleteRule" else "#ff9933"
                        add_edge(actor_ident, node_id, action_label, edge_color, evt_type, raw_event=event)

            elif evt_type == "DriverLoad":
                driver_path = event.get("ImageFileName", "")
                actor_ident = context_id or source_id
                if actor_ident and driver_path:
                    short_driver = driver_path.split('\\')[-1]
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    sha256 = event.get("SHA256HashData", "N/A")
                    company = event.get("CompanyName", "Unknown Company")

                    driver_info = (f"[{evt_type}]\nPath: {driver_path}\nCompany: {company}\nSHA256: {sha256}")
                    add_or_update_artifact_node(driver_path, short_driver, driver_info, "module", event)
                    add_edge(actor_ident, driver_path, "Loads Driver", "#b366ff", evt_type, raw_event=event)

            elif evt_type in ["AsepValueUpdate", "RegKeyCommit", "RegValueCommit", "RegSystemConfigValueUpdate"]:
                reg_key = event.get("RegObjectName", "")
                reg_value = event.get("RegValueName", "")
                actor_ident = context_id or source_id
                if actor_ident and reg_key:
                    reg_node_id = f"{reg_key}\\{reg_value}" if reg_value else reg_key
                    raw_reg = reg_value if reg_value else reg_key.split('\\')[-1]
                    display_reg = raw_reg[:50] + "..." if len(raw_reg) > 50 else raw_reg

                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)
                    full_reg_info = f"[{evt_type}]\nKey: {reg_key}\nValue: {reg_value}"

                    add_or_update_artifact_node(reg_node_id, display_reg, full_reg_info, "registry", event)
                    add_edge(actor_ident, reg_node_id, "Reg Update", "#ff9933", evt_type, raw_event=event)

            elif evt_type in ["NetworkReceiveAcceptIP4", "NetworkConnectIP4", "NetworkConnectIP6", "DnsRequest"]:
                remote_ip = event.get("RemoteAddressIP4", "")
                domain = event.get("DomainName", "")
                actor_ident = context_id or source_id

                if actor_ident and (remote_ip or domain):
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)

                    if evt_type == "DnsRequest":
                        dns_node_id = f"dns_{domain}"
                        ips = event.get("IP4Records", "")
                        cnames = event.get("CNAMERecords", "")
                        full_dns_info = f"[{evt_type}]\nDomain: {domain}"
                        if ips: full_dns_info += f"\nResolved IPs: {ips}"
                        if cnames: full_dns_info += f"\nCNAMEs: {cnames}"

                        add_or_update_artifact_node(dns_node_id, domain, full_dns_info, "network", event)
                        add_edge(actor_ident, dns_node_id, "DNS Query", "#00ffff", evt_type, raw_event=event)
                    else:
                        remote_port = event.get("RemotePort", "")
                        net_node_id = f"{remote_ip}:{remote_port}"
                        display_net = f"{remote_ip}:{remote_port}"
                        local_ip = event.get("LocalAddressIP4", "")
                        local_port = event.get("LocalPort", "")

                        full_net_info = f"[{evt_type}]\nRemote: {remote_ip}:{remote_port}\nLocal: {local_ip}:{local_port}"
                        add_or_update_artifact_node(net_node_id, display_net, full_net_info, "network", event)
                        add_edge(actor_ident, net_node_id, evt_type, "#00ffff", evt_type, raw_event=event)

            elif evt_type in ["NeighborListIP4", "LFODownloadConfirmation", "ModuleCertificateInfo2", "UserLogoff"]:
                host_node_id = f"host_{event.get('ComputerName', 'UnknownHost')}"

                if host_node_id not in nodes_dict:
                    add_or_update_artifact_node(host_node_id, f"Host:\n{event.get('ComputerName', 'Unknown')}", "Central Context Node", "network", event)

                event_hash = abs(hash(event.get('timestamp', 'time')))
                node_id = f"floating_{evt_type}_{event_hash}"
                tactic = event.get("Tactic", "N/A")
                technique = event.get("Technique", "N/A")

                if evt_type == "NeighborListIP4":
                    neighbors = event.get("NeighborList", "").replace('|', ' | ')
                    info = f"[{evt_type}]\nARP/Neighbor Data:\n{neighbors}\nTactic: {tactic}\nTechnique: {technique}"
                    add_or_update_artifact_node(node_id, "ARP Neighbor List", info, "network", event)
                    add_edge(host_node_id, node_id, "Network Intel", "#00ffff", evt_type, dashed=True, raw_event=event)

                elif evt_type == "LFODownloadConfirmation":
                    file_name = event.get("TargetFileName", "")
                    server = event.get("DownloadServer", "")
                    info = f"[{evt_type}]\nDownloaded: {file_name}\nFrom: {server}"
                    add_or_update_artifact_node(node_id, f"LFO Download:\n{file_name}", info, "file", event)
                    add_edge(host_node_id, node_id, "Service Download", "#4da6ff", evt_type, dashed=True, raw_event=event)

                elif evt_type == "ModuleCertificateInfo2":
                    sha256 = event.get("SHA256HashData", "")
                    flags = event.get("AuthenticodeSignatureFlags", "")
                    info = f"[{evt_type}]\nSHA256: {sha256}\nSignature Flags: {flags}"
                    add_or_update_artifact_node(node_id, f"Cert Info\n{sha256[:8]}...", info, "module", event)
                    add_edge(host_node_id, node_id, "Cert Telemetry", "#b366ff", evt_type, dashed=True, raw_event=event)

                elif evt_type == "UserLogoff":
                    logon_type = event.get("LogonType", "")
                    auth_id = event.get("AuthenticationId", "")
                    info = f"[{evt_type}]\nLogon ID: {auth_id}\nType: {logon_type}"
                    add_or_update_artifact_node(node_id, f"Session End\nID: {auth_id}", info, "commandline", event)
                    add_edge(host_node_id, node_id, "Logoff", "#a6a6a6", evt_type, dashed=True, raw_event=event)

            elif evt_type == "CommandHistory":
                cmd_history = event.get("CommandHistory", "")
                actor_ident = target_id or context_id
                if actor_ident and cmd_history:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)
                    cmd_node_id = f"cmdhist_{actor_ident}_{hash_str(cmd_history)}"
                    wrapped_cmd = textwrap.fill(cmd_history, width=60)

                    add_or_update_artifact_node(cmd_node_id, wrapped_cmd, f"[{evt_type}]\nCommand History:\n{cmd_history}", "commandline", event)
                    add_edge(actor_ident, cmd_node_id, "History", "#ffcc00", evt_type, dashed=True, raw_event=event)

            else:
                actor_ident = context_id or source_id or parent_id
                if actor_ident and target_id and actor_ident != target_id:
                    get_or_create_process_node(actor_ident, actor_name, username, evt_type, event)
                    get_or_create_process_node(target_id, target_name, username, evt_type, event)
                    add_edge(actor_ident, target_id, evt_type, "#a6a6a6", evt_type, raw_event=event)
            continue

        # --- DEFENDER EVENT LOGIC ---
        if evt_type == "ProcessCreated":
            cmdline = event.get("ProcessCommandLine", "No CommandLine")
            if actor_id and target_id:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                get_or_create_process_node(target_id, target_name, username, evt_type, event)
                add_edge(actor_id, target_id, "Spawns", "#ff4d4d", evt_type, raw_event=event)

                if cmdline and cmdline != "No CommandLine":
                    cmd_node_id = f"cmd_{target_id}"
                    wrapped_cmd = textwrap.fill(cmdline, width=60)
                    add_or_update_artifact_node(cmd_node_id, wrapped_cmd, f"[{evt_type}]\nRaw Command Line:\n{cmdline}", "commandline", event)
                    add_edge(target_id, cmd_node_id, "Args", "#ffcc00", evt_type, dashed=True, raw_event=event)

        elif evt_type == "PowerShellCommand":
            add_fields = get_additional_fields_dict(event)
            ps_command = add_fields.get("Command") or str(event.get("AdditionalFields", ""))
            if actor_id and ps_command:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                cmd_node_id = f"pscmd_{actor_id}_{hash_str(ps_command)}"
                wrapped_cmd = textwrap.fill(ps_command, width=60)
                add_or_update_artifact_node(cmd_node_id, wrapped_cmd, f"[{evt_type}]\nRaw PowerShell Command:\n{ps_command}", "commandline", event)
                add_edge(actor_id, cmd_node_id, "Executes PS", "#ffcc00", evt_type, dashed=True, raw_event=event)

        elif evt_type == "ClrUnbackedModuleLoaded":
            add_fields = get_additional_fields_dict(event)
            module_name = add_fields.get("ModuleILPathOrName", "Unbacked CLR Assembly")
            if actor_id:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                clr_node_id = f"clr_{actor_id}_{hash_str(module_name)}"
                display_clr = f"Unbacked CLR\n{module_name[:30]}"
                clr_info = f"[{evt_type}]\nAssembly / Module Name: {module_name}\nDetails:\n{event.get('AdditionalFields', '')}"
                add_or_update_artifact_node(clr_node_id, display_clr, clr_info, "module", event)
                add_edge(actor_id, clr_node_id, "Loads Unbacked CLR", "#b366ff", evt_type, dashed=True, raw_event=event)

        elif evt_type == "LdapSearch":
            add_fields = get_additional_fields_dict(event)
            search_filter = add_fields.get("SearchFilter", "Unknown Filter")
            attributes = str(add_fields.get("AttributeList", ""))
            if actor_id:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                ldap_node_id = f"ldap_{actor_id}_{hash_str(search_filter)}"
                display_ldap = f"LDAP Search\n{search_filter[:30]}..." if len(search_filter) > 30 else f"LDAP Search\n{search_filter}"
                ldap_info = f"[{evt_type}]\nFilter: {search_filter}\nAttributes: {attributes}"
                add_or_update_artifact_node(ldap_node_id, display_ldap, ldap_info, "commandline", event)
                add_edge(actor_id, ldap_node_id, "LDAP Query", "#ffcc00", evt_type, dashed=True, raw_event=event)

        elif evt_type in ["PnpDeviceAllowed", "PnpDeviceConnected"]:
            add_fields = get_additional_fields_dict(event)
            device_id = add_fields.get("DeviceInstanceId", "Unknown Device")
            driver_name = add_fields.get("DriverName", "Unknown Driver")
            pnp_actor = actor_id if actor_id else "SYSTEM_PNP"
            pnp_actor_name = actor_name if actor_id else "Plug and Play Manager"
            get_or_create_process_node(pnp_actor, pnp_actor_name, username, evt_type, event)
            pnp_node_id = f"pnp_{hash_str(device_id)}"
            display_pnp = f"PnP Device\n{driver_name}"
            pnp_info = f"[{evt_type}]\nDevice ID: {device_id}\nDriver: {driver_name}\nDetails: {event.get('AdditionalFields', '')}"
            add_or_update_artifact_node(pnp_node_id, display_pnp, pnp_info, "module", event)
            add_edge(pnp_actor, pnp_node_id, "Loads Device", "#b366ff", evt_type, dashed=True, raw_event=event)

        elif evt_type == "GetClipboardData":
            if actor_id:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                clip_node_id = f"clip_{actor_id}"
                clip_info = f"[{evt_type}]\nProcess accessed system clipboard contents."
                add_or_update_artifact_node(clip_node_id, "📋 Clipboard Data", clip_info, "commandline", event)
                add_edge(actor_id, clip_node_id, "Reads Clipboard", "#ffcc00", evt_type, dashed=True, raw_event=event)

        elif evt_type == "ProcessCreatedUsingWmiQuery":
            add_fields = get_additional_fields_dict(event)
            client_machine = add_fields.get("ClientMachine", "Local")
            wmi_actor = actor_id if actor_id else "WMI_Subsystem"
            wmi_actor_name = actor_name if actor_id else "WMI Engine"
            get_or_create_process_node(wmi_actor, wmi_actor_name, username, evt_type, event)
            wmi_node_id = f"wmi_query_{hash_str(str(add_fields))}"
            wmi_info = f"[{evt_type}]\nClient Machine: {client_machine}\nDetails:\n{event.get('AdditionalFields', '')}"
            add_or_update_artifact_node(wmi_node_id, f"WMI Query\n({client_machine})", wmi_info, "commandline", event)
            add_edge(wmi_actor, wmi_node_id, "WMI Query", "#ffcc00", evt_type, dashed=True, raw_event=event)

        elif evt_type == "NamedPipeEvent":
            add_fields = get_additional_fields_dict(event)
            pipe_name = add_fields.get("PipeName")
            file_op = add_fields.get("FileOperation", "NamedPipeEvent")
            if actor_id and pipe_name:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                display_pipe = pipe_name.split('\\')[-1] if '\\' in pipe_name else pipe_name
                if len(display_pipe) > 50: display_pipe = display_pipe[:50] + "..."
                pipe_info = f"[{evt_type}]\nPipe Name: {pipe_name}\nOperation: {file_op}"
                add_or_update_artifact_node(pipe_name, display_pipe, pipe_info, "file", event)
                add_edge(actor_id, pipe_name, file_op, "#4da6ff", evt_type, dashed=True, raw_event=event)

        elif evt_type == "DpapiAccessed":
            add_fields = get_additional_fields_dict(event)
            operation_type = add_fields.get("OperationType", "Unknown DPAPI Op")
            master_key_guid = add_fields.get("MasterKeyGUID", "Unknown GUID")
            flags = add_fields.get("Flags", "")
            if actor_id:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                dpapi_node_id = f"dpapi_{master_key_guid}"
                display_name = f"DPAPI\n{operation_type}"
                dpapi_info = f"[{evt_type}]\nOperation: {operation_type}\nMasterKey GUID: {master_key_guid}\nFlags: {flags}"
                add_or_update_artifact_node(dpapi_node_id, display_name, dpapi_info, "module", event)
                add_edge(actor_id, dpapi_node_id, operation_type, "#b366ff", evt_type, dashed=True, raw_event=event)

        elif evt_type == "BrowserLaunchedToOpenUrl":
            launched_url = event.get("RemoteUrl", "")
            if actor_id and launched_url:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                url_node_id = f"url_{hash_str(launched_url)}"
                display_url = launched_url[:50] + "..." if len(launched_url) > 50 else launched_url
                url_info = f"[{evt_type}]\nLaunched URL/URI:\n{launched_url}"
                add_or_update_artifact_node(url_node_id, display_url, url_info, "network", event)
                add_edge(actor_id, url_node_id, "Launches URL", "#00ffff", evt_type, dashed=True, raw_event=event)

        elif evt_type == "AntivirusReport":
            file_name = event.get("FileName", "Unknown Threat")
            sha1 = event.get("SHA1", "N/A")
            add_fields_raw = event.get("AdditionalFields", "")
            if isinstance(add_fields_raw, dict): add_fields_raw = json.dumps(add_fields_raw)
            av_actor = actor_id if actor_id else "SYSTEM_AV"
            av_actor_name = actor_name if actor_id else "Windows Defender Engine"
            get_or_create_process_node(av_actor, av_actor_name, username, evt_type, event)
            alert_node_id = f"av_alert_{file_name}_{sha1}"
            display_name = f"⚠️ AV ALERT\n{file_name[:25]}"
            alert_info = f"[{evt_type}]\nTarget Payload: {file_name}\nSHA1: {sha1}\nDetails: {add_fields_raw}"
            add_or_update_artifact_node(alert_node_id, display_name, alert_info, "alert", event)
            add_edge(av_actor, alert_node_id, "Detection", "#ff0000", evt_type, dashed=True, raw_event=event)

        elif evt_type in ["FileCreated", "FileModified", "FileDeleted", "FileRenamed", "ShellLinkCreateFileEvent"]:
            folder_path = event.get("FolderPath", "")
            file_name = event.get("FileName", "")
            full_path = folder_path if folder_path else file_name
            if actor_id and full_path:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                display_file = file_name[:50] + "..." if len(file_name) > 50 else file_name
                if not display_file: display_file = full_path[:50] + "..." if len(full_path) > 50 else full_path
                sha256 = event.get("SHA256", "N/A")
                add_fields_raw = event.get("AdditionalFields", "")
                if isinstance(add_fields_raw, dict): add_fields_raw = json.dumps(add_fields_raw)
                file_info = f"[{evt_type}]\nPath: {full_path}\nSHA256: {sha256}"
                if add_fields_raw: file_info += f"\nDetails: {add_fields_raw}"
                add_or_update_artifact_node(full_path, display_file, file_info, "file", event)
                add_edge(actor_id, full_path, evt_type, "#4da6ff", evt_type, raw_event=event)

        elif evt_type in ["ImageLoaded", "DriverLoad"]:
            dll_path = event.get("FolderPath", "")
            dll_name = event.get("FileName", "")
            if actor_id and dll_path:
                short_dll = dll_name if dll_name else dll_path.split('\\')[-1]
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                add_or_update_artifact_node(dll_path, short_dll, f"[{evt_type}]\nLoaded Module/Driver:\n{dll_path}", "module", event)
                add_edge(actor_id, dll_path, "Loads Module", "#b366ff", evt_type, raw_event=event)

        elif evt_type in ["RegistryKeyCreated", "RegistryValueCreated", "RegistryValueSet", "RegistryKeyDeleted", "RegistryValueDeleted"]:
            reg_key = event.get("RegistryKey") or event.get("PreviousRegistryKey", "")
            reg_value = event.get("RegistryValueName") or event.get("PreviousRegistryValueName", "")
            reg_data = event.get("RegistryValueData", "")
            if actor_id and reg_key:
                reg_node_id = f"{reg_key}\\{reg_value}" if reg_value else reg_key
                raw_reg = reg_value if reg_value else reg_key.split('\\')[-1]
                display_reg = raw_reg[:50] + "..." if len(raw_reg) > 50 else raw_reg
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                full_reg_info = f"[{evt_type}]\nKey: {reg_key}\nValue: {reg_value}\nData:\n{reg_data}"
                add_or_update_artifact_node(reg_node_id, display_reg, full_reg_info, "registry", event)
                add_edge(actor_id, reg_node_id, evt_type, "#ff9933", evt_type, raw_event=event)

        elif evt_type in ["ConnectionSuccess", "ConnectionFailed", "NetworkConnectionEvents", "NetworkCommunicationEvents", "ListeningPortCreated", "ListeningConnectionCreated", "InboundConnectionAccepted", "RemoteDesktopConnection", "HttpConnectionInspected", "ConnectionAcknowledged"]:
            remote_ip = event.get("RemoteIP", "")
            remote_port = event.get("RemotePort", "")
            local_ip = event.get("LocalIP", "")
            local_port = event.get("LocalPort", "")

            add_fields = get_additional_fields_dict(event)
            protocol = event.get("Protocol", "")
            if not protocol: protocol = add_fields.get("Protocol", "")

            remote_url = event.get("RemoteUrl", "")
            if not remote_url: remote_url = add_fields.get("host", "") or add_fields.get("uri", "")

            target_net = remote_ip if remote_ip else remote_url
            if not target_net and local_ip:
                target_net = f"Local_Listen:{local_ip}" if evt_type in ["ListeningPortCreated", "ListeningConnectionCreated"] else f"Local:{local_ip}"

            target_port = remote_port if remote_port else local_port
            net_actor = actor_id if actor_id else "SYSTEM_NETWORK"
            net_actor_name = actor_name if actor_id else "Network Subsystem"

            if target_net:
                net_node_id = f"{target_net}:{target_port}" if target_port else target_net
                get_or_create_process_node(net_actor, net_actor_name, username, evt_type, event)

                full_net_info = f"[{evt_type}]\nRemote: {remote_ip}:{remote_port}\nLocal: {local_ip}:{local_port}\nProtocol: {protocol}"
                if remote_url: full_net_info += f"\nURL/Host: {remote_url}"

                if evt_type == "HttpConnectionInspected" and add_fields:
                    method = add_fields.get("method", "UNKNOWN")
                    status = add_fields.get("status_code", "N/A")
                    full_net_info += f"\nHTTP Method: {method}\nStatus: {status}"
                    if add_fields.get("direction"): full_net_info += f"\nDirection: {add_fields.get('direction')}"

                elif evt_type == "ConnectionAcknowledged" and add_fields:
                    if "Tcp Flags" in add_fields: full_net_info += f"\nTCP Flags: {add_fields.get('Tcp Flags')}"
                    if "direction" in add_fields: full_net_info += f"\nDirection: {add_fields.get('direction')}"
                    if "Packet Size" in add_fields: full_net_info += f"\nPacket Size: {add_fields.get('Packet Size')} bytes"

                add_or_update_artifact_node(net_node_id, net_node_id, full_net_info, "network", event)
                add_edge(net_actor, net_node_id, evt_type, "#00ffff", evt_type, raw_event=event)

        else:
            if actor_id and target_id and actor_id != target_id:
                get_or_create_process_node(actor_id, actor_name, username, evt_type, event)
                get_or_create_process_node(target_id, target_name, username, evt_type, event)
                add_edge(actor_id, target_id, evt_type, "#a6a6a6", evt_type, raw_event=event)

    # Format for Cytoscape.js
    cy_nodes = []
    for n_id, n_data in nodes_dict.items():
        cy_nodes.append({"data": n_data})

    cy_edges = []
    for e_data in edges_list:
        cy_edges.append({"data": e_data})

    return {
        "elements": {
            "nodes": cy_nodes,
            "edges": cy_edges
        }
    }
