import json
import hashlib
import functools

def get_additional_fields_dict(event_data):
    fields = event_data.get("AdditionalFields")
    if not fields:
        return {}
    if isinstance(fields, dict):
        return fields
    if isinstance(fields, str):
        fields = fields.strip()
        if fields.startswith("{"):
            try:
                return json.loads(fields)
            except json.JSONDecodeError:
                pass
    return {}

@functools.lru_cache(maxsize=8192)
def hash_str(val: str) -> str:
    """Short, stable digest used to build labels/ids in the graph payload.

    The digest is truncated only for readability; determinism across processes
    is what matters here, not cryptographic strength.
    """
    return hashlib.md5(str(val).encode("utf-8")).hexdigest()[:10]


@functools.lru_cache(maxsize=65536)
def string_hash(val) -> str:
    """Stable identifier digest for graph element ids.

    Replaces the built-in ``hash()``, whose string hashing is salted per process
    (PYTHONHASHSEED). Ids built from it changed on every backend restart,
    breaking references and making the graph non-reproducible. A sha1 digest is
    fixed across processes; 16 hex chars keeps collisions negligible for
    realistic datasets.
    """
    return hashlib.sha1(str(val).encode("utf-8")).hexdigest()[:16]


class GraphBuilder:
    def __init__(self):
        self.nodes_dict = {}
        self.edges_list = []
        self.unmapped_events = []
        self._edge_seq = 0

    def get_or_create_process_node(self, pid, name=None, username=None, hostname=None, evt_type=None, raw_event=None):
        if not pid: return
        pid = str(pid)

        display_name = name if name else "Unknown"
        label = f"{display_name}\n{pid}" if name else f"Process ID:\n{pid}"
        if username:
            icon = "💻" if str(username).endswith("$") else "👤"
            label += f"\n{icon} {username}"
        if hostname:
            label += f"\n🖥️ {hostname}"

        title = f"Process Name: {display_name}\nPID: {pid}"
        if username:
            icon = "💻" if str(username).endswith("$") else "👤"
            title += f"\nUser: {icon} {username}"
        if hostname:
            title += f"\nHost: 🖥️ {hostname}"

        if pid not in self.nodes_dict:
            actions_list = [evt_type] if evt_type else []
            if actions_list:
                title += f"\n\nObserved Actions:\n[{'], ['.join(actions_list)}]"

            self.nodes_dict[pid] = {
                "id": pid,
                "label": label,
                "group": "process",
                "title": title,
                "username": username,
                "hostname": hostname,
                "process_name": name,
                "actions": actions_list,
                "raw_logs": [raw_event] if raw_event else []
            }
        else:
            node = self.nodes_dict[pid]
            current_label = node.get("label", "")
            current_username = node.get("username")
            current_hostname = node.get("hostname")
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
                current_title = node["title"]

            if hostname and not current_hostname:
                node["hostname"] = hostname
                if "🖥️" not in node["label"]:
                    node["label"] += f"\n🖥️ {hostname}"
                if "Host:" not in current_title:
                    parts = current_title.split('\n\nObserved Actions:')
                    if len(parts) > 1:
                        node["title"] = parts[0] + f"\nHost: 🖥️ {hostname}\n\nObserved Actions:" + parts[1]
                    else:
                        node["title"] += f"\nHost: 🖥️ {hostname}"

    def add_or_update_artifact_node(self, node_id, label, new_details, group, raw_event=None):
        if not node_id: return
        node_id = str(node_id)

        if node_id not in self.nodes_dict:
            self.nodes_dict[node_id] = {
                "id": node_id,
                "label": label,
                "group": group,
                "title": new_details,
                "raw_logs": [raw_event] if raw_event else []
            }
        else:
            current_title = self.nodes_dict[node_id].get("title", "")
            if raw_event:
                self.nodes_dict[node_id].setdefault("raw_logs", []).append(raw_event)

            if new_details not in current_title:
                separator = "\n\n" + "="*40 + "\n\n"
                new_title = f"{current_title}{separator}{new_details}" if current_title else new_details
                self.nodes_dict[node_id]["title"] = new_title

    def add_edge(self, source, target, label, color, event_simplename, dashed=False, raw_event=None):
        source_str = str(source)
        target_str = str(target)
        self._edge_seq += 1
        self.edges_list.append({
            "source": source_str,
            "target": target_str,
            "label": label,
            "color": color,
            "event_simplename": event_simplename,
            "dashed": dashed,
            # A per-builder sequence guarantees a unique id even when several
            # events produce identical source/target/label/content. Deriving it
            # from a content hash caused duplicate ids (Cytoscape silently drops
            # elements that share an id), losing evidence.
            "id": f"edge_{self._edge_seq}",
            "raw_logs": [raw_event] if raw_event else []
        })

    def build_cytoscape_elements(self):
        cy_nodes = [{"data": n_data} for n_data in self.nodes_dict.values()]
        cy_edges = [{"data": e_data} for e_data in self.edges_list]
        return {
            "elements": {
                "nodes": cy_nodes,
                "edges": cy_edges
            },
            "unmapped_events": self.unmapped_events
        }
