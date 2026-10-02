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


# Raw events are attached to graph elements so the details pane can show
# evidence. Hub nodes can appear in thousands of events, so only the first N are
# retained per element while the true total is still reported for the UI.
MAX_RAW_LOGS_PER_ELEMENT = 200

# The frontend global search used to JSON-stringify every element's raw events
# on each keystroke. We build a bounded, lowercased haystack once here instead.
MAX_SEARCH_TEXT_CHARS = 2000


def _append_raw_log(container: dict, raw_event) -> None:
    """Record ``raw_event`` on a node/edge dict, capping the retained list."""
    if not raw_event:
        return
    container["raw_logs_total"] = container.get("raw_logs_total", 0) + 1
    logs = container.setdefault("raw_logs", [])
    if len(logs) < MAX_RAW_LOGS_PER_ELEMENT:
        logs.append(raw_event)


def _build_search_text(data: dict, raw_logs) -> str:
    """Lowercased haystack used by the frontend's global search.

    Built once on the backend so the browser never has to re-serialise raw
    events while filtering. Truncated to keep the payload bounded.
    """
    parts = [
        str(data.get("title") or ""),
        str(data.get("label") or ""),
        str(data.get("id") or ""),
        str(data.get("event_simplename") or ""),
        str(data.get("username") or ""),
        str(data.get("process_name") or ""),
        str(data.get("hostname") or ""),
    ]
    if raw_logs:
        parts.append(json.dumps(raw_logs, default=str))
    text = " ".join(part for part in parts if part).lower()
    return text[:MAX_SEARCH_TEXT_CHARS]


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
                "raw_logs": [],
                "raw_logs_total": 0,
            }
            _append_raw_log(self.nodes_dict[pid], raw_event)
        else:
            node = self.nodes_dict[pid]
            current_label = node.get("label", "")
            current_username = node.get("username")
            current_hostname = node.get("hostname")
            current_title = node.get("title", "")
            current_name = node.get("process_name")
            actions_list = node.get("actions", [])

            _append_raw_log(node, raw_event)

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
                "raw_logs": [],
                "raw_logs_total": 0,
            }
            _append_raw_log(self.nodes_dict[node_id], raw_event)
        else:
            current_title = self.nodes_dict[node_id].get("title", "")
            _append_raw_log(self.nodes_dict[node_id], raw_event)

            if new_details not in current_title:
                separator = "\n\n" + "="*40 + "\n\n"
                new_title = f"{current_title}{separator}{new_details}" if current_title else new_details
                self.nodes_dict[node_id]["title"] = new_title

    def add_edge(self, source, target, label, color, event_simplename, dashed=False, raw_event=None):
        source_str = str(source)
        target_str = str(target)
        self._edge_seq += 1
        edge = {
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
            "raw_logs": [],
            "raw_logs_total": 0,
        }
        _append_raw_log(edge, raw_event)
        self.edges_list.append(edge)

    def build_cytoscape_elements(self):
        """Split the graph into lightweight elements plus server-side side maps.

        ``raw_logs`` and ``search_index`` are pulled out of each element's
        ``data`` so neither is shipped to or held by the browser:

        * ``raw_logs`` is served on demand by ``/api/graph/{id}/element-logs``.
        * ``search_index`` backs ``/api/graph/{id}/search`` so the global search
          can run over raw events without sending them to the client.
        """
        raw_logs_map = {}
        search_index = {}
        cy_nodes = []
        for n_data in self.nodes_dict.values():
            data = {key: value for key, value in n_data.items() if key != "raw_logs"}
            raw_logs_map[data["id"]] = n_data.get("raw_logs", [])
            search_index[data["id"]] = _build_search_text(data, n_data.get("raw_logs"))
            cy_nodes.append({"data": data})

        cy_edges = []
        for e_data in self.edges_list:
            data = {key: value for key, value in e_data.items() if key != "raw_logs"}
            raw_logs_map[data["id"]] = e_data.get("raw_logs", [])
            search_index[data["id"]] = _build_search_text(data, e_data.get("raw_logs"))
            cy_edges.append({"data": data})

        return {
            "elements": {
                "nodes": cy_nodes,
                "edges": cy_edges
            },
            "raw_logs": raw_logs_map,
            "search_index": search_index,
            "unmapped_events": self.unmapped_events
        }
