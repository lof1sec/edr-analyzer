import functools
import hashlib
import json
import os


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
def _hash_str(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()[:10]


def hash_str(val) -> str:
    """Short, stable digest used to build labels/ids in the graph payload.

    The digest is truncated only for readability; determinism across processes
    is what matters here, not cryptographic strength. ``val`` is coerced with
    ``str`` *before* the cached lookup so callers may pass numbers, ``None`` or
    even unhashable JSON values without a ``TypeError``.
    """
    return _hash_str(str(val))


@functools.lru_cache(maxsize=65536)
def _string_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]


def string_hash(val) -> str:
    """Stable identifier digest for graph element ids.

    Replaces the built-in ``hash()``, whose string hashing is salted per process
    (PYTHONHASHSEED). Ids built from it changed on every backend restart,
    breaking references and making the graph non-reproducible. A sha1 digest is
    fixed across processes; 16 hex chars keeps collisions negligible for
    realistic datasets. As with :func:`hash_str`, ``val`` is stringified before
    the cached lookup so unhashable values are safe.
    """
    return _string_hash(str(val))


def as_text(value) -> str:
    """Coerce a possibly non-string event field to text.

    CSV exports are always strings, but JSON exports can deliver a field as a
    number, boolean or ``None`` while the graph code assumes text. ``None``
    becomes an empty string (so ``if value:`` guards still skip it) and every
    other value is stringified, guaranteeing slices and string methods (``split``,
    ``replace`` …) never raise on untrusted input.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


# Raw events are attached to graph elements so the details pane can show
# evidence. Hub nodes can appear in thousands of events, so only the first N are
# retained per element while the true total is still reported for the UI.
MAX_RAW_LOGS_PER_ELEMENT = 200

# Search haystack per element. It is kept server-side only (never shipped to the
# browser) and built from *every* event, so the global search is not limited by
# the retained raw-log cap above. The cap is a safety valve for pathological hub
# elements, not a functional limit for realistic ones.
MAX_SEARCH_TEXT_CHARS = 100_000

# Fan-out hub: a node with more than this many exclusively-owned descendants has
# them collapsed into a single cluster placeholder in the initial payload. The
# hidden elements are served on demand by
# ``/api/graph/{id}/clusters/{cluster_id}``. Set to 0 (or negative) to disable.
DEFAULT_CLUSTER_MIN_CHILDREN = 50


def _cluster_min_children() -> int:
    """Read ``CLUSTER_MIN_CHILDREN`` at call time so tests can tune it per case."""
    raw = os.getenv("CLUSTER_MIN_CHILDREN")
    if raw is None:
        return DEFAULT_CLUSTER_MIN_CHILDREN
    try:
        return int(raw)
    except (TypeError, ValueError):
        return DEFAULT_CLUSTER_MIN_CHILDREN


def _append_raw_log(container: dict, raw_event) -> None:
    """Record ``raw_event`` as evidence and add it to the search haystack.

    The retained raw logs are capped at ``MAX_RAW_LOGS_PER_ELEMENT``, but every
    event also contributes to ``_search_text`` (bounded) so searching is not
    silently limited to the retained events.
    """
    if not raw_event:
        return
    container["raw_logs_total"] = container.get("raw_logs_total", 0) + 1
    logs = container.setdefault("raw_logs", [])
    if len(logs) < MAX_RAW_LOGS_PER_ELEMENT:
        logs.append(raw_event)

    existing = container.get("_search_text", "")
    if len(existing) < MAX_SEARCH_TEXT_CHARS:
        try:
            extra = json.dumps(raw_event, default=str)
        except (TypeError, ValueError):
            extra = str(raw_event)
        container["_search_text"] = (existing + " " + extra)[:MAX_SEARCH_TEXT_CHARS]


def _build_search_text(data: dict, search_text: str = "") -> str:
    """Lowercased haystack used by the backend search endpoint.

    Built once on the backend so the browser never has to re-serialise raw
    events while filtering. ``search_text`` already contains every raw event
    (bounded by ``MAX_SEARCH_TEXT_CHARS``).
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
    if search_text:
        parts.append(search_text)
    text = " ".join(part for part in parts if part).lower()
    return text[:MAX_SEARCH_TEXT_CHARS]


class GraphBuilder:
    def __init__(self):
        self.nodes_dict = {}
        self.edges_list = []
        self.unmapped_events = []
        self._edge_seq = 0

    def get_or_create_process_node(self, pid, name=None, username=None, hostname=None, evt_type=None, raw_event=None):
        if not pid:
            return
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
        if not node_id:
            return
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

    def _plan_clusters(self):
        """Collapse a process hub's exclusively-owned *artifact* children.

        Only non-process nodes are ever collapsed. Processes are the graph's
        central actors: their ``Spawns`` edges are what keep the graph connected,
        so a hub's process children always stay in the payload. Only the fan-out
        of artifact leaves (files, registry, network, command lines, modules,
        alerts, …) is hidden behind a placeholder. Artifacts never have outgoing
        edges in this model, so removing an exclusive one can never leave a
        dangling edge.

        Returns ``(collapsed_node_ids, collapsed_edge_ids, clusters)`` where
        ``clusters`` maps a placeholder id to the elements needed to expand it.
        """
        threshold = _cluster_min_children()
        if threshold <= 0:
            return set(), set(), {}

        children = {}
        parents = {}
        for edge in self.edges_list:
            # Only reason about edges whose endpoints are real nodes; a phantom
            # endpoint must never be collapsed or leave a dangling edge behind.
            if edge["source"] not in self.nodes_dict or edge["target"] not in self.nodes_dict:
                continue
            children.setdefault(edge["source"], []).append(edge)
            parents.setdefault(edge["target"], set()).add(edge["source"])

        collapsed_nodes = set()
        collapsed_edges = set()
        clusters = {}
        internal_keys = ("raw_logs", "_search_text")

        for hub_id, hub_edges in children.items():
            hub = self.nodes_dict.get(hub_id)
            if not hub or hub.get("group") != "process":
                continue

            # Exclusively-owned artifact children (their only parent is this hub).
            members = [
                edge["target"]
                for edge in hub_edges
                if edge["target"] not in collapsed_nodes
                and self.nodes_dict.get(edge["target"], {}).get("group") != "process"
                and parents.get(edge["target"]) == {hub_id}
            ]
            if len(members) < threshold:
                continue

            member_set = set(members)
            member_edges = [
                edge
                for edge in self.edges_list
                if edge["source"] == hub_id and edge["target"] in member_set
            ]

            hub_label = (hub.get("label") or hub_id).split("\n")[0]
            cluster_id = f"cluster_{hub_id}"
            cluster_node = {
                "id": cluster_id,
                "label": f"+{len(member_set)}",
                "group": "cluster",
                "title": (
                    f"{len(member_set)} exclusively-owned artifacts of {hub_label} "
                    "are collapsed.\nExpand the cluster to load them on demand."
                ),
                "isCluster": True,
                "clusterCount": len(member_set),
                "parentId": hub_id,
            }
            cluster_edge = {
                "id": f"cluster_edge_{hub_id}",
                "source": hub_id,
                "target": cluster_id,
                "label": "",
                "color": "#64748b",
                "event_simplename": "",
                "dashed": True,
                "raw_logs_total": 0,
            }

            clusters[cluster_id] = {
                "node": cluster_node,
                "edge": cluster_edge,
                "nodes": [
                    {"data": {k: v for k, v in self.nodes_dict[node_id].items() if k not in internal_keys}}
                    for node_id in members
                ],
                "edges": [
                    {"data": {k: v for k, v in edge.items() if k not in internal_keys}}
                    for edge in member_edges
                ],
            }
            collapsed_nodes.update(member_set)
            collapsed_edges.update(edge["id"] for edge in member_edges)

        return collapsed_nodes, collapsed_edges, clusters

    def build_cytoscape_elements(self):
        """Split the graph into lightweight elements plus server-side side maps.

        ``raw_logs`` and ``search_index`` are pulled out of each element's
        ``data`` so neither is shipped to or held by the browser:

        * ``raw_logs`` is served on demand by ``/api/graph/{id}/element-logs``.
        * ``search_index`` backs ``/api/graph/{id}/search`` so the global search
          can run over raw events without sending them to the client.

        ``clusters`` holds collapsed subtrees; the initial ``elements`` only
        carry the placeholder node/edge. Raw logs and search entries are still
        built for the collapsed nodes, so evidence and search keep working once
        a cluster is expanded.
        """
        internal_keys = ("raw_logs", "_search_text")
        raw_logs_map = {}
        search_index = {}
        for n_data in self.nodes_dict.values():
            data = {key: value for key, value in n_data.items() if key not in internal_keys}
            raw_logs_map[data["id"]] = n_data.get("raw_logs", [])
            search_index[data["id"]] = _build_search_text(data, n_data.get("_search_text", ""))
        for e_data in self.edges_list:
            data = {key: value for key, value in e_data.items() if key not in internal_keys}
            raw_logs_map[data["id"]] = e_data.get("raw_logs", [])
            search_index[data["id"]] = _build_search_text(data, e_data.get("_search_text", ""))

        collapsed_node_ids, collapsed_edge_ids, clusters = self._plan_clusters()

        cy_nodes = [
            {"data": {k: v for k, v in n_data.items() if k not in internal_keys}}
            for n_id, n_data in self.nodes_dict.items()
            if n_id not in collapsed_node_ids
        ]
        cy_edges = [
            {"data": {k: v for k, v in e_data.items() if k not in internal_keys}}
            for e_data in self.edges_list
            if e_data["id"] not in collapsed_edge_ids
        ]

        for cluster in clusters.values():
            cy_nodes.append({"data": cluster["node"]})
            cy_edges.append({"data": cluster["edge"]})

        return {
            "elements": {
                "nodes": cy_nodes,
                "edges": cy_edges
            },
            "raw_logs": raw_logs_map,
            "search_index": search_index,
            "unmapped_events": self.unmapped_events,
            "clusters": clusters,
        }
