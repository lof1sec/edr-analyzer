import os
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import Text, cast, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Dataset, GraphLayout, LogEvent
from app.parsers.builder import GraphBuilder
from app.parsers.defender import parse_defender_event
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.timestamps import format_timestamp
from app.parsers.vendor import DEFENDER, FALCON, get_vendor
from app.routers import graph_cache
from app.routers.auth import require_user
from app.schemas import LayoutRequest

router = APIRouter(
    prefix="/api/graph",
    tags=["Graph"],
    dependencies=[Depends(require_user)],
)

# Above this many elements the initial graph payload is truncated and the rest
# is served on demand via ``GET /{dataset_id}/elements``. Rendering tens of
# thousands of Cytoscape elements in one go freezes the browser, so the initial
# response keeps only the process-process backbone plus as many artifact leaves
# as fit the budget. Set to 0 (or negative) to always ship the full graph.
DEFAULT_MAX_INITIAL_ELEMENTS = 5000


def _max_initial_elements() -> int:
    """Read ``MAX_INITIAL_ELEMENTS`` at call time so tests can tune it per case."""
    raw = os.getenv("MAX_INITIAL_ELEMENTS")
    if raw is None:
        return DEFAULT_MAX_INITIAL_ELEMENTS
    try:
        return int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_INITIAL_ELEMENTS


def _truncate_elements(nodes, edges, cap):
    """Split a full graph payload into an initial view and an on-demand remainder.

    Returns ``(nodes, edges, omitted_nodes, omitted_edges)``. The initial view
    keeps every process node (trimmed to the highest-degree when they alone
    exceed the budget) and their process-process edges, then fills the remaining
    budget with artifact leaves and their edges to kept processes. Ordering is
    deterministic (degree desc, then id asc) so the ``/elements`` pages are
    stable across requests.
    """
    if cap <= 0 or len(nodes) + len(edges) <= cap:
        return nodes, edges, [], []

    process_ids = {n["data"]["id"] for n in nodes if n["data"].get("group") == "process"}
    artifact_ids = sorted(
        n["data"]["id"] for n in nodes if n["data"]["id"] not in process_ids
    )

    pp_edges = [
        e for e in edges
        if e["data"]["source"] in process_ids and e["data"]["target"] in process_ids
    ]
    pa_edges = [
        e for e in edges
        if (e["data"]["source"] in process_ids) != (e["data"]["target"] in process_ids)
    ]

    # Prefer the most-connected processes first so the truncated view keeps the
    # graph's backbone rather than a random slice.
    degree = {pid: 0 for pid in process_ids}
    for e in pp_edges:
        degree[e["data"]["source"]] += 1
        degree[e["data"]["target"]] += 1
    process_order = sorted(process_ids, key=lambda pid: (-degree.get(pid, 0), pid))

    process_budget = max(cap // 2, 1)
    selected_process = set()
    selected_edge_ids = set()
    # Count parallel process edges before admitting a node: otherwise a dense
    # process backbone can exceed the *total* element budget by itself.
    process_edges = {pid: [] for pid in process_ids}
    for edge in pp_edges:
        process_edges[edge["data"]["source"]].append(edge)
        if edge["data"]["target"] != edge["data"]["source"]:
            process_edges[edge["data"]["target"]].append(edge)
    for pid in process_order:
        if len(selected_process) >= process_budget:
            break
        new_edges = {
            edge["data"]["id"] for edge in process_edges[pid]
            if edge["data"]["source"] in (selected_process | {pid})
            and edge["data"]["target"] in (selected_process | {pid})
        } - selected_edge_ids
        if len(selected_process) + len(selected_edge_ids) + 1 + len(new_edges) <= cap:
            selected_process.add(pid)
            selected_edge_ids.update(new_edges)

    # Map each artifact to its incident process<->artifact edges once, so filling
    # the budget is O(pa_edges) instead of O(artifacts * pa_edges).
    incident = {aid: [] for aid in artifact_ids}
    for e in pa_edges:
        s, t = e["data"]["source"], e["data"]["target"]
        if s in incident:
            incident[s].append(e)
        if t in incident:
            incident[t].append(e)

    budget = cap - len(selected_process) - len(selected_edge_ids)
    selected_artifacts = set()
    for aid in artifact_ids:
        if budget <= 0:
            break

        add_edges = [
            e for e in incident[aid]
            if (e["data"]["target"] if e["data"]["source"] == aid else e["data"]["source"])
            in selected_process
        ]
        # Include isolated observations, and only edges with admitted endpoints.
        cost = 1 + len(add_edges)
        if cost > budget:
            continue
        selected_artifacts.add(aid)
        for e in add_edges:
            selected_edge_ids.add(e["data"]["id"])
        budget -= cost

    # Contextual edges between event and host/account/file artifacts are not
    # process edges; admit them only after both endpoints have been selected.
    for edge in edges:
        data = edge["data"]
        if (data["id"] not in selected_edge_ids
                and data["source"] in selected_process | selected_artifacts
                and data["target"] in selected_process | selected_artifacts
                and budget > 0):
            selected_edge_ids.add(data["id"])
            budget -= 1

    selected_ids = selected_process | selected_artifacts
    selected_nodes = [n for n in nodes if n["data"]["id"] in selected_ids]
    selected_edges = [e for e in edges if e["data"]["id"] in selected_edge_ids]

    omitted_nodes = sorted(
        (n for n in nodes if n["data"]["id"] not in selected_ids),
        key=lambda n: n["data"]["id"],
    )
    omitted_edges = sorted(
        (e for e in edges if e["data"]["id"] not in selected_edge_ids),
        key=lambda e: e["data"]["id"],
    )
    return selected_nodes, selected_edges, omitted_nodes, omitted_edges


def _truncated_parts(payload: dict, cap: int):
    """Return the initial view + omitted elements for ``payload``, memoised on it.

    The full payload stays cached in ``graph_cache``; only the *view* delivered to
    the browser is truncated. Memoising keeps the ``/elements`` pages from
    re-sorting the whole element list on every request.
    """
    memo = payload.get("_truncation")
    if memo is not None and memo["cap"] == cap:
        return memo["nodes"], memo["edges"], memo["omitted_nodes"], memo["omitted_edges"]

    elements = payload["elements"]
    nodes, edges, omitted_nodes, omitted_edges = _truncate_elements(
        elements["nodes"], elements["edges"], cap
    )
    payload["_truncation"] = {
        "cap": cap,
        "nodes": nodes,
        "edges": edges,
        "omitted_nodes": omitted_nodes,
        "omitted_edges": omitted_edges,
        # Bucket each edge by the later page of its endpoints. A page can now
        # return its edges without scanning every omitted node/edge again.
        "edge_buckets": _edge_buckets(nodes, omitted_nodes, omitted_edges),
    }
    return nodes, edges, omitted_nodes, omitted_edges


def _edge_buckets(initial_nodes, omitted_nodes, omitted_edges):
    initial_ids = {node["data"]["id"] for node in initial_nodes}
    position = {node["data"]["id"]: index for index, node in enumerate(omitted_nodes)}
    buckets = {}
    for edge in omitted_edges:
        source, target = edge["data"]["source"], edge["data"]["target"]
        if source not in initial_ids and source not in position:
            continue
        if target not in initial_ids and target not in position:
            continue
        later = max(position.get(source, -1), position.get(target, -1))
        if later >= 0:
            buckets.setdefault(later, []).append(edge)
    return buckets


def _build_graph_payload(
    dataset_id: int,
    db: Session,
    from_ms: int | None = None,
    to_ms: int | None = None,
) -> dict:
    """Parse every event of a dataset into a full graph payload.

    The payload contains lightweight ``elements`` (no raw logs) plus a
    ``raw_logs`` side map keyed by element id, used by the lazy detail endpoint.

    ``from_ms``/``to_ms`` (epoch milliseconds) restrict the events used to build
    the graph to that window. Undated events (``event_time IS NULL``) are excluded
    whenever either bound is given.
    """
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    query = db.query(LogEvent).filter(LogEvent.dataset_id == dataset_id)
    if from_ms is not None:
        query = query.filter(LogEvent.event_time >= from_ms)
    if to_ms is not None:
        query = query.filter(LogEvent.event_time <= to_ms)

    # ``yield_per`` streams rows instead of materialising every JSONB blob at
    # once, keeping peak memory bounded for large datasets.
    logs = query.order_by(LogEvent.id).yield_per(1000)
    builder = GraphBuilder()
    event_times = {}

    for log in logs:
        event = log.data
        evt_type = log.event_type
        # Stamp this event's normalized time so elements record when they were
        # first/last observed (the details pane shows it).
        builder.current_event_time = log.event_time
        builder.current_event_id = log.id

        # Vendor is detected per event, so a dataset can safely mix exports.
        vendor = get_vendor(event)

        if vendor in (FALCON, DEFENDER):
            ctx = describe_event(event, vendor)
            parse = parse_falcon_event if vendor == FALCON else parse_defender_event
            parse(
                builder,
                event,
                evt_type,
                ctx["actor_id"],
                ctx["actor_name"],
                ctx["target_id"],
                ctx["target_name"],
                ctx["username"],
                ctx["hostname"],
            )
            if log.id in builder.event_elements:
                event_times[log.id] = (log.event_time, evt_type)
        else:
            # Neither vendor marker is present. Report it as unmapped instead of
            # force-feeding it to the Defender parser.
            builder.unmapped_events.append(evt_type)

    payload = builder.build_cytoscape_elements()
    payload["event_times"] = event_times
    return payload


def _get_graph_payload(
    dataset_id: int,
    db: Session,
    from_ms: int | None = None,
    to_ms: int | None = None,
) -> dict:
    """Return the cached graph payload, building and caching it on a miss.

    The cache key includes the time window so each filtered graph is built and
    stored once.
    """
    key = (dataset_id, from_ms, to_ms)
    cached = graph_cache.get(key)
    if cached is not None:
        return cached

    payload = _build_graph_payload(dataset_id, db, from_ms, to_ms)
    graph_cache.put(key, payload)
    return payload


@router.get("/{dataset_id}")
def generate_graph(
    dataset_id: int,
    from_ms: int | None = Query(None, alias="from", description="Start of the time window (epoch ms)"),
    to_ms: int | None = Query(None, alias="to", description="End of the time window (epoch ms)"),
    db: Session = Depends(get_db),
):
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    # Raw logs are intentionally omitted here so the initial response and the
    # in-browser graph stay small; they are fetched on demand below. Unmapped
    # events are aggregated to counts so the payload does not carry one entry
    # per event.
    nodes, edges, omitted_nodes, omitted_edges = _truncated_parts(
        payload, _max_initial_elements()
    )
    return {
        "elements": {"nodes": nodes, "edges": edges},
        "unmapped_events": dict(Counter(payload["unmapped_events"])),
        "truncated": bool(omitted_nodes or omitted_edges),
        "total_nodes": len(payload["elements"]["nodes"]),
        "total_edges": len(payload["elements"]["edges"]),
    }


@router.get("/{dataset_id}/time-range")
def get_time_range(dataset_id: int, db: Session = Depends(get_db)):
    """Return the dataset's full event-time span (epoch ms), regardless of filters.

    ``min_ms``/``max_ms`` are ``None`` when the dataset has no dated events. The
    UI uses this to bound the time-range picker and show the available window.
    """
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    min_ms, max_ms = (
        db.query(func.min(LogEvent.event_time), func.max(LogEvent.event_time))
        .filter(LogEvent.dataset_id == dataset_id)
        .one()
    )
    return {"min_ms": min_ms, "max_ms": max_ms}


@router.get("/{dataset_id}/elements")
def get_elements(
    dataset_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Return a page of the elements omitted from the truncated initial view.

    Nodes are paged in stable id order; an edge is emitted on the page that
    loads the *later* of its two endpoints, and only once both endpoints are
    already loaded (either in the initial view or an earlier page), so the client
    never receives a dangling edge.
    """
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    _, _, omitted_nodes, _ = _truncated_parts(
        payload, _max_initial_elements()
    )

    if not omitted_nodes:
        return {"nodes": [], "edges": [], "offset": offset, "limit": limit, "remaining": 0}

    end = min(offset + limit, len(omitted_nodes))
    nodes_page = omitted_nodes[offset:end]

    buckets = payload["_truncation"]["edge_buckets"]
    edges_page = [edge for index in range(offset, end) for edge in buckets.get(index, ())]

    return {
        "nodes": nodes_page,
        "edges": edges_page,
        "offset": offset,
        "limit": limit,
        "remaining": len(omitted_nodes) - end,
    }


@router.get("/{dataset_id}/element-logs")
def get_element_logs(
    dataset_id: int,
    element_id: str = Query(..., description="Node or edge id from the graph payload"),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    logs = payload.get("raw_logs", {}).get(element_id, [])
    return {"element_id": element_id, "raw_logs": logs, "returned": len(logs)}


@router.get("/{dataset_id}/focus")
def get_focus_elements(
    dataset_id: int,
    element_id: str = Query(...),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Load a timeline target and its endpoints, even if paged or clustered."""
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    nodes = {node["data"]["id"]: node for node in payload["elements"]["nodes"]}
    edges = {edge["data"]["id"]: edge for edge in payload["elements"]["edges"]}
    cluster_id = None
    for candidate, cluster in payload["clusters"].items():
        if element_id in {item["data"]["id"] for item in cluster["nodes"] + cluster["edges"]}:
            cluster_id = candidate
            break
    if cluster_id:
        cluster = payload["clusters"][cluster_id]
        hub = nodes.get(cluster["node"]["parentId"])
        return {
            "nodes": ([hub] if hub else []) + cluster["nodes"],
            "edges": cluster["edges"],
            "cluster_id": cluster_id,
            "cluster_node": {"data": cluster["node"]},
            "cluster_edge": {"data": cluster["edge"]},
        }
    if element_id in edges:
        edge = edges[element_id]
        endpoints = [nodes[node_id] for node_id in
                     (edge["data"]["source"], edge["data"]["target"]) if node_id in nodes]
        return {"nodes": endpoints, "edges": [edge], "cluster_id": None}
    if element_id in nodes:
        node = nodes[element_id]
        # Bring in one real relationship so an artifact is not orphaned when
        # Cytoscape's filter effect runs after loading.
        incident = next((edge for edge in edges.values()
                         if element_id in (edge["data"]["source"], edge["data"]["target"])), None)
        if incident:
            other = incident["data"]["target"] if incident["data"]["source"] == element_id else incident["data"]["source"]
            return {"nodes": [node] + ([nodes[other]] if other in nodes else []),
                    "edges": [incident], "cluster_id": None}
        return {"nodes": [node], "edges": [], "cluster_id": None}
    raise HTTPException(status_code=404, detail="Element not found")


@router.get("/{dataset_id}/search")
def search_graph(
    dataset_id: int,
    q: str = Query("", description="Comma-separated search terms"),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Return the ids of elements matching the (lowercased) search terms.

    Runs against the cached ``search_index`` so raw events never reach the
    browser and the client no longer has to scan/serialise the whole graph on
    every keystroke.
    """
    terms = [term.strip().lower() for term in q.split(",") if term.strip()]
    if not terms:
        return {"ids": []}

    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    index = payload.get("search_index", {})
    ids = [element_id for element_id, text in index.items() if any(term in text for term in terms)]
    return {"ids": ids}


# --- Chronological timeline -------------------------------------------------

TIMELINE_DEFAULT_LIMIT = 200
TIMELINE_MAX_LIMIT = 1000


def _short_text(value, limit: int = 60) -> str:
    if value in (None, ""):
        return ""
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _summarize(event_type: str, ctx: dict) -> str:
    """One-line human summary of an event (never the raw log)."""
    actor = _short_text(ctx.get("actor_name") or ctx.get("actor_id"), 40)
    target = _short_text(ctx.get("target_name") or ctx.get("target_id"), 40)
    if actor and target:
        return f"{actor} → {target}"
    return target or actor or event_type


def _timeline_view(payload, hidden_event_types, hidden_users, hidden_pids, graph_q):
    """Resolve graph-derived event visibility before counting or paginating.

    Clusters and truncated elements still contribute: those are presentation
    choices, not event filters. Results are memoised on the graph's window-scoped
    cache entry; no raw events are copied into the response.
    """
    key = (tuple(sorted(hidden_event_types)), tuple(sorted(hidden_users)),
           tuple(sorted(hidden_pids)), graph_q.strip().lower())
    views = payload.setdefault("_timeline_views", {})
    if key in views:
        return views[key]

    nodes = {node["data"]["id"]: node["data"] for node in payload["elements"]["nodes"]}
    edges = {edge["data"]["id"]: edge["data"] for edge in payload["elements"]["edges"]}
    cluster_for = {}
    for cluster_id, cluster in payload["clusters"].items():
        for node in cluster["nodes"]:
            nodes[node["data"]["id"]] = node["data"]
            cluster_for[node["data"]["id"]] = cluster_id
        for edge in cluster["edges"]:
            edges[edge["data"]["id"]] = edge["data"]
            cluster_for[edge["data"]["id"]] = cluster_id

    terms = [term.strip() for term in graph_q.lower().split(",") if term.strip()]
    matches = (
        {element_id for element_id, text in payload["search_index"].items()
         if any(term in text for term in terms)} if terms else None
    )
    allowed_nodes = {
        node_id for node_id, data in nodes.items()
        if (data.get("group") != "process" or
            (str(data.get("username")) not in hidden_users and node_id not in hidden_pids))
    }
    visible_nodes = allowed_nodes if matches is None else allowed_nodes & matches
    # As in GraphView, an edge matching global search reveals its endpoints
    # unless an identity filter suppresses them.
    if matches is not None:
        for edge_id in matches & edges.keys():
            edge = edges[edge_id]
            visible_nodes.update({edge["source"], edge["target"]} & allowed_nodes)
    visible_edges = {
        edge_id for edge_id, data in edges.items()
        if data.get("event_simplename") not in hidden_event_types
        and data["source"] in visible_nodes and data["target"] in visible_nodes
    }
    visible_artifacts = {
        node_id for edge_id in visible_edges
        for node_id in (edges[edge_id]["source"], edges[edge_id]["target"])
        if nodes.get(node_id, {}).get("group") != "process"
    }
    visible_nodes = {
        node_id for node_id in visible_nodes
        if nodes.get(node_id, {}).get("group") in {"process", "event"} or node_id in visible_artifacts
    }

    result = {}
    for event_id, refs in payload["event_elements"].items():
        time_and_type = payload["event_times"].get(event_id)
        if not time_and_type or time_and_type[1] in hidden_event_types:
            continue
        # Contextual observation nodes must not resurrect a row whose actor was
        # explicitly hidden by an identity filter.
        if any(nodes.get(node_id, {}).get("group") == "process" and node_id not in allowed_nodes
               for node_id in refs["nodes"]):
            continue
        event_edges = refs["edges"] & visible_edges
        event_nodes = refs["nodes"] & visible_nodes
        # A hidden relationship cannot be kept alive by its shared actor node.
        if not event_edges and (refs["edges"] or not event_nodes):
            continue
        ids = sorted(event_nodes) + sorted(event_edges)
        semantic_edges = sorted(edge_id for edge_id in event_edges
                                if edges[edge_id].get("label") not in {"Observed on", "Reported by"})
        focus_id = semantic_edges[0] if semantic_edges else (sorted(event_edges)[0] if event_edges else ids[0])
        result[event_id] = {
            "element_ids": ids,
            "focus_element_id": focus_id,
            "focus_cluster_id": cluster_for.get(focus_id),
        }

    ordered = sorted(result, key=lambda event_id: (
        payload["event_times"][event_id][0] is None,
        payload["event_times"][event_id][0] or 0,
        event_id,
    ))
    # Keep only a few filter combinations per cached graph.
    if len(views) >= 8:
        views.pop(next(iter(views)))
    views[key] = (ordered, result)
    return ordered, result


@router.get("/{dataset_id}/timeline")
def get_timeline(
    dataset_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(TIMELINE_DEFAULT_LIMIT, ge=1, le=TIMELINE_MAX_LIMIT),
    event_type: str | None = Query(None),
    q: str | None = Query(None),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    graph_q: str = Query(""),
    hidden_event_type: list[str] | None = Query(None),
    hidden_user: list[str] | None = Query(None),
    hidden_pid: list[str] | None = Query(None),
    db: Session = Depends(get_db),
):
    """Return a dataset's events in chronological order, paginated.

    Events are ordered by their normalised ``event_time``; events without a
    usable timestamp sort last, in insertion order. Only compact summaries are
    returned (raw logs stay server-side, per the payload invariant).
    """
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    ordered, references = _timeline_view(
        payload, set(hidden_event_type or ()), set(hidden_user or ()),
        set(hidden_pid or ()), graph_q,
    )
    if event_type:
        ordered = [event_id for event_id in ordered
                   if payload["event_times"][event_id][1] == event_type]
    if q:
        # PostgreSQL's trigram index on this exact expression accelerates
        # substring searches; SQLite keeps the same behaviour in tests.
        search_query = db.query(LogEvent.id).filter(LogEvent.dataset_id == dataset_id)
        if from_ms is not None:
            search_query = search_query.filter(LogEvent.event_time >= from_ms)
        if to_ms is not None:
            search_query = search_query.filter(LogEvent.event_time <= to_ms)
        matching = {
            row.id for row in search_query.filter(cast(LogEvent.data, Text).ilike(f"%{q}%"))
        }
        ordered = [event_id for event_id in ordered if event_id in matching]

    total = len(ordered)
    page_ids = ordered[offset:offset + limit]
    rows = db.query(LogEvent).filter(LogEvent.id.in_(page_ids)).all() if page_ids else []
    by_id = {row.id: row for row in rows}

    entries = []
    for index, event_id in enumerate(page_ids, start=offset):
        log = by_id[event_id]
        event = log.data if isinstance(log.data, dict) else {}
        vendor = get_vendor(event)
        ctx = describe_event(event, vendor)
        entries.append({
            "index": index,
            "id": log.id,
            "time_ms": log.event_time,
            "iso": format_timestamp(log.event_time),
            "event_type": log.event_type,
            "vendor": vendor,
            "summary": _summarize(log.event_type, ctx),
            "actor_id": ctx.get("actor_id"),
            "target_id": ctx.get("target_id"),
            "element_ids": references[event_id]["element_ids"],
            "focus_element_id": references[event_id]["focus_element_id"],
            "focus_cluster_id": references[event_id]["focus_cluster_id"],
        })

    return {"total": total, "offset": offset, "limit": limit, "entries": entries}


# Safety cap for the on-demand neighbourhood endpoint: a hub at depth 3 can pull
# in a large slice of the graph, so we stop expanding rather than ship it all.
MAX_NEIGHBOR_NODES = 2000


@router.get("/{dataset_id}/clusters/{cluster_id}")
def get_cluster(
    dataset_id: int,
    cluster_id: str,
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Return the hidden elements of a collapsed cluster, on demand."""
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    cluster = payload.get("clusters", {}).get(cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {
        "cluster_id": cluster_id,
        "nodes": cluster["nodes"],
        "edges": cluster["edges"],
        "cluster_edge_id": cluster["edge"]["id"],
    }


@router.get("/{dataset_id}/neighbors")
def get_neighbors(
    dataset_id: int,
    element_id: str = Query(..., description="Node id to expand around"),
    depth: int = Query(1, ge=1, le=3),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Return the subgraph within ``depth`` hops of ``element_id``.

    Backs lazy/progressive exploration: the browser can pull in a neighbourhood
    without re-parsing or re-shipping the whole graph.
    """
    payload = _get_graph_payload(dataset_id, db, from_ms, to_ms)
    nodes = payload["elements"]["nodes"]
    edges = payload["elements"]["edges"]
    node_by_id = {node["data"]["id"]: node for node in nodes}
    if element_id not in node_by_id:
        raise HTTPException(status_code=404, detail="Element not found")

    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        source = edge["data"]["source"]
        target = edge["data"]["target"]
        adjacency.setdefault(source, set()).add(target)
        adjacency.setdefault(target, set()).add(source)

    selected = {element_id}
    frontier = {element_id}
    truncated = False
    for _ in range(depth):
        next_frontier: set[str] = set()
        for node_id in frontier:
            next_frontier |= adjacency.get(node_id, set())
        next_frontier -= selected
        if len(selected) + len(next_frontier) > MAX_NEIGHBOR_NODES:
            truncated = True
            next_frontier = set(list(next_frontier)[: MAX_NEIGHBOR_NODES - len(selected)])
        selected |= next_frontier
        frontier = next_frontier
        if not frontier:
            break

    selected_nodes = [node_by_id[node_id] for node_id in selected if node_id in node_by_id]
    selected_edges = [
        edge
        for edge in edges
        if edge["data"]["source"] in selected and edge["data"]["target"] in selected
    ]
    return {
        "element_id": element_id,
        "nodes": selected_nodes,
        "edges": selected_edges,
        "truncated": truncated,
    }


@router.get("/{dataset_id}/layout")
def get_layout(dataset_id: int, db: Session = Depends(get_db)):
    """Return the saved node positions for a dataset (empty when none)."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    layout = (
        db.query(GraphLayout).filter(GraphLayout.dataset_id == dataset_id).first()
    )
    return {"positions": layout.positions if layout else {}}


@router.put("/{dataset_id}/layout")
def save_layout(
    dataset_id: int,
    body: LayoutRequest,
    db: Session = Depends(get_db),
):
    """Persist the user's node arrangement for a dataset (upsert)."""
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    positions = {
        node_id: {"x": pos.x, "y": pos.y} for node_id, pos in body.positions.items()
    }
    layout = (
        db.query(GraphLayout).filter(GraphLayout.dataset_id == dataset_id).first()
    )
    if layout:
        layout.positions = positions
    else:
        db.add(GraphLayout(dataset_id=dataset_id, positions=positions))
    db.commit()
    return {"message": "Layout saved", "count": len(positions)}
