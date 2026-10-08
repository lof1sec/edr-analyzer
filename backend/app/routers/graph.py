import os
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, func
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
    selected_process = set(process_order[:process_budget])
    selected_edge_ids = {
        e["data"]["id"] for e in pp_edges
        if e["data"]["source"] in selected_process and e["data"]["target"] in selected_process
    }

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
        cost = 1 + len(add_edges)
        if cost > budget:
            continue
        selected_artifacts.add(aid)
        for e in add_edges:
            selected_edge_ids.add(e["data"]["id"])
        budget -= cost

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
    }
    return nodes, edges, omitted_nodes, omitted_edges


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

    for log in logs:
        event = log.data
        evt_type = log.event_type

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
        else:
            # Neither vendor marker is present. Report it as unmapped instead of
            # force-feeding it to the Defender parser.
            builder.unmapped_events.append(evt_type)

    return builder.build_cytoscape_elements()


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
    _, _, omitted_nodes, omitted_edges = _truncated_parts(
        payload, _max_initial_elements()
    )

    if not omitted_nodes:
        return {"nodes": [], "edges": [], "offset": offset, "limit": limit, "remaining": 0}

    end = min(offset + limit, len(omitted_nodes))
    nodes_page = omitted_nodes[offset:end]

    initial_ids = {
        n["data"]["id"] for n in payload["elements"]["nodes"]
    } - {n["data"]["id"] for n in omitted_nodes}
    loaded_ids = initial_ids | {n["data"]["id"] for n in omitted_nodes[:end]}
    page_ids = {n["data"]["id"] for n in nodes_page}

    edges_page = [
        e for e in omitted_edges
        if e["data"]["source"] in loaded_ids
        and e["data"]["target"] in loaded_ids
        and (e["data"]["source"] in page_ids or e["data"]["target"] in page_ids)
    ]

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


@router.get("/{dataset_id}/search")
def search_graph(
    dataset_id: int,
    q: str = Query("", description="Comma-separated search terms"),
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

    payload = _get_graph_payload(dataset_id, db)
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


def _timeline_element_ids(ctx: dict) -> list[str]:
    """Best-effort graph element ids to highlight for an event.

    Process node ids are host-scoped (``pid@host``; see
    ``GraphBuilder.process_node_id``), so each actor/target PID is combined
    with the event's host to match the builder. Artifacts keep their own id
    scheme and are not mapped.
    """
    host = ctx.get("hostname")
    host_text = "" if host in (None, "") else str(host).strip()
    ids = []
    for key in ("actor_id", "target_id"):
        value = ctx.get(key)
        if value not in (None, ""):
            pid = str(value)
            ids.append(f"{pid}@{host_text}" if host_text else pid)
    return list(dict.fromkeys(ids))


@router.get("/{dataset_id}/timeline")
def get_timeline(
    dataset_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(TIMELINE_DEFAULT_LIMIT, ge=1, le=TIMELINE_MAX_LIMIT),
    event_type: str | None = Query(None),
    q: str | None = Query(None),
    from_ms: int | None = Query(None, alias="from"),
    to_ms: int | None = Query(None, alias="to"),
    db: Session = Depends(get_db),
):
    """Return a dataset's events in chronological order, paginated.

    Events are ordered by their normalised ``event_time``; events without a
    usable timestamp sort last, in insertion order. Only compact summaries are
    returned (raw logs stay server-side, per the payload invariant).
    """
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    query = db.query(LogEvent).filter(LogEvent.dataset_id == dataset_id)
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if from_ms is not None:
        query = query.filter(LogEvent.event_time >= from_ms)
    if to_ms is not None:
        query = query.filter(LogEvent.event_time <= to_ms)
    if q:
        query = query.filter(cast(LogEvent.data, String).ilike(f"%{q}%"))

    total = query.count()
    # ``event_time IS NULL`` is False (0) for dated events, so ordering by it
    # ascending puts dated events first; undated ones keep insertion order last.
    ordered = query.order_by(
        LogEvent.event_time.is_(None),
        LogEvent.event_time.asc(),
        LogEvent.id.asc(),
    )
    rows = ordered.offset(offset).limit(limit).all()

    entries = []
    for index, log in enumerate(rows, start=offset):
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
            "element_ids": _timeline_element_ids(ctx),
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
