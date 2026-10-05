from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast
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


def _build_graph_payload(dataset_id: int, db: Session) -> dict:
    """Parse every event of a dataset into a full graph payload.

    The payload contains lightweight ``elements`` (no raw logs) plus a
    ``raw_logs`` side map keyed by element id, used by the lazy detail endpoint.
    """
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    # ``yield_per`` streams rows instead of materialising every JSONB blob at
    # once, keeping peak memory bounded for large datasets.
    logs = (
        db.query(LogEvent)
        .filter(LogEvent.dataset_id == dataset_id)
        .order_by(LogEvent.id)
        .yield_per(1000)
    )
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


def _get_graph_payload(dataset_id: int, db: Session) -> dict:
    """Return the cached graph payload, building and caching it on a miss."""
    cached = graph_cache.get(dataset_id)
    if cached is not None:
        return cached

    payload = _build_graph_payload(dataset_id, db)
    graph_cache.put(dataset_id, payload)
    return payload


@router.get("/{dataset_id}")
def generate_graph(dataset_id: int, db: Session = Depends(get_db)):
    payload = _get_graph_payload(dataset_id, db)
    # Raw logs are intentionally omitted here so the initial response and the
    # in-browser graph stay small; they are fetched on demand below. Unmapped
    # events are aggregated to counts so the payload does not carry one entry
    # per event.
    return {
        "elements": payload["elements"],
        "unmapped_events": dict(Counter(payload["unmapped_events"])),
    }


@router.get("/{dataset_id}/element-logs")
def get_element_logs(
    dataset_id: int,
    element_id: str = Query(..., description="Node or edge id from the graph payload"),
    db: Session = Depends(get_db),
):
    payload = _get_graph_payload(dataset_id, db)
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

    Process node ids are the ``str(pid)`` the builder uses, so the actor/target
    pids map directly; artifacts keep their own id scheme and are not mapped.
    """
    ids = []
    for key in ("actor_id", "target_id"):
        value = ctx.get(key)
        if value not in (None, ""):
            ids.append(str(value))
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
    db: Session = Depends(get_db),
):
    """Return the hidden elements of a collapsed cluster, on demand."""
    payload = _get_graph_payload(dataset_id, db)
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
    db: Session = Depends(get_db),
):
    """Return the subgraph within ``depth`` hops of ``element_id``.

    Backs lazy/progressive exploration: the browser can pull in a neighbourhood
    without re-parsing or re-shipping the whole graph.
    """
    payload = _get_graph_payload(dataset_id, db)
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
