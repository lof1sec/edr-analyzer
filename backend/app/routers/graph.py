from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Dataset, GraphLayout, LogEvent
from app.parsers.builder import GraphBuilder
from app.parsers.defender import parse_defender_event
from app.parsers.falcon import parse_falcon_event
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

        if vendor == FALCON:
            actor_id = event.get("ContextProcessId") or event.get("SourceProcessId") or event.get("ParentProcessId")
            actor_name = event.get("ContextBaseFileName") or event.get("ParentBaseFileName")
            target_id = event.get("TargetProcessId")
            target_name = event.get("FileName") or event.get("TargetFileName", "")
            username = event.get("UserName", "Unknown")
            hostname = event.get("ComputerName", "")
            if not actor_id and target_id:
               actor_id = target_id

            parse_falcon_event(builder, event, evt_type, actor_id, actor_name, target_id, target_name, username, hostname)
        elif vendor == DEFENDER:
            actor_id = event.get("InitiatingProcessId")
            actor_name = event.get("InitiatingProcessFileName")
            target_id = event.get("ProcessId")
            target_name = event.get("FileName")
            domain = event.get("AccountDomain", "")
            user = event.get("AccountName", "Unknown")
            username = f"{domain}\\{user}" if domain and user != "Unknown" else user
            hostname = event.get("DeviceName", "")

            parse_defender_event(builder, event, evt_type, actor_id, actor_name, target_id, target_name, username, hostname)
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
