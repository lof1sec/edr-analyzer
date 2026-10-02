from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Dataset, LogEvent
from app.parsers.builder import GraphBuilder
from app.parsers.defender import parse_defender_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.vendor import DEFENDER, FALCON, get_vendor
from app.routers import graph_cache

router = APIRouter(prefix="/api/graph", tags=["Graph"])


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
