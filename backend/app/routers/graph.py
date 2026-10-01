from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import LogEvent, Dataset
from app.parsers.builder import GraphBuilder
from app.parsers.falcon import parse_falcon_event
from app.parsers.defender import parse_defender_event

router = APIRouter(prefix="/api/graph", tags=["Graph"])

@router.get("/{dataset_id}")
def generate_graph(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    logs = db.query(LogEvent).filter(LogEvent.dataset_id == dataset_id).all()
    builder = GraphBuilder()

    for log in logs:
        event = log.data
        evt_type = log.event_type

        # Check if this is a CrowdStrike Falcon event (presence of #event_simpleName)
        is_falcon = "#event_simpleName" in event

        if is_falcon:
            actor_id = event.get("ContextProcessId") or event.get("SourceProcessId") or event.get("ParentProcessId")
            actor_name = event.get("ContextBaseFileName") or event.get("ParentBaseFileName")
            target_id = event.get("TargetProcessId")
            target_name = event.get("FileName") or event.get("TargetFileName", "")
            username = event.get("UserName", "Unknown")
            hostname = event.get("ComputerName", "")
            if not actor_id and target_id:
               actor_id = target_id

            parse_falcon_event(builder, event, evt_type, actor_id, actor_name, target_id, target_name, username, hostname)
        else:
            actor_id = event.get("InitiatingProcessId")
            actor_name = event.get("InitiatingProcessFileName")
            target_id = event.get("ProcessId")
            target_name = event.get("FileName")
            domain = event.get("AccountDomain", "")
            user = event.get("AccountName", "Unknown")
            username = f"{domain}\\{user}" if domain and user != "Unknown" else user
            hostname = event.get("DeviceName", "")

            parse_defender_event(builder, event, evt_type, actor_id, actor_name, target_id, target_name, username, hostname)

    return builder.build_cytoscape_elements()
