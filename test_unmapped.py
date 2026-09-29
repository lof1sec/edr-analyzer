import json
import pytest
from backend.app.models import Dataset, LogEvent
from backend.app.database import SessionLocal
from backend.app.routers.graph import generate_graph

def test_unmapped_events_are_tracked():
    # Setup db session and dummy dataset
    db = SessionLocal()
    try:
        ds = Dataset(name="TestDS")
        db.add(ds)
        db.commit()
        db.refresh(ds)

        # Add events
        events = [
            LogEvent(dataset_id=ds.id, event_type="ProcessCreated", data={"ActionType": "ProcessCreated", "InitiatingProcessId": "1", "ProcessId": "2"}),
            LogEvent(dataset_id=ds.id, event_type="UnknownEvent1", data={"ActionType": "UnknownEvent1", "InitiatingProcessId": "1", "ProcessId": "2"}),
            LogEvent(dataset_id=ds.id, event_type="UnknownEvent2", data={"ActionType": "UnknownEvent2", "InitiatingProcessId": "1", "ProcessId": "3"})
        ]
        db.add_all(events)
        db.commit()

        # Generate graph
        result = generate_graph(ds.id, db)

        # Assert unmapped events are caught
        unmapped = result.get("unmapped_events", [])
        assert len(unmapped) == 2
        assert "UnknownEvent1" in unmapped
        assert "UnknownEvent2" in unmapped

    finally:
        db.query(LogEvent).filter(LogEvent.dataset_id == ds.id).delete()
        db.query(Dataset).filter(Dataset.id == ds.id).delete()
        db.commit()
        db.close()
