import csv
import json
from io import StringIO
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Dataset, LogEvent
from app.schemas import DatasetResponse

router = APIRouter(prefix="/api/datasets", tags=["Datasets"])

@router.post("/upload")
async def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    is_csv = file.filename.lower().endswith('.csv')
    is_json = file.filename.lower().endswith(('.json', '.jsonl'))

    if not (is_csv or is_json):
        raise HTTPException(status_code=400, detail="Only CSV, JSON, or JSONL files are allowed")

    contents = await file.read()
    try:
        text = contents.decode('utf-8-sig').replace('\x00', '') # Handle BOM if present
    except UnicodeDecodeError:
        text = contents.decode('latin-1').replace('\x00', '')

    # Create new dataset entry
    dataset = Dataset(name=file.filename)
    db.add(dataset)
    db.commit()
    db.refresh(dataset)

    log_events = []

    if is_csv:
        # Parse CSV (Typically MS Defender)
        csv_reader = csv.DictReader(StringIO(text))
        for row in csv_reader:
            event_type = row.get("ActionType", "Unknown")
            log_events.append(LogEvent(dataset_id=dataset.id, event_type=event_type, data=row))
    else:
        # Parse JSON/JSONL (Typically CrowdStrike Falcon)
        lines = text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Handle if file is a single JSON array instead of JSONL
            if line == '[' or line == ']' or line == '},' or line == '{':
                continue

            try:
                # Remove trailing comma if present in formatted json array
                if line.endswith(','):
                    line = line[:-1]
                row = json.loads(line)

                # Falcon uses #event_simpleName
                event_type = row.get("#event_simpleName", "Unknown")
                log_events.append(LogEvent(dataset_id=dataset.id, event_type=event_type, data=row))
            except json.JSONDecodeError:
                # Attempt to parse entire file as one JSON array if line-by-line fails
                pass

        if not log_events:
            try:
                data_array = json.loads(text)
                if isinstance(data_array, list):
                    for row in data_array:
                        event_type = row.get("#event_simpleName", "Unknown")
                        log_events.append(LogEvent(dataset_id=dataset.id, event_type=event_type, data=row))
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Failed to parse JSON file")

    if not log_events:
        raise HTTPException(status_code=400, detail="No valid log events found in file")

    db.bulk_save_objects(log_events)
    db.commit()

    return {"message": f"Successfully uploaded and parsed {len(log_events)} logs", "dataset_id": dataset.id}


@router.get("/", response_model=list[DatasetResponse])
def get_datasets(db: Session = Depends(get_db)):
    datasets = db.query(Dataset).all()
    result = []
    for ds in datasets:
        count = db.query(LogEvent).filter(LogEvent.dataset_id == ds.id).count()
        result.append(
            DatasetResponse(
                id=ds.id,
                name=ds.name,
                created_at=ds.created_at,
                log_count=count
            )
        )
    return result

@router.delete("/{dataset_id}")
def delete_dataset(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    db.delete(dataset)
    db.commit()
    return {"message": "Dataset deleted successfully"}
