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
async def upload_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are allowed")

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

    # Parse CSV and store to DB
    csv_reader = csv.DictReader(StringIO(text))

    log_events = []
    for row in csv_reader:
        # ActionType is the common key for defender logs, fallback to unknown
        event_type = row.get("ActionType", "Unknown")

        log_event = LogEvent(
            dataset_id=dataset.id,
            event_type=event_type,
            data=row
        )
        log_events.append(log_event)

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
