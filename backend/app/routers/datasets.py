import codecs
import csv
import io
import json
import os
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Dataset, LogEvent
from app.schemas import DatasetResponse

router = APIRouter(prefix="/api/datasets", tags=["Datasets"])

# --- Upload limits / tuning -------------------------------------------------
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "200"))
MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024
CHUNK_SIZE = 1024 * 1024  # 1 MiB
INSERT_BATCH_SIZE = 1000


def _file_too_large() -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=f"File is too large. The maximum allowed size is {MAX_UPLOAD_SIZE_MB} MB.",
    )


def _detect_encoding_and_check_size(file_obj) -> str:
    """Stream the upload once to enforce the size limit and pick an encoding.

    Returns ``"utf-8-sig"`` when the content is valid UTF-8 (with or without a
    BOM), otherwise falls back to ``"latin-1"``, matching the previous behaviour
    without ever loading the whole file into memory.
    """
    file_obj.seek(0)
    decoder = codecs.getincrementaldecoder("utf-8-sig")()
    encoding = "utf-8-sig"
    total = 0

    while True:
        chunk = file_obj.read(CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_SIZE_BYTES:
            raise _file_too_large()
        if encoding == "utf-8-sig":
            try:
                decoder.decode(chunk)
            except UnicodeDecodeError:
                # Not valid UTF-8: fall back to latin-1, which never fails.
                encoding = "latin-1"

    file_obj.seek(0)
    return encoding


def _iter_clean_lines(file_obj, encoding):
    """Yield decoded lines with NUL bytes removed, without buffering the file."""
    stream = io.TextIOWrapper(file_obj, encoding=encoding, newline="")
    try:
        for line in stream:
            if "\x00" in line:
                line = line.replace("\x00", "")
            yield line
    finally:
        stream.detach()


def _parse_csv_rows(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples for a Defender-style CSV export."""
    reader = csv.DictReader(_iter_clean_lines(file_obj, encoding))
    for row in reader:
        yield row.get("ActionType", "Unknown"), row


def _parse_json_rows(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples for Falcon JSONL or a JSON array."""
    parsed_any = False

    for line in _iter_clean_lines(file_obj, encoding):
        line = line.strip()
        if not line or line in ("[", "]", "{", "}", "},"):
            continue
        if line.endswith(","):
            line = line[:-1]
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            parsed_any = True
            yield row.get("#event_simpleName", "Unknown"), row

    if parsed_any:
        return

    # Fallback: the whole file might be a single (pretty-printed) JSON array.
    file_obj.seek(0)
    raw = file_obj.read().decode(encoding, errors="replace").replace("\x00", "")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Failed to parse JSON file")

    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                yield row.get("#event_simpleName", "Unknown"), row


def _flush_batch(db: Session, batch: list) -> None:
    if batch:
        db.bulk_save_objects(batch)
        db.commit()
        batch.clear()


@router.post("/upload")
def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = (file.filename or "").lower()
    is_csv = filename.endswith(".csv")
    is_json = filename.endswith((".json", ".jsonl"))

    if not (is_csv or is_json):
        raise HTTPException(status_code=400, detail="Only CSV, JSON, or JSONL files are allowed")

    # Cheap pre-check when the multipart parser reported the size.
    reported_size = getattr(file, "size", None)
    if reported_size is not None and reported_size > MAX_UPLOAD_SIZE_BYTES:
        raise _file_too_large()

    # This also enforces the limit by counting the real bytes on disk.
    encoding = _detect_encoding_and_check_size(file.file)

    dataset = Dataset(name=file.filename)
    db.add(dataset)
    db.commit()
    db.refresh(dataset)

    row_iterator = (
        _parse_csv_rows(file.file, encoding)
        if is_csv
        else _parse_json_rows(file.file, encoding)
    )

    total_events = 0
    batch = []
    try:
        for event_type, row in row_iterator:
            batch.append(LogEvent(dataset_id=dataset.id, event_type=event_type, data=row))
            total_events += 1
            if len(batch) >= INSERT_BATCH_SIZE:
                _flush_batch(db, batch)
        _flush_batch(db, batch)

        if total_events == 0:
            raise HTTPException(status_code=400, detail="No valid log events found in file")
    except HTTPException:
        # Don't leave an empty/partial dataset behind on a failed parse.
        db.rollback()
        db.query(LogEvent).filter(LogEvent.dataset_id == dataset.id).delete(
            synchronize_session=False
        )
        db.delete(dataset)
        db.commit()
        raise

    return {
        "message": f"Successfully uploaded and parsed {total_events} logs",
        "dataset_id": dataset.id,
    }


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
