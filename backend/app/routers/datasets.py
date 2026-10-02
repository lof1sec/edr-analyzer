import codecs
import csv
import io
import json
import os

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Dataset, LogEvent
from app.parsers.vendor import extract_event_type
from app.routers import graph_cache
from app.routers.auth import require_user
from app.schemas import DatasetResponse

router = APIRouter(
    prefix="/api/datasets",
    tags=["Datasets"],
    dependencies=[Depends(require_user)],
)

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
    """Yield ``(event_type, row)`` tuples for a CSV export.

    The event type is taken from whichever vendor marker is present
    (``ActionType`` for Defender, ``#event_simpleName`` for Falcon), so the
    vendor no longer depends on the file extension.
    """
    reader = csv.DictReader(_iter_clean_lines(file_obj, encoding))
    for row in reader:
        yield extract_event_type(row), row


def _looks_like_json_array(file_obj, encoding) -> bool:
    """Peek at the first non-whitespace character to tell arrays from JSONL."""
    file_obj.seek(0)
    head = file_obj.read(4096)
    file_obj.seek(0)
    try:
        text = head.decode(encoding, errors="ignore")
    except LookupError:
        return False
    return text.lstrip().startswith("[")


def _iter_json_array(file_obj, encoding):
    """Yield the values of a top-level JSON array incrementally.

    A large ``.json`` array must not be read into memory in one go (the upload
    cap defaults to 200 MB), so this walks the stream in ``CHUNK_SIZE`` chunks
    and uses ``JSONDecoder.raw_decode`` to pull out one value at a time.

    Raises ``json.JSONDecodeError`` on a malformed/truncated array so the caller
    can turn it into an HTTP 400.
    """
    stream = io.TextIOWrapper(file_obj, encoding=encoding, newline="")
    decoder = json.JSONDecoder()
    buffer = ""
    eof = False

    def fill():
        nonlocal buffer, eof
        if eof:
            return
        chunk = stream.read(CHUNK_SIZE)
        if chunk:
            buffer += chunk.replace("\x00", "")
        else:
            eof = True

    try:
        # Find the opening bracket, skipping leading whitespace.
        while True:
            buffer = buffer.lstrip()
            if buffer:
                break
            fill()
            if eof and not buffer:
                return
        if buffer[0] != "[":
            return
        buffer = buffer[1:]

        while True:
            buffer = buffer.lstrip()
            if not buffer:
                if eof:
                    raise json.JSONDecodeError("Unterminated JSON array", buffer, 0)
                fill()
                continue
            if buffer[0] == "]":
                return
            if buffer[0] == ",":
                buffer = buffer[1:]
                continue
            try:
                value, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError as exc:
                if eof:
                    raise exc
                fill()
                continue
            buffer = buffer[end:]
            yield value
    finally:
        stream.detach()


def _parse_json_array(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples from a streamed JSON array."""
    try:
        for row in _iter_json_array(file_obj, encoding):
            if isinstance(row, dict):
                yield extract_event_type(row), row
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Failed to parse JSON file") from None


def _parse_json_document(file_obj, encoding):
    """Parse the whole upload as a single JSON document (a lone object)."""
    file_obj.seek(0)
    raw = file_obj.read().decode(encoding, errors="replace").replace("\x00", "")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Failed to parse JSON file") from None

    # Accept a single event object (arrays never reach this fallback).
    if isinstance(data, dict):
        yield extract_event_type(data), data


def _parse_json_rows(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples for Falcon JSONL or a JSON array."""
    if _looks_like_json_array(file_obj, encoding):
        yield from _parse_json_array(file_obj, encoding)
        return

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
            yield extract_event_type(row), row

    if parsed_any:
        return

    # Lines did not parse: the file may be a single (pretty-printed) document.
    yield from _parse_json_document(file_obj, encoding)


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

    # A freshly uploaded dataset has no cached graph, but an id could be reused
    # after a delete; drop any stale payload defensively.
    graph_cache.invalidate(dataset.id)

    return {
        "message": f"Successfully uploaded and parsed {total_events} logs",
        "dataset_id": dataset.id,
    }


@router.get("/", response_model=list[DatasetResponse])
def get_datasets(db: Session = Depends(get_db)):
    # Single aggregate query instead of one COUNT per dataset (N+1).
    rows = (
        db.query(Dataset, func.count(LogEvent.id))
        .outerjoin(LogEvent, LogEvent.dataset_id == Dataset.id)
        .group_by(Dataset.id)
        .order_by(Dataset.id)
        .all()
    )
    return [
        DatasetResponse(
            id=ds.id,
            name=ds.name,
            created_at=ds.created_at,
            log_count=log_count,
        )
        for ds, log_count in rows
    ]

@router.delete("/{dataset_id}")
def delete_dataset(dataset_id: int, db: Session = Depends(get_db)):
    dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")

    # Bulk-delete the events instead of letting the ORM cascade load and delete
    # them one by one, which is very slow for large datasets.
    db.query(LogEvent).filter(LogEvent.dataset_id == dataset_id).delete(
        synchronize_session=False
    )
    db.delete(dataset)
    db.commit()

    # Free the cached graph so a reused dataset id never serves stale data.
    graph_cache.invalidate(dataset_id)

    return {"message": "Dataset deleted successfully"}
