import codecs
import csv
import io
import json
import os
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Dataset, GraphLayout, LogEvent
from app.parsers.timestamps import extract_timestamp
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
MAX_JSON_EVENT_MB = 8
MAX_JSON_EVENT_BYTES = MAX_JSON_EVENT_MB * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_CSV_FIELD_CHARS = 1024 * 1024


def _validate_json_event(row):
    pending = [(row, 1)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            if depth > MAX_JSON_DEPTH:
                raise HTTPException(400, "JSON event exceeds maximum nesting depth")
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children if isinstance(child, (dict, list)))
    if len(json.dumps(row, ensure_ascii=False).encode("utf-8")) > MAX_JSON_EVENT_BYTES:
        raise HTTPException(413, "JSON event exceeds maximum size")


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

    if encoding == "utf-8-sig":
        # Flush the incremental decoder: a trailing truncated multi-byte
        # sequence (e.g. b"\xc2") is only reported once the input is final.
        # Without this the file is misdetected as UTF-8 and decoding later
        # raises inside the parser instead of falling back to latin-1.
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            encoding = "latin-1"

    file_obj.seek(0)
    return encoding


def _iter_clean_lines(file_obj, encoding, max_chars=None):
    """Yield decoded lines with NUL bytes removed, without buffering the file."""
    stream = io.TextIOWrapper(file_obj, encoding=encoding, newline="")
    try:
        while True:
            line = stream.readline(max_chars + 1) if max_chars is not None else stream.readline()
            if not line:
                break
            if max_chars is not None and len(line) > max_chars:
                raise HTTPException(413, "Upload record exceeds maximum size")
            if "\x00" in line:
                line = line.replace("\x00", "")
            yield line
    finally:
        try:
            stream.detach()
        except ValueError:
            # The underlying buffer was already closed (the generator was
            # garbage-collected without being fully consumed).
            pass


def _remove_json_nuls(event: dict) -> None:
    """Strip decoded NUL characters from a JSON event before storing it as JSONB.

    JSON escapes such as ``\\u0000`` survive the input-stream cleanup and are
    decoded into literal NULs by ``json.loads``. PostgreSQL rejects these even
    inside nested strings or keys. Walk one event at a time, iteratively, so a
    large upload never has to be materialised or recursively copied.
    """
    pending = [event]
    while pending:
        container = pending.pop()
        if isinstance(container, list):
            for index, value in enumerate(container):
                if isinstance(value, str):
                    if "\x00" in value:
                        container[index] = value.replace("\x00", "")
                elif isinstance(value, (dict, list)):
                    pending.append(value)
            continue

        renamed = []
        for key, value in container.items():
            if isinstance(value, str):
                if "\x00" in value:
                    container[key] = value.replace("\x00", "")
            elif isinstance(value, (dict, list)):
                pending.append(value)
            if "\x00" in key:
                renamed.append((key, key.replace("\x00", "")))

        for old_key, new_key in renamed:
            if new_key in container:
                raise HTTPException(
                    status_code=400,
                    detail="JSON keys collide after removing NUL characters",
                )
            container[new_key] = container.pop(old_key)


def _parse_csv_rows(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples for a CSV export.

    The event type is taken from whichever vendor marker is present
    (``ActionType`` for Defender, ``#event_simpleName`` for Falcon), so the
    vendor no longer depends on the file extension.
    """
    # csv.field_size_limit is interpreter-global; a separate per-row check below
    # enforces our own limit without changing global parser settings.
    reader = csv.DictReader(_iter_clean_lines(file_obj, encoding, MAX_JSON_EVENT_BYTES))
    try:
        for row in reader:
            if any(len(value) > MAX_CSV_FIELD_CHARS for value in row.values() if isinstance(value, str)):
                raise HTTPException(413, "CSV field exceeds maximum size")
            yield extract_event_type(row), row
    except csv.Error:
        # e.g. a field larger than csv.field_size_limit: a malformed export,
        # reported as a client error rather than an unhandled 500.
        raise HTTPException(status_code=400, detail="Failed to parse CSV file") from None


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
    need_separator = False
    after_comma = False

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
                if after_comma:
                    raise json.JSONDecodeError("Trailing comma", buffer, 0)
                if buffer[1:].strip() or any(
                    not character.isspace()
                    for chunk in iter(lambda: stream.read(4096), "")
                    for character in chunk
                ):
                    raise json.JSONDecodeError("Trailing data", buffer, 1)
                return
            if buffer[0] == ",":
                if not need_separator:
                    raise json.JSONDecodeError("Unexpected comma", buffer, 0)
                buffer = buffer[1:]
                need_separator = False
                after_comma = True
                continue
            if need_separator:
                raise json.JSONDecodeError("Missing comma", buffer, 0)
            try:
                value, end = decoder.raw_decode(buffer)
            except json.JSONDecodeError as exc:
                if eof:
                    raise exc
                if len(buffer.encode("utf-8")) > MAX_JSON_EVENT_BYTES:
                    raise HTTPException(413, "JSON event exceeds maximum size") from None
                fill()
                continue
            if len(buffer[:end].encode("utf-8")) > MAX_JSON_EVENT_BYTES:
                raise HTTPException(413, "JSON event exceeds maximum size")
            buffer = buffer[end:]
            need_separator = True
            after_comma = False
            yield value
    finally:
        try:
            stream.detach()
        except ValueError:
            # The underlying buffer was already closed (the generator was
            # garbage-collected without being fully consumed).
            pass


def _parse_json_array(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples from a streamed JSON array."""
    try:
        for row in _iter_json_array(file_obj, encoding):
            if isinstance(row, dict):
                _validate_json_event(row)
                _remove_json_nuls(row)
                yield extract_event_type(row), row
    except (json.JSONDecodeError, RecursionError):
        raise HTTPException(status_code=400, detail="Failed to parse JSON file") from None


def _parse_json_document(file_obj, encoding):
    """Parse the whole upload as a single JSON document (a lone object)."""
    file_obj.seek(0)
    raw_bytes = file_obj.read(MAX_JSON_EVENT_BYTES + 1)
    if len(raw_bytes) > MAX_JSON_EVENT_BYTES:
        raise HTTPException(413, "JSON event exceeds maximum size")
    raw = raw_bytes.decode(encoding, errors="replace").replace("\x00", "")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, RecursionError):
        raise HTTPException(status_code=400, detail="Failed to parse JSON file") from None

    # Accept a single event object (arrays never reach this fallback).
    if isinstance(data, dict):
        _validate_json_event(data)
        _remove_json_nuls(data)
        yield extract_event_type(data), data


def _parse_json_rows(file_obj, encoding):
    """Yield ``(event_type, row)`` tuples for Falcon JSONL or a JSON array."""
    if _looks_like_json_array(file_obj, encoding):
        yield from _parse_json_array(file_obj, encoding)
        return

    parsed_any = False
    for line in _iter_clean_lines(file_obj, encoding, MAX_JSON_EVENT_BYTES):
        if len(line.encode("utf-8")) > MAX_JSON_EVENT_BYTES:
            raise HTTPException(413, "JSON event exceeds maximum size")
        line = line.strip()
        if not line or line in ("[", "]", "{", "}", "},"):
            continue
        if line.endswith(","):
            line = line[:-1]
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            continue
        if isinstance(row, dict):
            _validate_json_event(row)
            _remove_json_nuls(row)
            parsed_any = True
            yield extract_event_type(row), row

    if parsed_any:
        return

    # Lines did not parse: the file may be a single (pretty-printed) document.
    yield from _parse_json_document(file_obj, encoding)


def _flush_batch(db: Session, batch: list) -> None:
    if batch:
        db.bulk_save_objects(batch)
        batch.clear()


@router.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    timezone: str | None = Form(None),
    db: Session = Depends(get_db),
):
    filename = (file.filename or "").lower()
    is_csv = filename.endswith(".csv")
    is_json = filename.endswith((".json", ".jsonl"))

    if not (is_csv or is_json):
        raise HTTPException(status_code=400, detail="Only CSV, JSON, or JSONL files are allowed")

    naive_timezone = None
    if timezone is not None:
        try:
            naive_timezone = ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid IANA timezone") from None

    # Cheap pre-check when the multipart parser reported the size.
    reported_size = getattr(file, "size", None)
    if reported_size is not None and reported_size > MAX_UPLOAD_SIZE_BYTES:
        raise _file_too_large()

    # This also enforces the limit by counting the real bytes on disk.
    encoding = _detect_encoding_and_check_size(file.file)

    dataset = Dataset(name=file.filename)
    db.add(dataset)
    db.flush()

    row_iterator = (
        _parse_csv_rows(file.file, encoding)
        if is_csv
        else _parse_json_rows(file.file, encoding)
    )

    total_events = 0
    batch = []
    try:
        for event_type, row in row_iterator:
            batch.append(LogEvent(
                dataset_id=dataset.id,
                event_type=event_type,
                event_time=extract_timestamp(row, naive_timezone if is_csv else None),
                data=row,
            ))
            total_events += 1
            if len(batch) >= INSERT_BATCH_SIZE:
                _flush_batch(db, batch)
        _flush_batch(db, batch)

        if total_events == 0:
            raise HTTPException(status_code=400, detail="No valid log events found in file")
        # Keep all batches in one transaction: a late parser/database failure
        # rolls back the dataset and every inserted event together.
        db.commit()
    except Exception:
        db.rollback()
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
    # The saved layout belongs to the dataset; delete it explicitly so a reused
    # dataset id never inherits a previous graph's arrangement.
    db.query(GraphLayout).filter(GraphLayout.dataset_id == dataset_id).delete(
        synchronize_session=False
    )
    db.delete(dataset)
    db.commit()

    # Free the cached graph so a reused dataset id never serves stale data.
    graph_cache.invalidate(dataset_id)

    return {"message": "Dataset deleted successfully"}
