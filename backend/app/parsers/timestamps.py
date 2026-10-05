"""Normalise an event's timestamp for the chronological timeline.

Exports differ in both field name (Falcon ``timestamp``, Defender ``Timestamp``…)
and format (epoch seconds/milliseconds or ISO-8601), so the timeline relies on a
single normalised value: epoch milliseconds. Anything that cannot be parsed
becomes ``None``; the timeline then falls back to insertion order for that event.
"""
import math
import re
from datetime import UTC, datetime

FALCON_TIME_FIELDS = ("timestamp", "@timestamp")
DEFENDER_TIME_FIELDS = (
    "Timestamp",
    "EventTime",
    "TimestampUtc",
    "UtcTime",
    "LocalTime",
    "CreationTime",
)

# Defender first, then Falcon: events are single-vendor, so the order only
# decides which field wins if a mixed export carries several at once.
_CANDIDATE_FIELDS = DEFENDER_TIME_FIELDS + FALCON_TIME_FIELDS

_NUMERIC = re.compile(r"^[+-]?\d+(\.\d+)?$")

# Epoch values above this (seconds / 1000 = year ~5138) are assumed to already
# be milliseconds. Keeps both common epoch units working.
_MS_THRESHOLD = 1e11

# Reject implausible epochs (after 9999-12-31) so a corrupt value cannot yield a
# meaningless timestamp.
_MAX_EPOCH_MS = 253_402_300_799_999


def extract_timestamp(event) -> int | None:
    """Return the event time as epoch milliseconds, or ``None`` if unknown."""
    if not isinstance(event, dict):
        return None
    for field in _CANDIDATE_FIELDS:
        value = event.get(field)
        if value is None:
            continue
        parsed = _parse_timestamp(value)
        if parsed is not None:
            return parsed
    return None


def _parse_timestamp(value) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (OverflowError, ValueError):
            return None
        return _epoch_to_ms(number)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if _NUMERIC.match(text):
            try:
                number = float(text)
            except (OverflowError, ValueError):
                return None
            return _epoch_to_ms(number)
        # ISO 8601 / RFC 3339. ``fromisoformat`` handles "Z" on 3.11+, but
        # normalising it keeps the behaviour explicit across versions.
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(iso)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp() * 1000)
    return None


def _epoch_to_ms(value: float) -> int | None:
    # ``NaN``/``inf`` reach here from JSON exports (Python's ``json`` accepts
    # ``NaN``/``Infinity``) and from oversized numeric strings; they must not
    # crash the upload, which extracts a timestamp on every row.
    if not math.isfinite(value) or value <= 0:
        return None
    try:
        ms = int(value) if value > _MS_THRESHOLD else int(value * 1000)
    except (OverflowError, ValueError):
        return None
    if ms <= 0 or ms > _MAX_EPOCH_MS:
        return None
    return ms


def format_timestamp(ms: int | None) -> str | None:
    """Return an ISO-8601 (UTC) string for epoch milliseconds, or ``None``."""
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat()
    except (OverflowError, OSError, ValueError):
        return None
