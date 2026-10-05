"""Centralised detection of the EDR product that produced a log event.

Relying on the file extension (CSV vs JSON) is unreliable: both products can be
exported in either format. Detect the vendor from the event fields instead, and
extract the event type from whichever marker is present.
"""
from typing import Any

FALCON_EVENT_TYPE_FIELD = "#event_simpleName"
DEFENDER_EVENT_TYPE_FIELD = "ActionType"

FALCON = "falcon"
DEFENDER = "defender"
UNKNOWN = "unknown"


def get_vendor(event: Any) -> str:
    """Return ``FALCON``, ``DEFENDER`` or ``UNKNOWN`` for a parsed event."""
    if not isinstance(event, dict):
        return UNKNOWN
    if FALCON_EVENT_TYPE_FIELD in event:
        return FALCON
    if DEFENDER_EVENT_TYPE_FIELD in event:
        return DEFENDER
    return UNKNOWN


def extract_event_type(event: Any, default: str = "Unknown") -> str:
    """Return the event type, regardless of which EDR product produced it.

    The marker value is always returned as text: a JSON export may carry it as a
    number, and the result is stored in a string database column.
    """
    if not isinstance(event, dict):
        return default
    value = event.get(FALCON_EVENT_TYPE_FIELD)
    if value is None:
        value = event.get(DEFENDER_EVENT_TYPE_FIELD)
    if value is None or value == "":
        return default
    return value if isinstance(value, str) else str(value)


def is_falcon_event(event: Any) -> bool:
    """Whether the event carries the CrowdStrike Falcon marker."""
    return isinstance(event, dict) and FALCON_EVENT_TYPE_FIELD in event
