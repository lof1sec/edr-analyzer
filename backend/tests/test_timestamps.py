"""Unit tests for the timestamp normaliser used by the timeline."""
from datetime import UTC, datetime

from app.parsers.timestamps import extract_timestamp, format_timestamp


def _iso_ms(year, month, day, hour=0, minute=0, second=0):
    return int(datetime(year, month, day, hour, minute, second, tzinfo=UTC).timestamp() * 1000)


def test_epoch_seconds_string():
    assert extract_timestamp({"timestamp": "1700000000"}) == 1700000000000


def test_epoch_seconds_number():
    assert extract_timestamp({"timestamp": 1700000000}) == 1700000000000


def test_epoch_milliseconds_number():
    assert extract_timestamp({"timestamp": 1700000000000}) == 1700000000000


def test_epoch_fractional_seconds():
    assert extract_timestamp({"timestamp": "1700000000.5"}) == 1700000000500


def test_iso_string_with_z():
    expected = _iso_ms(2026, 10, 5, 12, 0, 0)
    assert extract_timestamp({"Timestamp": "2026-10-05T12:00:00Z"}) == expected


def test_iso_string_without_timezone_is_utc():
    expected = _iso_ms(2026, 10, 5, 12, 0, 0)
    assert extract_timestamp({"Timestamp": "2026-10-05T12:00:00"}) == expected


def test_defender_field_is_preferred_when_present():
    assert extract_timestamp({"Timestamp": "2026-10-05T12:00:00Z", "timestamp": "0"}) == _iso_ms(
        2026, 10, 5, 12, 0, 0
    )


def test_missing_or_invalid_returns_none():
    assert extract_timestamp({}) is None
    assert extract_timestamp({"timestamp": None}) is None
    assert extract_timestamp({"timestamp": "not-a-time"}) is None
    assert extract_timestamp({"timestamp": 0}) is None
    assert extract_timestamp("not a dict") is None


def test_format_timestamp():
    assert format_timestamp(None) is None
    assert format_timestamp(0) == "1970-01-01T00:00:00+00:00"


def test_non_finite_and_overflowing_values_return_none():
    # These reach ``extract_timestamp`` from real JSON exports (``json`` accepts
    # ``NaN``/``Infinity``) and from oversized numbers; they must never crash the
    # upload, which extracts a timestamp on every row.
    assert extract_timestamp({"timestamp": float("nan")}) is None
    assert extract_timestamp({"timestamp": float("inf")}) is None
    assert extract_timestamp({"timestamp": float("-inf")}) is None
    assert extract_timestamp({"timestamp": 10**400}) is None
    assert extract_timestamp({"timestamp": "9" * 400}) is None


def test_implausible_epoch_is_rejected():
    # The last millisecond of 9999 is accepted; a value past it is not.
    assert extract_timestamp({"timestamp": 253402300799999}) == 253402300799999
    assert extract_timestamp({"timestamp": 253402300800000}) is None
