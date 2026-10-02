import io

import pytest
from fastapi import HTTPException

from app.routers import datasets as ds


def parse(data: bytes, kind: str):
    """Run the upload parsing helpers over an in-memory buffer."""
    encoding = ds._detect_encoding_and_check_size(io.BytesIO(data))
    parse_fn = ds._parse_csv_rows if kind == "csv" else ds._parse_json_rows
    return list(parse_fn(io.BytesIO(data), encoding))


def test_csv_defender():
    data = b"ActionType,DeviceName\nProcessCreated,HOST1\nFileCreated,HOST1\n"
    assert [etype for etype, _ in parse(data, "csv")] == ["ProcessCreated", "FileCreated"]


def test_csv_falcon_marker():
    # A Falcon export delivered as CSV must still be recognised.
    data = b"#event_simpleName,ComputerName\nProcessRollup2,H1\nDnsRequest,H1\n"
    assert [etype for etype, _ in parse(data, "csv")] == ["ProcessRollup2", "DnsRequest"]


def test_utf8_bom_is_stripped():
    data = b"\xef\xbb\xbfActionType\nProcessCreated\n"
    assert parse(data, "csv")[0][0] == "ProcessCreated"


def test_latin1_fallback():
    data = b"ActionType,Data\nProcessCreated,caf\xe9\n"
    _, row = parse(data, "csv")[0]
    assert row["Data"] == "caf\u00e9"


def test_jsonl_mixed_vendors():
    data = b'{"ActionType":"ProcessCreated"}\n{"#event_simpleName":"DnsRequest"}\n'
    assert [etype for etype, _ in parse(data, "json")] == ["ProcessCreated", "DnsRequest"]


def test_json_array():
    data = b'[\n  {"ActionType": "ProcessCreated"},\n  {"#event_simpleName": "DnsRequest"}\n]\n'
    assert [etype for etype, _ in parse(data, "json")] == ["ProcessCreated", "DnsRequest"]


def test_single_json_object():
    data = b'{\n  "#event_simpleName": "UserLogon",\n  "ComputerName": "H1"\n}\n'
    assert [etype for etype, _ in parse(data, "json")] == ["UserLogon"]


def test_invalid_json_raises_400():
    with pytest.raises(HTTPException) as excinfo:
        parse(b"[ this is not json", "json")
    assert excinfo.value.status_code == 400


def test_size_limit_raises_413(monkeypatch):
    monkeypatch.setattr(ds, "MAX_UPLOAD_SIZE_BYTES", 10)
    with pytest.raises(HTTPException) as excinfo:
        ds._detect_encoding_and_check_size(io.BytesIO(b"x" * 11))
    assert excinfo.value.status_code == 413
