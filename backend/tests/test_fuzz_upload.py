"""Property tests: the upload parsing helpers must turn any bytes into either
rows or a clean client error (HTTP 400/413), never an unhandled exception."""
import io

import pytest
from fastapi import HTTPException
from hypothesis import given
from hypothesis import strategies as st

from app.routers import datasets as ds


def _parse(data: bytes, kind: str):
    encoding = ds._detect_encoding_and_check_size(io.BytesIO(data))
    parse_fn = ds._parse_csv_rows if kind == "csv" else ds._parse_json_rows
    return list(parse_fn(io.BytesIO(data), encoding))


@given(data=st.binary(max_size=2048))
def test_upload_parsers_only_raise_client_errors(data):
    for kind in ("csv", "json"):
        try:
            rows = _parse(data, kind)
        except HTTPException as exc:
            assert exc.status_code in (400, 413)
        else:
            for evt_type, row in rows:
                assert isinstance(evt_type, str)
                assert isinstance(row, dict)


def test_truncated_utf8_falls_back_to_latin1():
    # b"\xc2" is an incomplete UTF-8 sequence. The size/encoding probe must
    # finalise its decoder and pick latin-1; otherwise the file is misdetected
    # as UTF-8 and decoding raises inside the parser.
    encoding = ds._detect_encoding_and_check_size(io.BytesIO(b"\xc2"))
    assert encoding == "latin-1"


def test_csv_field_over_limit_is_a_400_not_a_crash():
    # A single field larger than csv.field_size_limit (128 KiB by default).
    data = b'ActionType,Data\nProcessCreated,"' + b"x" * 140000 + b'"\n'
    with pytest.raises(HTTPException) as excinfo:
        _parse(data, "csv")
    assert excinfo.value.status_code == 400


def test_deeply_nested_json_is_a_400_not_a_crash():
    # Nesting beyond the interpreter recursion limit must not escape as a 500.
    data = b"[" * 5000
    with pytest.raises(HTTPException) as excinfo:
        _parse(data, "json")
    assert excinfo.value.status_code == 400
