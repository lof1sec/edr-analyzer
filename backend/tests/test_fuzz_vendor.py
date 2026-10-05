"""Property tests: vendor detection must never raise on any input."""
from hypothesis import given
from hypothesis import strategies as st

from app.parsers.vendor import (
    DEFENDER,
    FALCON,
    UNKNOWN,
    extract_event_type,
    get_vendor,
    is_falcon_event,
)
from tests.strategies import event_dict, json_value

VALID_VENDORS = {FALCON, DEFENDER, UNKNOWN}

# Anything a decoded event could be: dicts are the norm, but a bad export can
# leave a scalar or a list at the top level.
any_value = st.one_of(event_dict, st.lists(json_value), st.none(), st.integers(), st.text())


@given(event=any_value)
def test_get_vendor_never_crashes(event):
    assert get_vendor(event) in VALID_VENDORS


@given(event=any_value)
def test_is_falcon_event_always_bool(event):
    assert isinstance(is_falcon_event(event), bool)


@given(event=any_value, default=st.text(max_size=20))
def test_extract_event_type_is_always_text(event, default):
    assert isinstance(extract_event_type(event, default), str)
