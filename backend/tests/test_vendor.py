import pytest

from app.parsers.vendor import (
    DEFENDER,
    FALCON,
    UNKNOWN,
    extract_event_type,
    get_vendor,
    is_falcon_event,
)


@pytest.mark.parametrize(
    "event, expected",
    [
        ({"#event_simpleName": "ProcessRollup2"}, FALCON),
        ({"#event_simpleName": "ProcessRollup2", "Type": "DeviceProcessEvents"}, FALCON),
        ({"ActionType": "ProcessCreated"}, DEFENDER),
        ({"Type": "DeviceProcessEvents"}, DEFENDER),
        ({"Type": "DeviceInfo"}, DEFENDER),
        ({"Type": "DisruptionAndResponseEvents"}, DEFENDER),
        ({"Type": "UnknownTable"}, UNKNOWN),
        ({"foo": "bar"}, UNKNOWN),
        ({}, UNKNOWN),
        ("not a dict", UNKNOWN),
        (None, UNKNOWN),
    ],
)
def test_get_vendor(event, expected):
    assert get_vendor(event) == expected


@pytest.mark.parametrize(
    "event, expected",
    [
        ({"#event_simpleName": "DnsRequest"}, "DnsRequest"),
        ({"ActionType": "FileCreated"}, "FileCreated"),
        ({"Type": "DeviceProcessEvents", "ActionType": "ProcessCreated"}, "ProcessCreated"),
        ({"Type": "DeviceInfo"}, "DeviceInfo"),
        ({"Type": "DeviceFileCertificateInfo", "ActionType": ""}, "DeviceFileCertificateInfo"),
        ({"#event_simpleName": ""}, "Unknown"),
        ({"foo": "bar"}, "Unknown"),
        ("not a dict", "Unknown"),
    ],
)
def test_extract_event_type(event, expected):
    assert extract_event_type(event) == expected


def test_is_falcon_event():
    assert is_falcon_event({"#event_simpleName": "X"}) is True
    assert is_falcon_event({"ActionType": "X"}) is False
    assert is_falcon_event("not a dict") is False
