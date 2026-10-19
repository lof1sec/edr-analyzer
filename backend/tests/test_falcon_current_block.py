"""Exact S-V Falcon routes and evidence boundaries."""

import pytest

from app.parsers.builder import GraphBuilder
from app.parsers.events import describe_event
from app.parsers.falcon import parse_falcon_event
from app.parsers.falcon_current_block import EVENTS
from app.parsers.vendor import FALCON


def graph(name, **fields):
    event = {"#event_simpleName": name, "ComputerName": "HOST", **fields}
    builder = GraphBuilder()
    builder.current_event_id = 42
    parse_falcon_event(builder, event, name, **describe_event(event, FALCON))
    return builder, builder.build_cytoscape_elements()


@pytest.mark.parametrize("name", sorted(EVENTS))
def test_exact_event_is_mapped_without_inferred_process_relationships(name):
    builder, payload = graph(name, ContextProcessId="10", TargetProcessId="20")
    assert not builder.unmapped_events
    assert builder.event_elements[42]["nodes"]
    assert all(edge["data"]["label"] == "Observed"
               for edge in payload["elements"]["edges"])
    assert "20@HOST" not in builder.nodes_dict
    assert ("10@HOST" in builder.nodes_dict) == (
        name not in {"UserIdentity", "SyntheticProcessRollup2"}
        and not name.startswith(("SpotlightEntity", "SignInfoWith", "Synthetic", "Telemetry", "User")))


@pytest.mark.parametrize("name", ["SmtpCommand", "SmtpEmailMessage", "SmtpAttachment",
                                   "SpotlightEntityBatch", "SignInfoWithCertAndContext",
                                   "UserIdentity", "UserLogonFailed", "UACExeElevation",
                                   "TerminateProcess", "SyntheticProcessRollup2"])
def test_payload_remains_raw_and_outcomes_are_not_invented(name):
    secret = "SECRET_PRIVATE_PAYLOAD"
    builder, payload = graph(name, ContextProcessId="10", CommandArg1=secret,
                             Body=secret, Attachment=secret, Recipient=secret,
                             EntityPayload=secret, Certificate=secret, Signature=secret)
    assert secret not in str(payload["elements"])
    assert secret in str(payload["raw_logs"])
    assert all(edge["data"]["label"] == "Observed"
               for edge in payload["elements"]["edges"])
    assert not builder.unmapped_events
