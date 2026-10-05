"""Shared Hypothesis strategies and graph invariants for the parser fuzz tests.

Events are shaped to look like what the parsers actually receive after a CSV or
JSON export: JSON-like scalars (including ``None`` and numbers) and nested
arrays/objects. Event types are biased toward the values the parsers branch on
so real code paths are exercised instead of only the fallback branch.
"""
import json

from hypothesis import strategies as st

# --- Values and event shapes -------------------------------------------------

# A value a JSON export may deliver for any field.
json_value = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=12,
)

event_dict = st.dictionaries(st.text(max_size=12), json_value, max_size=20)


def _graph_id() -> st.SearchStrategy:
    """A graph element id as it arrives from a CSV (text) or JSON (any scalar).

    ``edge_``-prefixed node ids are excluded: the builder reserves that
    namespace for edge ids, and real node ids never use it.
    """
    return st.one_of(
        st.integers(min_value=1, max_value=100_000),
        st.text(min_size=1, max_size=24).filter(
            lambda value: not value.startswith("edge_")
        ),
    )


graph_id = _graph_id()

# Ids/names that a parser argument may legitimately be missing or empty.
optional_id = st.one_of(st.none(), graph_id)


# --- Known event types (real branches) ---------------------------------------

DEFENDER_EVENT_TYPES = [
    "ProcessCreated",
    "PowerShellCommand",
    "ClrUnbackedModuleLoaded",
    "LdapSearch",
    "PnpDeviceAllowed",
    "PnpDeviceConnected",
    "GetClipboardData",
    "ProcessCreatedUsingWmiQuery",
    "NamedPipeEvent",
    "DpapiAccessed",
    "BrowserLaunchedToOpenUrl",
    "AntivirusReport",
    "FileCreated",
    "FileModified",
    "FileDeleted",
    "FileRenamed",
    "ShellLinkCreateFileEvent",
    "ImageLoaded",
    "DriverLoad",
    "RegistryKeyCreated",
    "RegistryValueCreated",
    "RegistryValueSet",
    "RegistryKeyDeleted",
    "RegistryValueDeleted",
    "ConnectionSuccess",
    "ConnectionFailed",
    "NetworkConnectionEvents",
    "NetworkCommunicationEvents",
    "ListeningPortCreated",
    "ListeningConnectionCreated",
    "InboundConnectionAccepted",
    "RemoteDesktopConnection",
    "HttpConnectionInspected",
    "ConnectionAcknowledged",
    "ConnectionDropped",
    "DnsConnectionInspected",
    "SslConnectionInspected",
]

FALCON_EVENT_TYPES = [
    "ProcessRollup2",
    "ProcessAncestryInformation",
    "AssociateIndicator",
    "UserLogon",
    "UserIdentity",
    "IoSessionLoggedOn",
    "NewScriptWritten",
    "NewExecutableWritten",
    "SuspiciousPeFileWritten",
    "ExecutableDeleted",
    "SuspiciousCreateSymbolicLink",
    "ScheduledTaskModified",
    "FirewallSetRule",
    "FirewallDeleteRule",
    "DriverLoad",
    "AsepValueUpdate",
    "RegKeyCommit",
    "RegValueCommit",
    "RegSystemConfigValueUpdate",
    "NetworkReceiveAcceptIP4",
    "NetworkConnectIP4",
    "NetworkConnectIP6",
    "DnsRequest",
    "NeighborListIP4",
    "LFODownloadConfirmation",
    "ModuleCertificateInfo2",
    "UserLogoff",
    "CommandHistory",
]


def event_type_strategy(known_types):
    """Known branch types (real paths) mixed with arbitrary text (robustness)."""
    return st.one_of(st.sampled_from(known_types), st.text(min_size=1, max_size=40))


# --- Shared invariants -------------------------------------------------------


def assert_graph_invariants(payload: dict) -> None:
    """Assert every invariant a built graph payload must satisfy.

    * the payload is JSON-serialisable (the browser must be able to load it),
    * node ids and edge ids are each unique and never collide with each other,
    * every edge points at a node present in the payload (no dangling edge).
    """
    json.dumps(payload)

    nodes = payload["elements"]["nodes"]
    edges = payload["elements"]["edges"]
    node_ids = [node["data"]["id"] for node in nodes]
    edge_ids = [edge["data"]["id"] for edge in edges]

    assert len(node_ids) == len(set(node_ids))
    assert len(edge_ids) == len(set(edge_ids))
    assert not (set(node_ids) & set(edge_ids))

    known = set(node_ids)
    for edge in edges:
        source = edge["data"]["source"]
        target = edge["data"]["target"]
        assert source in known, source
        assert target in known, target
