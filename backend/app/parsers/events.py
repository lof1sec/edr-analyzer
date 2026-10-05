"""Per-vendor extraction of an event's actor/target/user/host fields.

Shared by the graph builder and the timeline so both read an event the same way.
Vendor detection itself stays field-based (``app/parsers/vendor.py``): callers
pass the vendor detected from the event's marker field.
"""
from app.parsers.vendor import DEFENDER, FALCON


def describe_event(event: dict, vendor: str) -> dict:
    """Return the actor/target/user/host fields used by the parsers.

    The returned values are the raw event values (they may be ``None``, numbers
    or strings); the parsers/``as_text`` coerce them as needed.
    """
    if vendor == FALCON:
        actor_id = (
            event.get("ContextProcessId")
            or event.get("SourceProcessId")
            or event.get("ParentProcessId")
        )
        actor_name = event.get("ContextBaseFileName") or event.get("ParentBaseFileName")
        target_id = event.get("TargetProcessId")
        target_name = event.get("FileName") or event.get("TargetFileName", "")
        username = event.get("UserName", "Unknown")
        hostname = event.get("ComputerName", "")
        if not actor_id and target_id:
            actor_id = target_id
    elif vendor == DEFENDER:
        actor_id = event.get("InitiatingProcessId")
        actor_name = event.get("InitiatingProcessFileName")
        target_id = event.get("ProcessId")
        target_name = event.get("FileName")
        domain = event.get("AccountDomain", "")
        user = event.get("AccountName", "Unknown")
        username = f"{domain}\\{user}" if domain and user != "Unknown" else user
        hostname = event.get("DeviceName", "")
    else:
        actor_id = actor_name = target_id = target_name = None
        username = "Unknown"
        hostname = ""

    return {
        "actor_id": actor_id,
        "actor_name": actor_name,
        "target_id": target_id,
        "target_name": target_name,
        "username": username,
        "hostname": hostname,
    }
