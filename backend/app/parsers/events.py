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
        if event.get("#event_simpleName") == "ClassifiedModuleLoad":
            # The target process loads ImageFileName; ContextProcessId only
            # identifies the origin of this telemetry record.
            actor_id = target_id
            process_path = event.get("TargetImageFileName")
            actor_name = (process_path.replace("\\", "/").split("/")[-1]
                          if isinstance(process_path, str) else None)
            target_name = event.get("ImageFileName")
        elif event.get("#event_simpleName") in ("InjectedThread", "DllInjection", "ProcessInjection"):
            actor_name = event.get("InjectorImageFileName") or actor_name
            target_name = (event.get("InjecteeImageFileName") or event.get("InjectedDll")
                           or target_id)
        elif event.get("#event_simpleName") == "NewExecutableRenamed":
            target_name = event.get("TargetFileName")
            actor_name = event.get("SourceFileName") or actor_name
        elif event.get("#event_simpleName") == "ReflectiveDotnetModuleLoad":
            target_name = (event.get("AssemblyName") or event.get("ModuleILPath")
                           or event.get("DotnetModuleId"))
        elif event.get("#event_simpleName") == "ScriptControlDetectInfo":
            target_name = event.get("ScriptContentName") or event.get("PatternId")
        elif event.get("#event_simpleName") == "SensitiveWmiQuery":
            target_name = event.get("WmiQuery") or event.get("WmiNamespaceName")
        elif event.get("#event_simpleName") == "CreateService":
            actor_id = event.get("RpcClientProcessId") or actor_id
            target_name = event.get("ServiceObjectName") or event.get("ServiceDisplayName")
        elif event.get("#event_simpleName") == "RemoteCommandResponse":
            actor_id = actor_name = target_id = None
            target_name = event.get("CommandName") or event.get("CommandCode")
        if not actor_id and target_id:
            actor_id = target_id
    elif vendor == DEFENDER:
        actor_id = event.get("InitiatingProcessId")
        actor_name = event.get("InitiatingProcessFileName")
        target_id = event.get("ProcessId")
        target_name = event.get("FileName")
        if event.get("ActionType") == "KerberosConnectionInspected":
            # Network inspection does not establish the AccountName as the actor.
            domain = event.get("InitiatingProcessAccountDomain", "")
            user = event.get("InitiatingProcessAccountName") or "Unknown"
        else:
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
