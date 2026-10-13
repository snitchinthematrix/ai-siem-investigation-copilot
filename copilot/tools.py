"""Read-only, parameterized queries the agent may call. The model never writes SQL."""
from __future__ import annotations

import json
from datetime import timedelta

from copilot.attack import lookup_attack_technique
from copilot.normalize import parse_time

MAX_ROWS = 15
MAX_FIELD_CHARS = 400
MAX_ANCESTORS = 5
EVENT_FIELDS = [
    "event_id", "ts", "host", "channel", "event_code", "username", "image", "command_line",
    "parent_image", "parent_command_line", "process_guid", "parent_process_guid", "target_image",
    "target_filename", "target_object", "details", "dest_ip", "dest_port",
]
EXTRA_FIELDS = ("GrantedAccess", "DestinationHostname", "IntegrityLevel")
KEYWORD_COLUMNS = ("image", "command_line", "parent_image", "target_image",
                   "target_filename", "target_object", "details", "dest_ip")
PROCESS_CREATE = "channel LIKE '%sysmon%' AND event_code = 1"
ENTITY_COLUMNS = {"host": "host", "user": "username", "ip": "dest_ip"}


class ToolError(ValueError):
    """A problem with the arguments, worded so the model can correct itself."""


def _compact(row: dict) -> dict:
    event = {}
    for field in EVENT_FIELDS:
        value = row[field]
        if value is None:
            continue
        if field == "ts":
            value = value.isoformat(sep=" ", timespec="milliseconds")
        elif isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
            value = f"{value[:MAX_FIELD_CHARS]}...[truncated, {len(value)} chars]"
        event[field] = value
    extra = json.loads(row.get("extra") or "{}")
    for field in EXTRA_FIELDS:
        if extra.get(field) not in (None, "", "-"):
            event[field] = extra[field]
    return event


def _select(conn, where: str, params: list, limit=MAX_ROWS, order: str = "ts, event_id") -> dict:
    limit = max(1, min(int(limit), MAX_ROWS))
    total = conn.execute(f"SELECT count(*) FROM events WHERE {where}", params).fetchone()[0]
    cursor = conn.execute(
        f"SELECT {', '.join(EVENT_FIELDS)}, extra FROM events WHERE {where} ORDER BY {order} LIMIT {limit}", params)
    names = [column[0] for column in cursor.description]
    events = [_compact(dict(zip(names, row))) for row in cursor.fetchall()]
    return {"total_matches": total, "returned": len(events), "truncated": total > len(events), "events": events}


def _time(value, name: str):
    parsed = parse_time(value)
    if parsed is None:
        raise ToolError(f"{name} must look like 'YYYY-MM-DD HH:MM:SS', got {value!r}")
    return parsed


def _host(value) -> str:
    return str(value).lower().split(".")[0]


def _user(value) -> str:
    return str(value).lower().split("\\")[-1]


def search_events(conn, host=None, username=None, event_code=None, keyword=None,
                  start=None, end=None, limit=MAX_ROWS) -> dict:
    where, params = [], []
    if host:
        where.append("host = ?")
        params.append(_host(host))
    if username:
        where.append("username = ?")
        params.append(_user(username))
    if event_code is not None:
        where.append("event_code = ?")
        params.append(int(event_code))
    if keyword:
        escaped = str(keyword).replace("!", "!!").replace("%", "!%").replace("_", "!_")
        where.append("(" + " OR ".join(f"{column} ILIKE ? ESCAPE '!'" for column in KEYWORD_COLUMNS) + ")")
        params.extend([f"%{escaped}%"] * len(KEYWORD_COLUMNS))
    if start:
        where.append("ts >= ?")
        params.append(_time(start, "start"))
    if end:
        where.append("ts <= ?")
        params.append(_time(end, "end"))
    if not where:
        raise ToolError("give at least one filter")
    return _select(conn, " AND ".join(where), params, limit)


def _process(conn, process_guid: str) -> dict | None:
    events = _select(conn, f"{PROCESS_CREATE} AND process_guid = ?", [process_guid], 1)["events"]
    return events[0] if events else None


def get_process_tree(conn, process_guid) -> dict:
    process_guid = str(process_guid)
    process = _process(conn, process_guid)
    if process is None:
        raise ToolError(f"no process creation event with process_guid {process_guid!r}")
    ancestors, current = [], process
    for _ in range(MAX_ANCESTORS):
        parent_guid = current.get("parent_process_guid")
        parent = _process(conn, parent_guid) if parent_guid else None
        if parent is None:
            break
        ancestors.append(parent)
        current = parent
    return {
        "process": process,
        "ancestors": ancestors,
        "children": _select(conn, f"{PROCESS_CREATE} AND parent_process_guid = ?", [process_guid]),
        "other_activity": _select(conn, f"process_guid = ? AND NOT ({PROCESS_CREATE})", [process_guid]),
    }


def get_entity_activity(conn, entity_type, value, around, window_minutes=10) -> dict:
    if entity_type not in ENTITY_COLUMNS:
        raise ToolError("entity_type must be one of: host, user, ip")
    minutes = max(1, min(int(window_minutes), 120))
    centre = _time(around, "around")
    start, end = centre - timedelta(minutes=minutes), centre + timedelta(minutes=minutes)
    value = {"host": _host, "user": _user, "ip": str}[entity_type](value)
    where, params = f"{ENTITY_COLUMNS[entity_type]} = ? AND ts BETWEEN ? AND ?", [value, start, end]
    counts = conn.execute(
        f"SELECT event_code, count(*) FROM events WHERE {where} GROUP BY event_code ORDER BY count(*) DESC, event_code",
        params).fetchall()
    return {
        "window_start": start.isoformat(sep=" "),
        "window_end": end.isoformat(sep=" "),
        "event_counts": {str(code): count for code, count in counts},
        # process creation, network, file creation, registry value set
        "notable_events": _select(conn, where + " AND channel LIKE '%sysmon%' AND event_code IN (1, 3, 11, 13)",
                                  params, order="event_code, ts, event_id"),
    }


def collect_event_ids(value) -> set[str]:
    """Every event_id that appears anywhere in a tool result."""
    if isinstance(value, dict):
        found = {value["event_id"]} if isinstance(value.get("event_id"), str) else set()
        for item in value.values():
            found |= collect_event_ids(item)
        return found
    if isinstance(value, list):
        found = set()
        for item in value:
            found |= collect_event_ids(item)
        return found
    return set()


TOOLS = {
    "search_events": search_events,
    "get_process_tree": get_process_tree,
    "get_entity_activity": get_entity_activity,
    "lookup_attack_technique": lambda conn, query: lookup_attack_technique(query),
}


def run_tool(conn, name: str, arguments: dict) -> dict:
    """Run a tool for the model. Bad input comes back as an error result, never an exception."""
    if name not in TOOLS:
        return {"error": f"unknown tool {name!r}. Available: {', '.join(TOOLS)}, submit_verdict"}
    try:
        return TOOLS[name](conn, **arguments)
    except (TypeError, ValueError) as exc:
        return {"error": f"{name}: {exc}"}


def _spec(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required},
    }}


TOOL_SPECS = [
    _spec("search_events",
          f"Search log events. Give at least one filter. Returns at most {MAX_ROWS} events, oldest first, "
          "with total_matches so you know if more exist; narrow the filters if truncated.",
          {"host": {"type": "string", "description": "Host name, e.g. workstation5"},
           "username": {"type": "string", "description": "Account name without the domain"},
           "event_code": {"type": "integer", "description": "Windows event ID. Sysmon: 1 process create, "
                          "3 network connection, 10 process access, 11 file create, 13 registry value set"},
           "keyword": {"type": "string", "description": "Text to find in image paths, command lines, "
                       "file names, registry paths or destination IPs"},
           "start": {"type": "string", "description": "Earliest time, UTC, 'YYYY-MM-DD HH:MM:SS'"},
           "end": {"type": "string", "description": "Latest time, UTC, 'YYYY-MM-DD HH:MM:SS'"},
           "limit": {"type": "integer", "description": f"1 to {MAX_ROWS}"}},
          []),
    _spec("get_process_tree",
          "Show a process's creation event, its ancestors (nearest first), the processes it started, "
          "and its other activity such as network connections and file or registry writes.",
          {"process_guid": {"type": "string", "description": "process_guid value taken from an event"}},
          ["process_guid"]),
    _spec("get_entity_activity",
          "Summarize what a host, user or destination IP did around a point in time: event counts by "
          "event code, plus the process, network, file and registry events in the window.",
          {"entity_type": {"type": "string", "enum": ["host", "user", "ip"]},
           "value": {"type": "string"},
           "around": {"type": "string", "description": "Centre of the window, UTC, 'YYYY-MM-DD HH:MM:SS'"},
           "window_minutes": {"type": "integer", "description": "Minutes each side of the centre, 1 to 120"}},
          ["entity_type", "value", "around"]),
    _spec("lookup_attack_technique",
          "Look up a MITRE ATT&CK technique by ID (T1053.005) or by a keyword in its name.",
          {"query": {"type": "string"}},
          ["query"]),
]
