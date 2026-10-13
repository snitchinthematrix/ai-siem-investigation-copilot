"""Turn raw OTRF Security Datasets records into rows for the events table."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from statistics import median

FALLBACK_TIME_FIELDS = ("@timestamp", "EventTime", "TimeCreated")

# Raw fields kept in the extra column. The captures carry about 350 others, mostly
# log-shipping metadata, which would make the database too large to commit.
KEPT_EXTRA = (
    "GrantedAccess", "DestinationHostname", "IntegrityLevel", "SourceIp", "LogonId",
    "TargetUserName", "TaskName", "ObjectName", "ScriptBlockText",
)


def parse_time(value) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def clock_offsets(records: list[dict]) -> dict[str, timedelta]:
    """How far each fallback time field runs from Sysmon's UtcTime in one capture.

    Captures record non-Sysmon events in a different timezone from UtcTime, so the
    offset is measured on records that carry both and applied to those that do not.
    """
    offsets = {}
    for field in FALLBACK_TIME_FIELDS:
        deltas = []
        for record in records:
            utc, other = parse_time(record.get("UtcTime")), parse_time(record.get(field))
            if utc and other:
                deltas.append((utc - other).total_seconds())
        if deltas:
            offsets[field] = timedelta(seconds=round(median(deltas) / 900) * 900)
    return offsets


def _first(record: dict, *keys: str) -> str | None:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", "-"):
            return str(value)
    return None


def _to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _timestamp(record: dict, offsets: dict[str, timedelta]) -> datetime | None:
    utc = parse_time(record.get("UtcTime"))
    if utc:
        return utc
    for field in FALLBACK_TIME_FIELDS:
        parsed = parse_time(record.get(field))
        if parsed:
            return parsed + offsets.get(field, timedelta(0))
    return None


def normalize_records(records: list[dict], dataset: str) -> tuple[list[dict], int]:
    """Return (rows sorted by time, number of records skipped)."""
    offsets = clock_offsets(records)
    rows, skipped = [], 0
    for record in records:
        ts, event_code = _timestamp(record, offsets), _to_int(record.get("EventID"))
        if ts is None or event_code is None:
            skipped += 1
            continue
        user = _first(record, "User", "SubjectUserName")
        rows.append({
            "ts": ts,
            "dataset": dataset,
            "host": (_first(record, "Hostname") or "unknown").lower().split(".")[0],
            "channel": str(record.get("Channel", "")).lower(),
            "event_code": event_code,
            "username": user.split("\\")[-1].lower() if user else None,
            "image": _first(record, "Image", "NewProcessName", "SourceImage", "ProcessName"),
            "command_line": _first(record, "CommandLine"),
            "parent_image": _first(record, "ParentImage", "ParentProcessName"),
            "parent_command_line": _first(record, "ParentCommandLine"),
            "process_guid": _first(record, "ProcessGuid", "SourceProcessGUID"),
            "parent_process_guid": _first(record, "ParentProcessGuid"),
            "target_image": _first(record, "TargetImage"),
            "target_filename": _first(record, "TargetFilename"),
            "target_object": _first(record, "TargetObject"),
            "details": _first(record, "Details"),
            "dest_ip": _first(record, "DestinationIp"),
            "dest_port": _to_int(record.get("DestinationPort")),
            "extra": json.dumps({k: record[k] for k in KEPT_EXTRA if record.get(k) not in (None, "", "-")}, default=str),
        })
    rows.sort(key=lambda row: row["ts"])
    return rows, skipped
