"""Detection rules that turn events into the alert queue."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from copilot.db import DATA_DIR
from copilot.schema import Alert

ALERTS_PATH = DATA_DIR / "alerts.json"
SYSMON = "channel LIKE '%sysmon%'"
PROCESS_CREATE = SYSMON + " AND event_code = 1"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    where: str
    group_by: str  # one alert per (host, value of this column)


RULES = [
    Rule("R001", "LSASS process memory access", "high",
         SYSMON + r" AND event_code = 10 AND target_image ILIKE '%\lsass.exe'", "image"),
    Rule("R002", "Registry Run key modified", "medium",
         SYSMON + r" AND event_code = 13 AND target_object ILIKE '%\CurrentVersion\Run\%'", "target_object"),
    Rule("R003", "Scheduled task created from command line", "medium",
         PROCESS_CREATE + " AND image ILIKE '%schtasks.exe' AND command_line ILIKE '%/create%'", "command_line"),
    Rule("R004", "BITS transfer job started", "medium",
         PROCESS_CREATE + " AND image ILIKE '%bitsadmin.exe' AND command_line ILIKE '%/transfer%'", "command_line"),
    Rule("R005", "PowerShell hidden window or encoded command", "high",
         PROCESS_CREATE + " AND (command_line ILIKE '% -enc %' OR command_line ILIKE '%-w hidden%'"
         " OR command_line ILIKE '%-windowstyle hidden%' OR command_line ILIKE '%frombase64string%')", "command_line"),
    Rule("R006", "Memory dump file created", "medium",
         SYSMON + " AND event_code = 11 AND target_filename ILIKE '%.dmp'", "target_filename"),
]


def alert_id(rule_id: str, host: str, group_key: str) -> str:
    digest = hashlib.sha1(f"{rule_id}|{host}|{group_key}".encode()).hexdigest()[:8]
    return f"{rule_id}-{digest}"


def generate_alerts(conn) -> list[Alert]:
    alerts = []
    for rule in RULES:
        rows = conn.execute(
            f"SELECT host, {rule.group_by}, min(ts), count(*), list(event_id ORDER BY ts, event_id) "
            f"FROM events WHERE {rule.where} AND {rule.group_by} IS NOT NULL "
            f"GROUP BY host, {rule.group_by}"
        ).fetchall()
        for host, group_key, first_ts, count, event_ids in rows:
            alerts.append(Alert(
                id=alert_id(rule.id, host, group_key),
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                host=host,
                ts=first_ts.isoformat(sep=" ", timespec="seconds"),
                summary=f"{rule.title} on {host}: {rule.group_by} = {group_key[:300]}",
                event_count=count,
                trigger_event_ids=event_ids[:5],
            ))
    return sorted(alerts, key=lambda alert: alert.id)


def save_alerts(alerts: list[Alert], path: Path = ALERTS_PATH) -> None:
    Path(path).write_text(json.dumps([a.model_dump() for a in alerts], indent=2), encoding="utf-8")


def load_alerts(path: Path = ALERTS_PATH) -> list[Alert]:
    return [Alert(**item) for item in json.loads(Path(path).read_text(encoding="utf-8"))]
