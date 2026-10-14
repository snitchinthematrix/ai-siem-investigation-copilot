"""Shaping data for the UI. No Streamlit here, so it can be tested without a browser."""
from __future__ import annotations

from copilot.schema import Alert, Step

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
SEVERITY_COLOR = {"critical": "red", "high": "red", "medium": "orange", "low": "blue", "informational": "gray"}
# verdict -> (label, colour, what it means for the analyst)
VERDICTS = {
    "true_positive": ("True positive", "red", "Real attack activity"),
    "false_positive": ("False positive", "green", "Benign activity"),
    "needs_more_info": ("Needs more information", "orange", "Not enough evidence to decide"),
}
AGENT, BASELINE = "Agent (with tools)", "Baseline (alert only)"
TITLE_CHARS = 100


def result_events(value) -> list[dict]:
    """Every distinct event in a tool result, in the order first seen."""
    found: dict[str, dict] = {}

    def walk(item) -> None:
        if isinstance(item, dict):
            if isinstance(item.get("event_id"), str):
                found.setdefault(item["event_id"], item)
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return list(found.values())


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")


def step_outcome(step: Step) -> str:
    result = step.result or {}
    if "error" in result:
        return "error"
    if "total_matches" in result:
        return f"{result['total_matches']} matches"
    if "matches" in result:
        return _count(len(result["matches"]), "technique")
    return _count(len(result_events(result)), "event")


def step_title(number: int, step: Step) -> str:
    arguments = ", ".join(f"{key}={value!r}" for key, value in (step.arguments or {}).items())
    title = f"{number}. {step.tool}({arguments})"
    return title if len(title) <= TITLE_CHARS else title[:TITLE_CHARS - 1] + "…"


def queue_rows(alerts: list[Alert], agent_verdicts: dict[str, str], open_id: str | None) -> list[dict]:
    return [{
        "Open": "●" if alert.id == open_id else "",
        "Alert ID": alert.id,
        "Severity": alert.severity,
        "Rule": alert.title,
        "Host": alert.host,
        "Agent verdict": agent_verdicts.get(alert.id, "not run").replace("_", " "),
        "First seen (UTC)": alert.ts,
        "Events": alert.event_count,
    } for alert in alerts]


def filter_alerts(alerts: list[Alert], verdict_by_alert: dict[str, str], severities=None, rule=None,
                  agent_verdicts=None) -> list[Alert]:
    """An empty filter means no filter."""
    return [alert for alert in alerts
            if (not severities or alert.severity in severities)
            and (not rule or alert.title == rule)
            and (not agent_verdicts or verdict_by_alert.get(alert.id) in agent_verdicts)]


def selected_alert(alerts: list[Alert], visible: list[Alert], current_id: str | None,
                   pick: tuple | None, last_pick: tuple | None) -> str | None:
    """The alert to show. pick is (table key, row) from the queue; it only counts the first time it is seen."""
    if pick and pick != last_pick and 0 <= pick[1] < len(visible):
        return visible[pick[1]].id
    if any(alert.id == current_id for alert in alerts):
        return current_id
    return alerts[0].id if alerts else None


def class_accuracy(agent_cases: list[dict], baseline_cases: list[dict]) -> list[dict]:
    """Verdict accuracy split by what the alert really was, one row per group and runner."""
    rows = []
    for expected, name in (("true_positive", "Real attacks"), ("false_positive", "Benign activity")):
        for who, cases in ((AGENT, agent_cases), (BASELINE, baseline_cases)):
            group = [case for case in cases if case["expected"] == expected]
            if not group:
                continue
            correct = sum(bool(case["verdict_correct"]) for case in group)
            rows.append({"group": f"{name} ({len(group)})", "who": who, "correct": correct, "total": len(group),
                         "accuracy": round(100 * correct / len(group), 1)})
    return rows
