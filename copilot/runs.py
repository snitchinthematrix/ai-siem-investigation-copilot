"""Saved investigation runs: the scorecard's input and the demo's replay source."""
from __future__ import annotations

from pathlib import Path

from copilot.db import ROOT
from copilot.schema import RunRecord

RUNS_DIR = ROOT / "runs"


def save_run(record: RunRecord, root: Path = RUNS_DIR) -> Path:
    path = Path(root) / record.mode / f"{record.alert_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_run(alert_id: str, mode: str = "agent", root: Path = RUNS_DIR) -> RunRecord | None:
    path = Path(root) / mode / f"{alert_id}.json"
    if not path.exists():
        return None
    return RunRecord.model_validate_json(path.read_text(encoding="utf-8"))


def resolve_live_result(live: RunRecord | None, recorded: RunRecord | None) -> tuple[RunRecord | None, str | None]:
    """Pick the run to show after a live attempt, and a notice if it is not the live one."""
    if live is None:
        return None, None
    if live.verdict is None and recorded is not None:
        return recorded, f"The live run could not finish ({live.error}). Showing the recorded run for this alert instead."
    return live, None
