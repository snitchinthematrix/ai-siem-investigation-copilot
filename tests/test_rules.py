import json

import pytest
import yaml

from copilot.db import ROOT
from copilot.rules import ALERTS_PATH, generate_alerts, load_alerts, save_alerts

SYNTHETIC_ALERT_IDS = {
    "R001-f1bba6fb", "R002-8a0a4627", "R003-bff45b6f", "R003-15a5656f", "R004-1412f6d6",
    "R005-035ed10e", "R005-978f265e", "R005-9d43bf3d", "R006-bfc8ce56",
}


def test_synthetic_events_produce_the_expected_alerts(conn):
    assert {a.id for a in generate_alerts(conn)} == SYNTHETIC_ALERT_IDS


def test_alert_points_at_its_triggering_events(conn):
    alert = next(a for a in generate_alerts(conn) if a.id == "R003-15a5656f")
    assert alert.host == "workstation8"
    assert alert.trigger_event_ids == ["E000016"]
    assert alert.event_count == 1
    assert alert.ts == "2020-11-02 15:00:45"
    assert "schtasks.exe /Create" in alert.summary


def test_alerts_round_trip_through_json(conn, tmp_path):
    alerts = generate_alerts(conn)
    save_alerts(alerts, tmp_path / "alerts.json")
    assert load_alerts(tmp_path / "alerts.json") == alerts


def test_synthetic_labels_match_synthetic_alerts():
    labels = yaml.safe_load((ROOT / "evals" / "labels.yaml").read_text(encoding="utf-8"))
    assert {k for k, v in labels.items() if v["source"] == "synthetic"} == SYNTHETIC_ALERT_IDS


def test_every_built_alert_has_exactly_one_label():
    if not ALERTS_PATH.exists():
        pytest.skip("run scripts/build_data.py first")
    labels = yaml.safe_load((ROOT / "evals" / "labels.yaml").read_text(encoding="utf-8"))
    built = {a["id"] for a in json.loads(ALERTS_PATH.read_text(encoding="utf-8"))}
    assert built == set(labels)
