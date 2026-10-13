from copilot.runs import load_run, resolve_live_result, save_run
from copilot.schema import RunRecord, Verdict


def record(error=None, verdict=True, mode="agent"):
    v = Verdict(verdict="true_positive", confidence=1, severity="high", evidence=[{"claim": "c", "event_ids": []}], report_md="r") if verdict else None
    return RunRecord(alert_id="R001-abc", mode=mode, model="m", verdict=v, error=error)


def test_save_and_load_round_trip(tmp_path):
    path = save_run(record(), tmp_path)
    assert path == tmp_path / "agent" / "R001-abc.json"
    assert load_run("R001-abc", "agent", tmp_path) == record()


def test_load_missing_run_returns_none(tmp_path):
    assert load_run("R001-abc", "baseline", tmp_path) is None


def test_no_live_run_yet_shows_nothing():
    assert resolve_live_result(None, record()) == (None, None)


def test_successful_live_run_is_shown():
    live = record()
    assert resolve_live_result(live, None) == (live, None)


def test_failed_live_run_falls_back_to_the_recording_with_a_notice():
    recorded = record()
    shown, notice = resolve_live_result(record(error="LLM unavailable: 429", verdict=False), recorded)
    assert shown is recorded and "recorded run" in notice


def test_failed_live_run_without_a_recording_is_shown_as_is():
    live = record(error="LLM unavailable: 429", verdict=False)
    assert resolve_live_result(live, None) == (live, None)
