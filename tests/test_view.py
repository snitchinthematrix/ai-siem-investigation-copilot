from copilot.schema import Alert, Step
from copilot.tools import get_event
from copilot.view import (
    class_accuracy, filter_alerts, queue_rows, result_events, selected_alert, step_outcome, step_title,
)

EVENT_A = {"event_id": "E000001", "host": "ws1", "image": "a.exe"}
EVENT_B = {"event_id": "E000002", "host": "ws1", "image": "b.exe"}


def alert(alert_id, severity="high", title="LSASS process memory access", host="ws1"):
    return Alert(id=alert_id, rule_id=alert_id[:4], title=title, severity=severity, host=host,
                 ts="2020-01-01 00:00:00", summary="s", event_count=1, trigger_event_ids=["E000001"])


def test_result_events_finds_nested_events_once_in_order():
    result = {"process": EVENT_B, "ancestors": [EVENT_A], "children": {"events": [EVENT_A, EVENT_B]}}
    assert [e["event_id"] for e in result_events(result)] == ["E000002", "E000001"]
    assert result_events({"matches": [{"id": "T1003"}]}) == []
    assert result_events(None) == []


def test_step_outcome_and_title():
    search = Step(kind="tool_call", tool="search_events", arguments={"host": "ws1"},
                  result={"total_matches": 54, "events": [EVENT_A]})
    assert step_outcome(search) == "54 matches"
    assert step_title(3, search) == "3. search_events(host='ws1')"
    failed = Step(kind="tool_call", tool="get_process_tree", arguments={}, result={"error": "no process"})
    assert step_outcome(failed) == "error"
    lookup = Step(kind="tool_call", tool="lookup_attack_technique", arguments={"query": "x"},
                  result={"matches": [{"id": "T1003"}, {"id": "T1059"}]})
    assert step_outcome(lookup) == "2 techniques"
    lookup.result = {"matches": [{"id": "T1003"}]}
    assert step_outcome(lookup) == "1 technique"
    tree = Step(kind="tool_call", tool="get_process_tree", arguments={}, result={"process": EVENT_A, "ancestors": []})
    assert step_outcome(tree) == "1 event"


def test_step_title_is_cut_to_a_readable_length():
    step = Step(kind="tool_call", tool="search_events", arguments={"keyword": "x" * 500}, result={})
    assert len(step_title(1, step)) <= 100


def test_queue_rows_mark_the_open_alert_and_show_the_agent_verdict():
    alerts = [alert("R001-aaaaaaaa"), alert("R002-bbbbbbbb", severity="medium")]
    rows = queue_rows(alerts, {"R001-aaaaaaaa": "true_positive"}, "R002-bbbbbbbb")
    assert [row["Open"] for row in rows] == ["", "●"]
    assert rows[0]["Agent verdict"] == "true positive" and rows[1]["Agent verdict"] == "not run"
    assert rows[1]["Alert ID"] == "R002-bbbbbbbb"


def test_filter_alerts_treats_an_empty_filter_as_everything():
    alerts = [alert("R001-aaaaaaaa"), alert("R002-bbbbbbbb", severity="medium", title="Registry Run key modified")]
    verdicts = {"R001-aaaaaaaa": "true_positive", "R002-bbbbbbbb": "false_positive"}
    assert filter_alerts(alerts, verdicts) == alerts
    assert filter_alerts(alerts, verdicts, severities=["medium"]) == alerts[1:]
    assert filter_alerts(alerts, verdicts, rule="LSASS process memory access") == alerts[:1]
    assert filter_alerts(alerts, verdicts, agent_verdicts=["false_positive"]) == alerts[1:]


def test_selected_alert_keeps_the_open_alert_until_a_new_row_is_picked():
    alerts = [alert("R001-aaaaaaaa"), alert("R002-bbbbbbbb")]
    # Nothing chosen yet: the first alert.
    assert selected_alert(alerts, alerts, current_id=None, pick=None, last_pick=None) == "R001-aaaaaaaa"
    # A new pick wins.
    assert selected_alert(alerts, alerts, "R001-aaaaaaaa", pick=("k", 1), last_pick=None) == "R002-bbbbbbbb"
    # A pick already acted on does not override an alert opened from elsewhere.
    assert selected_alert(alerts, alerts, "R001-aaaaaaaa", pick=("k", 1), last_pick=("k", 1)) == "R001-aaaaaaaa"
    # The open alert stays open when a filter hides it.
    assert selected_alert(alerts, alerts[:1], "R002-bbbbbbbb", pick=None, last_pick=None) == "R002-bbbbbbbb"
    # An unknown ID falls back to the first alert; a pick outside the table is ignored.
    assert selected_alert(alerts, alerts, "nope", pick=("k", 9), last_pick=None) == "R001-aaaaaaaa"


def test_class_accuracy_splits_attacks_from_benign_alerts():
    agent = [{"expected": "true_positive", "verdict_correct": True},
             {"expected": "false_positive", "verdict_correct": True},
             {"expected": "false_positive", "verdict_correct": True}]
    base = [{"expected": "true_positive", "verdict_correct": True},
            {"expected": "false_positive", "verdict_correct": False},
            {"expected": "false_positive", "verdict_correct": True}]
    rows = class_accuracy(agent, base)
    assert {(r["group"], r["who"]): (r["correct"], r["total"], r["accuracy"]) for r in rows} == {
        ("Real attacks (1)", "Agent (with tools)"): (1, 1, 100.0),
        ("Real attacks (1)", "Baseline (alert only)"): (1, 1, 100.0),
        ("Benign activity (2)", "Agent (with tools)"): (2, 2, 100.0),
        ("Benign activity (2)", "Baseline (alert only)"): (1, 2, 50.0),
    }


def test_get_event_returns_one_event_or_none(conn):
    first = conn.execute("SELECT event_id, host FROM events ORDER BY event_id LIMIT 1").fetchone()
    event = get_event(conn, first[0])
    assert event["event_id"] == first[0] and event["host"] == first[1]
    assert get_event(conn, "E999999") is None
    assert get_event(conn, "x' OR '1'='1") is None
