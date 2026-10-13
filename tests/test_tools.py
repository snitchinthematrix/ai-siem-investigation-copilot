from datetime import datetime

import pytest

from copilot.synthetic import INJECTION_NOTE
from copilot.tools import (
    MAX_FIELD_CHARS, MAX_ROWS, TOOL_SPECS, ToolError, _compact, collect_event_ids,
    get_entity_activity, get_process_tree, run_tool, search_events,
)


def test_search_by_keyword_and_host(conn):
    result = search_events(conn, host="WORKSTATION7.theshire.local", keyword="bitsadmin")
    assert [e["event_id"] for e in result["events"]] == ["E000003"]
    assert result["truncated"] is False


def test_search_by_time_window_and_event_code(conn):
    result = search_events(conn, event_code=1, start="2020-11-02 15:00:00", end="2020-11-02T15:00:30Z")
    assert [e["event_id"] for e in result["events"]] == ["E000013", "E000014"]


def test_search_by_username_ignores_domain_and_case(conn):
    result = search_events(conn, username="THESHIRE\\FBolger")
    assert result["total_matches"] == 4


def test_results_are_capped_and_report_the_true_total(conn):
    result = search_events(conn, host="workstation7", limit=1000)
    assert result["returned"] == 12 <= MAX_ROWS
    small = search_events(conn, host="workstation7", limit=2)
    assert (small["returned"], small["total_matches"], small["truncated"]) == (2, 12, True)


def test_long_fields_are_truncated_and_nulls_dropped():
    row = {field: None for field in
           ["event_id", "ts", "host", "channel", "event_code", "username", "image", "command_line",
            "parent_image", "parent_command_line", "process_guid", "parent_process_guid", "target_image",
            "target_filename", "target_object", "details", "dest_ip", "dest_port"]}
    row.update(event_id="E1", ts=datetime(2020, 1, 1), command_line="A" * 5000,
               extra='{"GrantedAccess": "0x1fffff", "Hashes": "x"}')
    event = _compact(row)
    assert len(event["command_line"]) < MAX_FIELD_CHARS + 40
    assert "5000 chars" in event["command_line"]
    assert "image" not in event and "Hashes" not in event
    assert event["GrantedAccess"] == "0x1fffff"


def test_injection_text_reaches_the_model_untruncated(conn):
    event = search_events(conn, host="workstation8", keyword="OneDriveSync")["events"][0]
    assert INJECTION_NOTE in event["command_line"]


def test_keyword_with_sql_characters_is_literal(conn):
    result = search_events(conn, keyword="100%'; DROP TABLE events;--")
    assert result["total_matches"] == 0
    assert search_events(conn, keyword="_")["total_matches"] < 16
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 16


def test_search_needs_a_filter_and_a_valid_timestamp(conn):
    with pytest.raises(ToolError, match="at least one filter"):
        search_events(conn)
    with pytest.raises(ToolError, match="start must look like"):
        search_events(conn, host="workstation8", start="last tuesday")


def test_process_tree_shows_parents_children_and_activity(conn):
    tree = get_process_tree(conn, "{s7-0002}")
    assert tree["process"]["event_id"] == "E000014"
    assert [a["event_id"] for a in tree["ancestors"]] == ["E000013"]
    assert [e["event_id"] for e in tree["children"]["events"]] == ["E000016"]
    assert [e["event_id"] for e in tree["other_activity"]["events"]] == ["E000015"]


def test_process_tree_unknown_guid(conn):
    with pytest.raises(ToolError, match="no process creation event"):
        get_process_tree(conn, "{missing}")


def test_entity_activity_counts_and_notable_events(conn):
    activity = get_entity_activity(conn, "user", "fbolger", "2020-11-02 15:00:20", window_minutes=5)
    assert activity["event_counts"] == {"1": 3, "3": 1}
    assert {e["event_id"] for e in activity["notable_events"]["events"]} == {"E000013", "E000014", "E000015", "E000016"}
    by_ip = get_entity_activity(conn, "ip", "203.0.113.47", "2020-11-02 15:00:20")
    assert by_ip["event_counts"] == {"3": 1}


def test_entity_activity_rejects_unknown_entity_type(conn):
    with pytest.raises(ToolError, match="entity_type"):
        get_entity_activity(conn, "domain", "x", "2020-11-02 15:00:20")


def test_run_tool_turns_bad_model_input_into_error_results(conn):
    assert "unknown tool" in run_tool(conn, "drop_database", {})["error"]
    assert "error" in run_tool(conn, "search_events", {"hostname": "x"})
    assert "error" in run_tool(conn, "search_events", {"host": "x", "limit": "many"})
    assert "error" in run_tool(conn, "search_events", {})
    assert "error" in run_tool(conn, "get_process_tree", {"process_guid": "{missing}"})
    assert run_tool(conn, "search_events", {"host": "workstation8"})["total_matches"] == 4


def test_collect_event_ids_walks_nested_results(conn):
    assert collect_event_ids(get_process_tree(conn, "{s7-0002}")) == {"E000013", "E000014", "E000015", "E000016"}
    assert collect_event_ids({"error": "x"}) == set()


def test_tool_specs_name_the_four_tools():
    assert [s["function"]["name"] for s in TOOL_SPECS] == [
        "search_events", "get_process_tree", "get_entity_activity", "lookup_attack_technique"]
