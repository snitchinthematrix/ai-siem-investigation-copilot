from copilot.db import COLUMNS


def test_fixture_database_holds_synthetic_events_with_sequential_ids(conn):
    rows = conn.execute("SELECT event_id, host, image FROM events ORDER BY event_id").fetchall()
    assert len(rows) == 16
    assert rows[0][0] == "E000001" and rows[-1][0] == "E000016"
    assert rows[15][1] == "workstation8" and rows[15][2].endswith("schtasks.exe")


def test_columns_match_the_table(conn):
    names = [c[0] for c in conn.execute("SELECT * FROM events LIMIT 0").description]
    assert names == COLUMNS
