"""Paths, schema and connections for the events database."""
from __future__ import annotations

from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "events.duckdb"

COLUMNS = [
    "event_id", "ts", "dataset", "host", "channel", "event_code", "username", "image",
    "command_line", "parent_image", "parent_command_line", "process_guid",
    "parent_process_guid", "target_image", "target_filename", "target_object",
    "details", "dest_ip", "dest_port", "extra",
]

SCHEMA = """
CREATE TABLE events (
    event_id VARCHAR PRIMARY KEY, ts TIMESTAMP, dataset VARCHAR, host VARCHAR,
    channel VARCHAR, event_code INTEGER, username VARCHAR, image VARCHAR,
    command_line VARCHAR, parent_image VARCHAR, parent_command_line VARCHAR,
    process_guid VARCHAR, parent_process_guid VARCHAR, target_image VARCHAR,
    target_filename VARCHAR, target_object VARCHAR, details VARCHAR,
    dest_ip VARCHAR, dest_port INTEGER, extra VARCHAR
)
"""


def create_events_db(path, rows: list[dict]) -> duckdb.DuckDBPyConnection:
    """Create a fresh database at path, numbering events in the order given."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).unlink(missing_ok=True)
    conn = duckdb.connect(str(path))
    conn.execute(SCHEMA)
    values = [[f"E{n:06d}", *(row[c] for c in COLUMNS[1:])] for n, row in enumerate(rows, start=1)]
    if values:
        conn.executemany(f"INSERT INTO events VALUES ({', '.join('?' * len(COLUMNS))})", values)
    return conn


def connect(path=DB_PATH) -> duckdb.DuckDBPyConnection:
    return duckdb.connect(str(path), read_only=True)
