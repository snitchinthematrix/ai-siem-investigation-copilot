import pytest

from copilot.db import create_events_db
from copilot.normalize import normalize_records
from copilot.synthetic import SYNTHETIC_RECORDS


@pytest.fixture()
def conn():
    rows, _ = normalize_records(SYNTHETIC_RECORDS, "synthetic")
    connection = create_events_db(":memory:", rows)
    yield connection
    connection.close()
