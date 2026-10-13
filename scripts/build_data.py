"""Download the public captures and build everything under data/."""
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.db import DATA_DIR, DB_PATH, create_events_db
from copilot.normalize import normalize_records
from copilot.synthetic import SYNTHETIC_RECORDS

RAW_DIR = DATA_DIR / "raw"
BASE_URL = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/"
CAPTURES = [
    "credential_access/host/psh_lsass_memory_dump_comsvcs",
    "persistence/host/empire_persistence_registry_modification_run_keys_standard_user",
    "persistence/host/empire_schtasks_creation_standard_user",
    "defense_evasion/host/cmd_bitsadmin_download_psh_script",
]


def fetch(url: str, dest: Path) -> Path:
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        print("downloading", url)
        urllib.request.urlretrieve(url, dest)
    return dest


def read_capture(zip_path: Path) -> list[dict]:
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open(archive.namelist()[0]) as handle:
            return [json.loads(line) for line in handle if line.strip()]


def build_events() -> None:
    rows = []
    for capture in CAPTURES:
        name = capture.rsplit("/", 1)[-1]
        records = read_capture(fetch(BASE_URL + capture + ".zip", RAW_DIR / f"{name}.zip"))
        normalized, skipped = normalize_records(records, name)
        print(f"{name}: {len(normalized)} events, {skipped} skipped")
        rows.extend(normalized)
    synthetic, _ = normalize_records(SYNTHETIC_RECORDS, "synthetic")
    rows.extend(synthetic)
    print(f"writing {len(rows)} events to {DB_PATH} (this takes a few minutes)")
    create_events_db(DB_PATH, rows).close()


if __name__ == "__main__":
    build_events()
