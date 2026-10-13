"""Look up MITRE ATT&CK techniques from a small local index."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from copilot.db import DATA_DIR

TECHNIQUES_PATH = DATA_DIR / "attack_techniques.json"
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)
MAX_MATCHES = 5


def build_technique_index(stix: dict) -> list[dict]:
    """Reduce the ATT&CK STIX bundle to id, name, tactics and a short description."""
    index = []
    for obj in stix["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ids = [r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        if not ids:
            continue
        index.append({
            "id": ids[0],
            "name": obj["name"],
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
            "description": obj.get("description", "")[:500],
        })
    return sorted(index, key=lambda technique: technique["id"])


@lru_cache(maxsize=4)
def _load(path: str) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def lookup_attack_technique(query: str, path: Path = TECHNIQUES_PATH) -> dict:
    """Find a technique by exact ID (T1053.005) or by a keyword in its name."""
    techniques, text = _load(str(path)), str(query).strip()
    if TECHNIQUE_ID.match(text):
        matches = [t for t in techniques if t["id"] == text.upper()]
    else:
        matches = [t for t in techniques if text.lower() in t["name"].lower()][:MAX_MATCHES]
    if not matches:
        return {"matches": [], "note": f"no ATT&CK technique matches {text!r}"}
    return {"matches": matches}
