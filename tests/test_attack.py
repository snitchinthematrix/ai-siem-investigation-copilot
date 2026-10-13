import json

from copilot.attack import build_technique_index, lookup_attack_technique

STIX = {"objects": [
    {"type": "attack-pattern", "name": "Scheduled Task", "description": "Adversaries may abuse the Windows Task Scheduler. " * 30,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1053.005"}],
     "kill_chain_phases": [{"phase_name": "persistence"}, {"phase_name": "execution"}]},
    {"type": "attack-pattern", "name": "OS Credential Dumping", "description": "Dump credentials.",
     "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"},
                             {"source_name": "mitre-attack", "external_id": "T1003"}],
     "kill_chain_phases": [{"phase_name": "credential-access"}]},
    {"type": "attack-pattern", "name": "Old Technique", "revoked": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    {"type": "malware", "name": "Not a technique"},
]}


def _index(tmp_path):
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps(build_technique_index(STIX)), encoding="utf-8")
    return path


def test_index_keeps_live_techniques_and_trims_descriptions():
    index = build_technique_index(STIX)
    assert [t["id"] for t in index] == ["T1003", "T1053.005"]
    assert index[1]["tactics"] == ["persistence", "execution"]
    assert len(index[1]["description"]) <= 500


def test_lookup_by_id_is_case_insensitive(tmp_path):
    result = lookup_attack_technique("t1053.005", _index(tmp_path))
    assert [m["name"] for m in result["matches"]] == ["Scheduled Task"]


def test_lookup_by_name_keyword(tmp_path):
    result = lookup_attack_technique("credential", _index(tmp_path))
    assert [m["id"] for m in result["matches"]] == ["T1003"]


def test_lookup_miss_says_so(tmp_path):
    result = lookup_attack_technique("T1234", _index(tmp_path))
    assert result["matches"] == [] and "note" in result
