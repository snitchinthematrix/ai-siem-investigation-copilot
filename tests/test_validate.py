import pytest
from pydantic import ValidationError

from copilot.schema import Verdict
from copilot.validate import validate_citations


def make_verdict(evidence, timeline=()):
    return Verdict(verdict="true_positive", confidence=0.9, severity="high", techniques=["T1053.005"],
                   evidence=evidence, timeline=list(timeline), next_actions=[], report_md="report")


def test_all_citations_valid(conn):
    verdict = make_verdict([{"claim": "task created", "event_ids": ["E000016"]}],
                           [{"ts": "2020-11-02 15:00:20", "description": "cradle", "event_ids": ["E000014"]}])
    report = validate_citations(verdict, {"E000014", "E000016"}, conn)
    assert (report.cited, report.valid, report.not_retrieved, report.nonexistent) == (2, 2, [], [])


def test_real_event_that_was_never_retrieved_is_flagged(conn):
    report = validate_citations(make_verdict([{"claim": "c", "event_ids": ["E000001", "E000016"]}]), {"E000016"}, conn)
    assert (report.cited, report.valid, report.not_retrieved) == (2, 1, ["E000001"])


def test_invented_event_id_is_flagged(conn):
    report = validate_citations(make_verdict([{"claim": "c", "event_ids": ["E999999"]}]), {"E999999"}, conn)
    assert (report.valid, report.nonexistent) == (0, ["E999999"])


def test_claims_without_citations_are_counted(conn):
    report = validate_citations(make_verdict([{"claim": "trust me", "event_ids": []}]), set(), conn)
    assert (report.cited, report.uncited_claims) == (0, 1)


def test_repeated_citations_count_once(conn):
    verdict = make_verdict([{"claim": "a", "event_ids": ["E000016"]}, {"claim": "b", "event_ids": ["E000016"]}])
    assert validate_citations(verdict, {"E000016"}, conn).cited == 1


def test_verdict_rejects_unknown_values():
    with pytest.raises(ValidationError):
        Verdict(verdict="maybe", confidence=0.5, severity="high", evidence=[], report_md="")
    with pytest.raises(ValidationError):
        Verdict(verdict="true_positive", confidence=1.7, severity="high", evidence=[], report_md="")


def test_verdict_needs_at_least_one_evidence_item():
    with pytest.raises(ValidationError):
        Verdict(verdict="true_positive", confidence=0.5, severity="high", evidence=[], report_md="r")
