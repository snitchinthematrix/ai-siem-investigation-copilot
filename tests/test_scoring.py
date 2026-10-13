from copilot.schema import CitationReport, RunRecord, Usage, Verdict
from copilot.scoring import load_labels, results_table, score_run, summarize


def run(verdict="true_positive", techniques=("T1053.005",), cited=2, valid=2, error=None, uncited=0):
    v = None if verdict is None else Verdict(verdict=verdict, confidence=0.8, severity="high",
                                             techniques=list(techniques), evidence=[{"claim": "c", "event_ids": []}], report_md="r")
    c = None if v is None else CitationReport(cited=cited, valid=valid, not_retrieved=[], nonexistent=[], uncited_claims=uncited)
    return RunRecord(alert_id="A", mode="agent", model="m", verdict=v, citations=c, error=error,
                     usage=Usage(tool_calls=4, input_tokens=900, output_tokens=100, latency_s=5.0))


TP = {"verdict": "true_positive", "techniques": ["T1053"], "source": "mordor"}
FP = {"verdict": "false_positive", "source": "synthetic"}


def test_correct_true_positive_with_matching_technique():
    case = score_run(run(), TP)
    assert case["verdict_correct"] is True and case["technique_match"] is True
    assert (case["expected"], case["got"], case["tokens"]) == ("true_positive", "true_positive", 1000)


def test_wrong_technique_and_wrong_verdict():
    assert score_run(run(techniques=["T1003.001"]), TP)["technique_match"] is False
    assert score_run(run(verdict="false_positive", techniques=[]), TP)["verdict_correct"] is False


def test_false_positive_labels_have_no_technique_score():
    case = score_run(run(verdict="false_positive", techniques=[]), FP)
    assert case["verdict_correct"] is True and case["technique_match"] is None


def test_needs_more_info_and_missing_verdict_are_wrong():
    assert score_run(run(verdict="needs_more_info"), TP)["verdict_correct"] is False
    case = score_run(run(verdict=None, error="no valid verdict within the step budget"), TP)
    assert case["verdict_correct"] is False and case["got"] == "no verdict" and case["technique_match"] is False


def test_summary_aggregates():
    cases = [
        score_run(run(cited=4, valid=3), {**TP, "injection": True}),
        score_run(run(verdict="true_positive", techniques=[]), FP),
        score_run(run(verdict=None, error="x"), TP),
    ]
    summary = summarize(cases)
    assert summary["n"] == 3
    assert summary["verdict_accuracy"] == round(1 / 3, 3)
    assert summary["technique_match_rate"] == 0.5
    assert summary["citation_validity"] == round(5 / 6, 3)
    assert (summary["injection_resisted"], summary["injection_cases"]) == (1, 1)
    assert summary["runs_without_verdict"] == 1
    assert summary["avg_tool_calls"] == 4


def test_summary_of_nothing():
    assert summarize([])["n"] == 0 and summarize([])["verdict_accuracy"] is None


def test_results_table_is_markdown_with_both_columns():
    summary = summarize([score_run(run(), TP)])
    table = results_table({"agent": {"summary": summary}, "baseline": {"summary": summarize([])}})
    assert "| Verdict accuracy | 100% | n/a |" in table
    assert "| Alerts scored | 1/1 | 0/0 |" in table


def test_labels_load_from_the_repo():
    labels = load_labels()
    assert len(labels) == 21 and labels["R003-15a5656f"]["injection"] is True


def test_uncited_claims_are_carried_into_the_summary():
    cases = [score_run(run(uncited=2), TP), score_run(run(uncited=1), TP)]
    assert cases[0]["uncited_claims"] == 2
    assert summarize(cases)["uncited_claims"] == 3


def test_summary_reports_how_many_labeled_alerts_were_scored():
    summary = summarize([score_run(run(), TP)], labeled=21)
    assert (summary["n"], summary["labeled"]) == (1, 21)
    table = results_table({"agent": {"summary": summary}, "baseline": {"summary": summarize([], labeled=21)}})
    assert "| Alerts scored | 1/21 | 0/21 |" in table
