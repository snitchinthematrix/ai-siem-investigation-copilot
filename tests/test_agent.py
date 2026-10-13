import json

import pytest

from copilot.agent import FORCE_SUBMIT, SUBMIT_SPEC, SYSTEM_PROMPT, baseline, investigate
from copilot.llm import LLMUnavailable
from copilot.rules import generate_alerts
from copilot.synthetic import INJECTION_NOTE
from tests.fakes import FakeLLM, turn, verdict_args

SEARCH = ("search_events", {"host": "workstation8", "keyword": "schtasks"})


@pytest.fixture()
def alert(conn):
    return next(a for a in generate_alerts(conn) if a.id == "R003-15a5656f")


def test_investigates_then_returns_a_validated_verdict(conn, alert):
    llm = FakeLLM([turn(SEARCH), turn(("submit_verdict", verdict_args()))])
    seen = []
    record = investigate(alert, conn, llm, on_step=seen.append)
    assert record.verdict.verdict == "true_positive"
    assert record.error is None
    assert (record.alert_id, record.mode, record.model) == ("R003-15a5656f", "agent", "fake-model")
    assert [s.kind for s in record.steps] == ["tool_call"] and seen == record.steps
    assert record.steps[0].result["events"][0]["event_id"] == "E000016"
    assert (record.citations.cited, record.citations.valid) == (1, 1)
    assert (record.usage.llm_calls, record.usage.tool_calls, record.usage.input_tokens) == (2, 1, 20)


def test_alert_trigger_events_count_as_retrieved(conn, alert):
    record = investigate(alert, conn, FakeLLM([turn(("submit_verdict", verdict_args()))]))
    assert record.citations.valid == 1


def test_unretrieved_and_invented_citations_are_reported(conn, alert):
    evidence = [{"claim": "c", "event_ids": ["E000001", "E999999", "E000016"]}]
    record = investigate(alert, conn, FakeLLM([turn(("submit_verdict", verdict_args(evidence=evidence, timeline=[])))]))
    assert record.citations.not_retrieved == ["E000001"]
    assert record.citations.nonexistent == ["E999999"]
    assert record.citations.valid == 1


def test_tool_results_go_back_to_the_model_and_carry_the_injection_text(conn, alert):
    llm = FakeLLM([turn(SEARCH), turn(("submit_verdict", verdict_args()))])
    investigate(alert, conn, llm)
    tool_message = llm.calls[1]["messages"][-1]
    assert tool_message["role"] == "tool" and tool_message["tool_call_id"] == "call0"
    assert INJECTION_NOTE in json.loads(tool_message["content"])["events"][0]["command_line"]
    assert "untrusted" in SYSTEM_PROMPT


def test_unparseable_arguments_and_unknown_tools_become_error_results(conn, alert):
    llm = FakeLLM([turn(("search_events", None)), turn(("delete_logs", {})), turn(("submit_verdict", verdict_args()))])
    record = investigate(alert, conn, llm)
    assert "not valid JSON" in record.steps[0].result["error"]
    assert "unknown tool" in record.steps[1].result["error"]
    assert record.verdict is not None


def test_invalid_verdict_is_rejected_and_the_model_can_retry(conn, alert):
    llm = FakeLLM([turn(("submit_verdict", {"verdict": "maybe"})), turn(("submit_verdict", verdict_args()))])
    record = investigate(alert, conn, llm)
    assert [s.kind for s in record.steps] == ["error"]
    assert "invalid verdict" in llm.calls[1]["messages"][-1]["content"]
    assert record.verdict.verdict == "true_positive"


def test_text_only_turn_is_nudged_back_to_the_tools(conn, alert):
    llm = FakeLLM([turn(content="I think it is fine."), turn(("submit_verdict", verdict_args()))])
    record = investigate(alert, conn, llm)
    assert llm.calls[1]["messages"][-1]["role"] == "user"
    assert record.verdict is not None


def test_step_budget_forces_a_final_verdict_call(conn, alert):
    llm = FakeLLM([turn(SEARCH)])  # never submits
    record = investigate(alert, conn, llm, max_steps=2)
    assert len(llm.calls) == 3
    assert [c["tool_choice"] for c in llm.calls] == ["auto", "auto", FORCE_SUBMIT]
    assert record.verdict is None and record.citations is None
    assert "step budget" in record.error


def test_provider_failure_ends_the_run_with_a_recorded_error(conn, alert):
    llm = FakeLLM([turn(SEARCH), LLMUnavailable("429 rate limit")])
    record = investigate(alert, conn, llm)
    assert record.error.startswith("LLM unavailable")
    assert record.verdict is None and len(record.steps) == 1


def test_baseline_makes_one_call_with_no_investigation_tools(conn, alert):
    llm = FakeLLM([turn(("submit_verdict", verdict_args()))])
    record = baseline(alert, conn, llm)
    assert len(llm.calls) == 1
    assert llm.calls[0]["tools"] == [SUBMIT_SPEC] and llm.calls[0]["tool_choice"] == FORCE_SUBMIT
    assert (record.mode, record.usage.tool_calls, record.steps) == ("baseline", 0, [])
    assert record.verdict is not None and record.citations.valid == 1


def test_baseline_records_invalid_output_and_provider_failure(conn, alert):
    assert "valid verdict" in baseline(alert, conn, FakeLLM([turn(("submit_verdict", {"verdict": "maybe"}))])).error
    assert baseline(alert, conn, FakeLLM([LLMUnavailable("down")])).error.startswith("LLM unavailable")


def test_a_rejected_request_ends_the_run_as_a_failure_not_an_outage(conn, alert):
    from copilot.llm import LLMRejected
    record = investigate(alert, conn, FakeLLM([turn(SEARCH), LLMRejected("400 context length")]))
    assert record.verdict is None
    assert record.error.startswith("LLM rejected") and not record.error.startswith("LLM unavailable")
    assert baseline(alert, conn, FakeLLM([LLMRejected("400")])).error.startswith("LLM rejected")


def test_both_prompts_treat_the_alert_and_tool_results_as_untrusted():
    from copilot.agent import BASELINE_PROMPT, UNTRUSTED_RULE
    assert "alert" in UNTRUSTED_RULE and "tool result" in UNTRUSTED_RULE
    assert UNTRUSTED_RULE in SYSTEM_PROMPT and UNTRUSTED_RULE in BASELINE_PROMPT
