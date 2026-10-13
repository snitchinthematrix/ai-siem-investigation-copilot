"""Investigate page: pick an alert and watch the agent work through it."""
import os
import time

import streamlit as st

from copilot.agent import investigate
from copilot.db import connect
from copilot.llm import llm_from_env
from copilot.render import plain, report
from copilot.rules import load_alerts
from copilot.runs import load_run, resolve_live_result
from copilot.scoring import load_labels

REPLAY_DELAY = float(os.environ.get("REPLAY_DELAY", "0.5"))
LIVE_RUNS_PER_SESSION = 3
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
REPLAY, LIVE = "Recorded run", "Live run"

st.set_page_config(page_title="SIEM Investigation Copilot", layout="wide")


@st.cache_resource
def shared_connection():
    return connect()


def render_step(step) -> None:
    if step.kind == "error":
        st.warning(f"Rejected verdict: {plain(step.message)}")
        return
    arguments = ", ".join(f"{key}={value!r}" for key, value in (step.arguments or {}).items())
    result = step.result or {}
    if "error" in result:
        outcome = "error"
    elif "total_matches" in result:
        outcome = f"{result['total_matches']} matches"
    else:
        outcome = "done"
    with st.expander(plain(f"{step.tool}({arguments})"[:110] + f" -> {outcome}")):
        st.json(result)


def render_verdict(record, label) -> None:
    verdict, citations = record.verdict, record.citations
    unverified = set(citations.not_retrieved) | set(citations.nonexistent)
    columns = st.columns(4)
    columns[0].metric("Verdict", verdict.verdict.replace("_", " "))
    columns[1].metric("Confidence", f"{verdict.confidence:.0%}")
    columns[2].metric("Severity", verdict.severity)
    columns[3].metric("Valid citations", f"{citations.valid}/{citations.cited}")
    if unverified:
        st.error("Unverified citations: " + plain(", ".join(sorted(unverified)))
                 + ". These event IDs do not exist or were never retrieved during the run.")
    if citations.uncited_claims:
        st.warning(f"{citations.uncited_claims} evidence claim(s) cite no events.")
    st.write("**ATT&CK techniques:** " + (plain(", ".join(verdict.techniques)) or "none"))

    st.subheader("Evidence")
    for item in verdict.evidence:
        ids = ", ".join(f"{i} (unverified)" if i in unverified else i for i in item.event_ids) or "no citation"
        st.markdown(f"- {plain(item.claim)}  \n  {plain(ids)}")
    if verdict.timeline:
        st.subheader("Timeline")
        st.table([{"time": plain(entry.ts), "what happened": plain(entry.description),
                   "events": plain(", ".join(entry.event_ids))}
                  for entry in verdict.timeline])
    if verdict.next_actions:
        st.subheader("Recommended next actions")
        for action in verdict.next_actions:
            st.markdown(f"- {plain(action)}")
    st.subheader("Incident report")
    st.markdown(report(verdict.report_md))

    usage = record.usage
    st.caption(f"{record.model} · {usage.tool_calls} tool calls · "
               f"{usage.input_tokens + usage.output_tokens} tokens · {usage.latency_s:.1f}s")
    if label:
        with st.expander("Ground truth for this alert"):
            origin = "hand-written synthetic scenario" if label["source"] == "synthetic" else "OTRF Security Datasets capture"
            st.write(f"**{label['verdict'].replace('_', ' ')}** ({origin}): {label['note']}")


def show(record, label, animate: bool) -> None:
    st.subheader("Investigation trace")
    for step in record.steps:
        render_step(step)
        if animate:
            time.sleep(REPLAY_DELAY)
    if record.verdict:
        render_verdict(record, label)
    else:
        st.error(f"The run ended without a verdict: {plain(record.error)}")


alerts = sorted(load_alerts(), key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.id))
labels = load_labels()
llm = llm_from_env()
live_runs_left = LIVE_RUNS_PER_SESSION - st.session_state.get("live_runs", 0)

st.title("SIEM Investigation Copilot")
st.caption("An AI agent investigates a SIEM alert over Windows attack telemetry and cites the log events "
           "behind every claim. Its accuracy is on the Scorecard page.")

with st.sidebar:
    st.header("Alert queue")
    # The ID keeps labels unique: Streamlit matches a selection by label, so duplicates collapse into one.
    index = st.radio("Alert", range(len(alerts)), label_visibility="collapsed",
                     format_func=lambda i: f"[{alerts[i].severity}] {alerts[i].title} · {alerts[i].host} · {alerts[i].id}")
    live_available = llm is not None and live_runs_left > 0
    mode = st.radio("Run", [REPLAY, LIVE], disabled=not live_available)
    if llm is None:
        st.caption("Live runs are off: no LLM is configured. Recorded runs show real agent output.")
    elif live_runs_left <= 0:
        st.caption("Live run limit for this session reached. Recorded runs remain available.")
    else:
        st.caption(f"{live_runs_left} live run(s) left this session. The LLM is on a free tier.")

alert = alerts[index]
label = labels.get(alert.id)
recorded = load_run(alert.id)

st.subheader(f"{alert.id}: {alert.title}")
st.text(alert.summary)  # raw log text: shown literally, never as Markdown
st.caption(f"Host {alert.host} · first seen {alert.ts} UTC · {alert.event_count} matching event(s) · "
           f"triggers {', '.join(alert.trigger_event_ids)}")

if mode == LIVE and live_available:
    live_results = st.session_state.setdefault("live_results", {})
    if st.button("Investigate live", type="primary"):
        st.session_state["live_runs"] = st.session_state.get("live_runs", 0) + 1
        progress = st.empty()
        with progress.container():
            st.subheader("Investigating...")
            live_results[alert.id] = investigate(alert, shared_connection().cursor(), llm, on_step=render_step)
        progress.empty()
    record, notice = resolve_live_result(live_results.get(alert.id), recorded)
    if notice:
        st.warning(plain(notice))
    if record is None:
        st.info("Press Investigate live to run the agent on this alert now.")
    else:
        show(record, label, animate=False)
elif recorded is None:
    st.info("No recorded run for this alert yet. Create one with scripts/run_evals.py.")
else:
    show(recorded, label, animate=st.button("Replay step by step", type="primary"))
