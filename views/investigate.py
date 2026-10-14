"""Investigate page: pick an alert from the queue and watch the agent work through it."""
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
from copilot.tools import get_event
from copilot.view import (
    SEVERITY_COLOR, SEVERITY_ORDER, VERDICTS, filter_alerts, queue_rows, result_events, selected_alert,
    step_outcome, step_title,
)

REPLAY_DELAY = float(os.environ.get("REPLAY_DELAY", "0.5"))
LIVE_RUNS_PER_SESSION = 3
REPLAY, LIVE = "Recorded run", "Live run"
TOOL_ICONS = {
    "search_events": ":material/search:",
    "get_process_tree": ":material/account_tree:",
    "get_entity_activity": ":material/monitoring:",
    "lookup_attack_technique": ":material/menu_book:",
}
# Shown first in an events table; the remaining fields follow.
EVENT_COLUMNS = ["event_id", "ts", "host", "event_code", "username", "image", "command_line"]


@st.cache_resource
def shared_connection():
    return connect()


@st.cache_data
def recorded_verdicts(alert_ids: tuple[str, ...]) -> dict[str, str]:
    runs = {alert_id: load_run(alert_id) for alert_id in alert_ids}
    return {alert_id: run.verdict.verdict for alert_id, run in runs.items() if run and run.verdict}


@st.cache_data
def event_by_id(event_id: str) -> dict | None:
    return get_event(shared_connection().cursor(), event_id)


def field(column, label: str, value: str) -> None:
    """A labelled value that wraps instead of being cut off. value is Markdown."""
    column.caption(label)
    column.markdown(value)


def events_table(events: list[dict]) -> None:
    # A dataframe shows text literally, so log content needs no escaping here.
    columns = EVENT_COLUMNS + sorted({key for event in events for key in event} - set(EVENT_COLUMNS))
    st.dataframe([{column: event.get(column) for column in columns} for event in events], hide_index=True)


def event_links(event_ids: list[str], unverified=frozenset(), key: str = "") -> None:
    """One button per cited event; pressing it shows the log event the claim rests on."""
    if not event_ids:
        st.caption("No events cited.")
        return
    with st.container(horizontal=True):
        for position, event_id in enumerate(event_ids):
            event = None if event_id in unverified else event_by_id(event_id)
            if event is None:
                st.markdown(f":red-badge[:material/warning: {plain(event_id)} unverified]")
                continue
            with st.popover(plain(event_id), icon=":material/description:", key=f"event-{key}-{position}",
                            width="content"):
                st.caption(f"{event.get('channel', '')} · event code {event.get('event_code', '')}")
                st.dataframe([{"field": name, "value": str(value)} for name, value in event.items()],
                             hide_index=True, width=640)
                if event.get("command_line"):
                    st.caption("Command line")
                    st.code(event["command_line"], language=None, wrap_lines=True)


def render_step(number: int, step) -> None:
    if step.kind == "error":
        st.warning(f"Rejected verdict: {plain(step.message)}", icon=":material/block:")
        return
    result = step.result or {}
    label = plain(step_title(number, step)) + f" → {step_outcome(step)}"
    with st.expander(label, icon=TOOL_ICONS.get(step.tool, ":material/build:")):
        if "error" in result:
            st.error(plain(result["error"]))
        tab_names = ["Result", "Arguments", "Raw JSON"]
        shown, arguments, raw = st.tabs(tab_names)
        with shown:
            events = result_events(result)
            if result.get("truncated") or result.get("total_matches", 0) > len(events):
                st.caption(f"Showing {len(events)} of {result['total_matches']} matching events.")
            if events:
                events_table(events)
            elif "matches" in result:
                st.dataframe([{"technique": match.get("id"), "name": match.get("name"),
                               "tactics": ", ".join(match.get("tactics", []))} for match in result["matches"]],
                             hide_index=True)
            elif "error" not in result:
                st.caption("No events returned.")
        with arguments:
            st.dataframe([{"argument": name, "value": str(value)} for name, value in (step.arguments or {}).items()],
                         hide_index=True)
        with raw:
            st.json(result, expanded=1)


def render_verdict(record, label) -> None:
    verdict, citations = record.verdict, record.citations
    unverified = set(citations.not_retrieved) | set(citations.nonexistent)
    name, colour, meaning = VERDICTS[verdict.verdict]

    st.subheader("Verdict")
    with st.container(border=True):
        columns = st.columns([3, 2, 2, 2, 3])
        field(columns[0], f"Verdict · {meaning.lower()}", f"#### :{colour}[{name}]")
        field(columns[1], "Confidence", f"**{verdict.confidence:.0%}**")
        field(columns[2], "Severity", f":{SEVERITY_COLOR[verdict.severity]}-badge[{verdict.severity}]")
        citation_colour = "red" if unverified else "green"
        field(columns[3], "Valid citations", f":{citation_colour}-badge[{citations.valid} of {citations.cited}]")
        if label:
            matches = label["verdict"] == verdict.verdict
            field(columns[4], "Ground truth",
                  ":green-badge[:material/check: Matches the label]" if matches
                  else f":red-badge[:material/close: Label says {label['verdict'].replace('_', ' ')}]")
        st.markdown("**ATT&CK techniques:** " + (" ".join(f":gray-badge[{plain(t)}]" for t in verdict.techniques)
                                               or "none"))
    if unverified:
        st.error("Unverified citations: " + plain(", ".join(sorted(unverified)))
                 + ". These event IDs do not exist or were never retrieved during the run.")
    if citations.uncited_claims:
        st.warning(f"{citations.uncited_claims} evidence claim(s) cite no events.")

    evidence, timeline, actions, written = st.tabs([
        f"Evidence ({len(verdict.evidence)})", f"Timeline ({len(verdict.timeline)})",
        f"Next actions ({len(verdict.next_actions)})", "Incident report"])
    with evidence:
        st.caption("Press an event ID to see the log event the claim rests on.")
        for number, item in enumerate(verdict.evidence):
            with st.container(border=True):
                st.markdown(plain(item.claim))
                event_links(item.event_ids, unverified, key=f"evidence-{number}")
    with timeline:
        if verdict.timeline:
            for number, entry in enumerate(verdict.timeline):
                with st.container(border=True):
                    when, what = st.columns([1, 4])
                    when.markdown(f"**{plain(entry.ts)}**")
                    with what:
                        st.markdown(plain(entry.description))
                        event_links(entry.event_ids, unverified, key=f"timeline-{number}")
        else:
            st.caption("The agent gave no timeline.")
    with actions:
        if verdict.next_actions:
            for action in verdict.next_actions:
                st.markdown(f"- {plain(action)}")
        else:
            st.caption("The agent recommended no actions.")
    with written:
        st.markdown(report(verdict.report_md))

    usage = record.usage
    st.caption(f"{record.model} · {usage.tool_calls} tool calls · "
               f"{usage.input_tokens + usage.output_tokens} tokens · {usage.latency_s:.1f}s")
    if label:
        with st.expander("Ground truth for this alert", icon=":material/fact_check:"):
            origin = "hand-written synthetic scenario" if label["source"] == "synthetic" else "OTRF Security Datasets capture"
            st.write(f"**{label['verdict'].replace('_', ' ')}** ({origin}): {label['note']}")


def show(record, label, animate: bool) -> None:
    st.subheader(f"Investigation trace ({len(record.steps)} steps)")
    for number, step in enumerate(record.steps, start=1):
        render_step(number, step)
        if animate:
            time.sleep(REPLAY_DELAY)
    if record.verdict:
        render_verdict(record, label)
    else:
        st.error(f"The run ended without a verdict: {plain(record.error)}")


alerts = sorted(load_alerts(), key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.id))
labels = load_labels()
llm = llm_from_env()
verdict_by_alert = recorded_verdicts(tuple(alert.id for alert in alerts))
live_runs_left = LIVE_RUNS_PER_SESSION - st.session_state.get("live_runs", 0)

st.title("SIEM Investigation Copilot")
st.caption("An AI agent investigates a SIEM alert over Windows attack telemetry and cites the log events "
           "behind every claim. Its accuracy is on the Scorecard page.")

with st.sidebar:
    st.header("Run")
    live_available = llm is not None and live_runs_left > 0
    mode = st.radio("Run", [REPLAY, LIVE], disabled=not live_available, label_visibility="collapsed")
    if llm is None:
        st.caption("Live runs are off: no LLM is configured. Recorded runs show real agent output.")
    elif live_runs_left <= 0:
        st.caption("Live run limit for this session reached. Recorded runs remain available.")
    else:
        st.caption(f"{live_runs_left} live run(s) left this session. The LLM is on a free tier.")
    st.divider()
    st.caption("Recorded runs are the agent's real output from the evaluation, saved so the demo works "
               "without an API key.")

st.subheader("Alert queue")
severity_filter, rule_filter, verdict_filter = st.columns([2, 3, 5])
severities = severity_filter.pills("Severity", sorted({a.severity for a in alerts}, key=SEVERITY_ORDER.get),
                                   selection_mode="multi")
rule = rule_filter.selectbox("Rule", sorted({a.title for a in alerts}), index=None, placeholder="All rules")
wanted_verdicts = verdict_filter.pills("Agent verdict", list(VERDICTS), selection_mode="multi",
                                       format_func=lambda v: VERDICTS[v][0])
visible = filter_alerts(alerts, verdict_by_alert, severities, rule, wanted_verdicts)

# The key changes with the filters so a row number from one filtered table is never read against another.
queue_key = f"queue|{severities}|{rule}|{wanted_verdicts}"
# Cell selection is on as well as row selection so that a click anywhere in a row opens it.
chosen = st.dataframe(
    queue_rows(visible, verdict_by_alert, st.session_state.get("alert_id")), hide_index=True, height=248,
    key=queue_key, on_select="rerun", selection_mode=["single-row", "single-cell"],
    column_config={"Open": st.column_config.TextColumn("", width=30),
                   "Rule": st.column_config.TextColumn(width="medium"),
                   "Events": st.column_config.NumberColumn(width="small")}).selection
picked_rows = list(chosen.rows) or [cell[0] for cell in chosen.get("cells", [])]
pick = (queue_key, picked_rows[0]) if picked_rows else None
alert_id = selected_alert(alerts, visible, st.session_state.get("alert_id"), pick, st.session_state.get("queue_pick"))
st.session_state["queue_pick"] = pick
if alert_id != st.session_state.get("alert_id"):
    st.session_state["alert_id"] = alert_id
    st.rerun()  # redraw the queue with the marker on the newly opened alert
st.caption(f"{len(visible)} of {len(alerts)} alerts shown. Click a row to open that alert; ● marks the open one.")

alert = next(a for a in alerts if a.id == alert_id)
label = labels.get(alert.id)
recorded = load_run(alert.id)

with st.container(border=True):
    st.markdown(f"#### {alert.id} · {alert.title} &nbsp; :{SEVERITY_COLOR.get(alert.severity, 'gray')}-badge[{alert.severity}]")
    st.text(alert.summary)  # raw log text: shown literally, never as Markdown
    host, seen, count, triggers = st.columns([2, 3, 2, 5])
    field(host, "Host", f"**{plain(alert.host)}**")
    field(seen, "First seen (UTC)", f"**{plain(alert.ts)}**")
    field(count, "Matching events", f"**{alert.event_count}**")
    with triggers:
        st.caption("Trigger events")
        event_links(alert.trigger_event_ids, key="trigger")

if mode == LIVE and llm is not None:
    live_results = st.session_state.setdefault("live_results", {})
    if st.button("Investigate live", type="primary", icon=":material/play_arrow:", disabled=live_runs_left <= 0):
        st.session_state["live_runs"] = st.session_state.get("live_runs", 0) + 1
        progress = st.empty()
        with progress.container():
            st.subheader("Investigating...")
            seen_steps = []

            def on_step(step) -> None:
                seen_steps.append(step)
                render_step(len(seen_steps), step)

            live_results[alert.id] = investigate(alert, shared_connection().cursor(), llm, on_step=on_step)
        progress.empty()
        st.rerun()  # so the sidebar counts this run
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
    show(recorded, label, animate=st.button("Replay step by step", type="primary", icon=":material/replay:"))
