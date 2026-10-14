"""Scorecard page: how the agent did on the labeled alerts, next to a no-tools baseline."""
import json

import altair as alt
import streamlit as st

from copilot.scoring import METRIC_ROWS, RESULTS_PATH
from copilot.view import AGENT, BASELINE, class_accuracy

SERIES_COLOURS = ["#2a78d6", "#eb6834"]  # agent, baseline
FILTERS = {
    "All": lambda agent, base: True,
    "Agent wrong": lambda agent, base: not agent["verdict_correct"],
    "Baseline wrong": lambda agent, base: base is not None and not base["verdict_correct"],
    "Prompt injection": lambda agent, base: agent["injection"],
}

st.title("Scorecard")

if not RESULTS_PATH.exists():
    st.info("No results yet. Run scripts/run_evals.py to produce them.")
    st.stop()

results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
agent, base = results["agent"], results["baseline"]
summary, base_summary = agent["summary"], base["summary"]
base_by_alert = {case["alert_id"]: case for case in base["cases"]}
synthetic = sum(case["source"] == "synthetic" for case in agent["cases"])

st.caption(f"{summary['n']} of {summary['labeled']} labeled alerts scored ({synthetic} from hand-written synthetic scenarios) · "
           f"model {results['model']} · generated {results['generated']}")


def escalated(cases) -> tuple[int, int]:
    """Benign alerts called an attack, and how many benign alerts there were."""
    benign = [case for case in cases if case["expected"] == "false_positive"]
    return sum(case["got"] == "true_positive" for case in benign), len(benign)


tiles = st.columns(4)
accuracy, base_accuracy = summary["verdict_accuracy"], base_summary["verdict_accuracy"]
tiles[0].metric("Verdict accuracy", "n/a" if accuracy is None else f"{accuracy:.0%}", border=True, height="stretch",
                delta=None if None in (accuracy, base_accuracy) else f"{100 * (accuracy - base_accuracy):+.0f} pts vs baseline")
wrongly, benign_total = escalated(agent["cases"])
base_wrongly, _ = escalated(base["cases"])
tiles[1].metric("False alarms", f"{wrongly} of {benign_total}", border=True, height="stretch", delta_color="inverse",
                delta=f"{wrongly - base_wrongly:+d} vs baseline",
                help="Benign alerts the agent called an attack, out of all benign alerts.")
cited = sum(case["cited"] for case in agent["cases"])
valid = sum(case["valid_citations"] for case in agent["cases"])
tiles[2].metric("Valid citations", f"{valid} of {cited}", border=True, height="stretch",
                help="A cited event is valid when it exists and the agent retrieved it during that run.")
tiles[3].metric("Injections resisted", f"{summary['injection_resisted']} of {summary['injection_cases']}",
                border=True, height="stretch", help="Alerts whose log data tells the AI analyst to mark them as false positives.")

st.subheader("Verdict accuracy by what the alert really was")
chart_rows = class_accuracy(agent["cases"], base["cases"])
bars = alt.Chart(alt.Data(values=chart_rows)).encode(
    y=alt.Y("group:N", title=None, sort=None, scale=alt.Scale(paddingInner=0.3, paddingOuter=0.15), axis=alt.Axis(labelLimit=220, ticks=False, domain=False, labelPadding=8)),
    yOffset=alt.YOffset("who:N", sort=[AGENT, BASELINE]),
    x=alt.X("accuracy:Q", title="Alerts judged correctly (%)", scale=alt.Scale(domain=[0, 100]),
            axis=alt.Axis(values=[0, 25, 50, 75, 100], gridColor="#e6e8eb", domainColor="#c9cdd2", tickColor="#c9cdd2")),
    tooltip=[alt.Tooltip("who:N", title="Run"), alt.Tooltip("group:N", title="Alerts"),
             alt.Tooltip("correct:Q", title="Correct"), alt.Tooltip("total:Q", title="Total"),
             alt.Tooltip("accuracy:Q", title="Accuracy (%)")],
)
chart = (
    bars.mark_bar(size=16, cornerRadiusEnd=4).encode(
        color=alt.Color("who:N", title=None, sort=[AGENT, BASELINE],
                        scale=alt.Scale(domain=[AGENT, BASELINE], range=SERIES_COLOURS),
                        legend=alt.Legend(orient="top", direction="horizontal", symbolType="square")))
    + bars.mark_text(align="left", dx=6, color="#1b1f24").encode(text=alt.Text("label:N"))
    .transform_calculate(label="datum.correct + ' of ' + datum.total")
).properties(height=alt.Step(24)).configure_view(stroke=None)
st.altair_chart(chart, width="stretch")
st.caption("The baseline is the same model given only the alert text, with no tools.")

with st.expander("All metrics", icon=":material/table_rows:"):
    st.dataframe([{"Metric": name, AGENT: fmt(summary), BASELINE: fmt(base_summary)} for name, fmt in METRIC_ROWS],
                 hide_index=True)

failures = [case for case in agent["cases"] if not case["verdict_correct"]]
st.subheader(f"Agent failures ({len(failures)})")
if failures:
    st.dataframe([{"alert": c["alert_id"], "expected": c["expected"], "got": c["got"],
                   "source": c["source"], "error": c["error"]} for c in failures], hide_index=True)
else:
    st.write("None on this set.")

st.subheader("Every case")
shown_filter, source_filter = st.columns([3, 2])
choice = shown_filter.segmented_control("Show", list(FILTERS), default="All") or "All"
sources = source_filter.pills("Source", sorted({case["source"] for case in agent["cases"]}), selection_mode="multi")
cases = [case for case in agent["cases"]
         if FILTERS[choice](case, base_by_alert.get(case["alert_id"]))
         and (not sources or case["source"] in sources)]


def baseline_field(case, name, missing):
    other = base_by_alert.get(case["alert_id"])
    return other[name] if other else missing


selection = st.dataframe(
    [{"alert": c["alert_id"], "source": c["source"], "injection": c["injection"], "expected": c["expected"],
      "agent": c["got"], "agent correct": c["verdict_correct"],
      "baseline": baseline_field(c, "got", "not run"), "baseline correct": baseline_field(c, "verdict_correct", None),
      "technique match": c["technique_match"], "citations": f"{c['valid_citations']}/{c['cited']}",
      "tool calls": c["tool_calls"], "seconds": c["latency_s"]} for c in cases],
    hide_index=True, on_select="rerun", selection_mode=["single-row", "single-cell"], key=f"cases|{choice}|{sources}",
).selection
selection = list(selection.rows) or [cell[0] for cell in selection.get("cells", [])]
st.caption(f"{len(cases)} of {len(agent['cases'])} cases shown. Click a row to open that alert's investigation.")
if selection and selection[0] < len(cases):
    chosen = cases[selection[0]]["alert_id"]
    if st.button(f"Open {chosen} in Investigate", type="primary", icon=":material/open_in_new:"):
        st.session_state["alert_id"] = chosen
        st.switch_page("views/investigate.py")

st.subheader("How to read this")
st.markdown(
    "- The set is small. Each alert is several percentage points, so treat the numbers as a sanity check, "
    "not a benchmark.\n"
    "- Attack alerts come from public OTRF Security Datasets captures. Several benign alerts and the "
    "prompt-injection attack are hand-written and marked synthetic.\n"
    "- A citation is valid when the event exists and the agent retrieved it during the run. "
    "It does not prove the claim is a correct reading of that event.\n"
    "- The baseline is the same model given only the alert text, to show what querying the logs adds.\n"
    "- Each alert was run once. A run that ended without a verdict counts as wrong."
)
