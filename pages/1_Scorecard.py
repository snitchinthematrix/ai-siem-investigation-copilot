"""Scorecard page: how the agent did on the labeled alerts, next to a no-tools baseline."""
import json

import streamlit as st

from copilot.scoring import METRIC_ROWS, RESULTS_PATH

st.set_page_config(page_title="Scorecard", layout="wide")
st.title("Scorecard")

if not RESULTS_PATH.exists():
    st.info("No results yet. Run scripts/run_evals.py to produce them.")
    st.stop()

results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
agent, base = results["agent"], results["baseline"]
synthetic = sum(case["source"] == "synthetic" for case in agent["cases"])

st.caption(f"{agent['summary']['n']} labeled alerts ({synthetic} from hand-written synthetic scenarios) · "
           f"model {results['model']} · generated {results['generated']}")

st.table([{"Metric": name, "Agent (with tools)": fmt(agent["summary"]), "Baseline (alert only)": fmt(base["summary"])}
          for name, fmt in METRIC_ROWS])

failures = [case for case in agent["cases"] if not case["verdict_correct"]]
st.subheader(f"Agent failures ({len(failures)})")
if failures:
    st.table([{"alert": c["alert_id"], "expected": c["expected"], "got": c["got"],
               "source": c["source"], "error": c["error"] or ""} for c in failures])
else:
    st.write("None on this set.")

st.subheader("Every case")
st.dataframe(
    [{"alert": c["alert_id"], "source": c["source"], "injection": c["injection"], "expected": c["expected"],
      "agent": c["got"], "baseline": next((b["got"] for b in base["cases"] if b["alert_id"] == c["alert_id"]), "not run"),
      "technique match": c["technique_match"], "citations": f"{c['valid_citations']}/{c['cited']}",
      "tool calls": c["tool_calls"], "seconds": c["latency_s"]} for c in agent["cases"]],
    hide_index=True)

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
