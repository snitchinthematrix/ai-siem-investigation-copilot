"""Run the agent and the baseline over every labeled alert and write evals/results.json."""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from copilot.agent import baseline, investigate
from copilot.db import connect
from copilot.llm import llm_from_env
from copilot.rules import load_alerts
from copilot.runs import load_run, save_run
from copilot.scoring import RESULTS_PATH, load_labels, results_table, score_run, summarize

RUNNERS = {"agent": investigate, "baseline": baseline}


def write_results(labels: dict) -> dict:
    results = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "model": None}
    for mode in RUNNERS:
        records = [(alert_id, load_run(alert_id, mode)) for alert_id in labels]
        cases = [score_run(record, labels[alert_id]) for alert_id, record in records if record]
        results[mode] = {"summary": summarize(cases, labeled=len(labels)), "cases": cases}
        results["model"] = next((record.model for _, record in records if record), results["model"])
    RESULTS_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["both", "agent", "baseline"], default="both")
    parser.add_argument("--only", help="run a single alert ID")
    parser.add_argument("--sleep", type=float, default=5, help="seconds to wait between runs")
    parser.add_argument("--force", action="store_true", help="re-run alerts that already have a saved run")
    parser.add_argument("--table", action="store_true", help="only rebuild results.json and print the table")
    args = parser.parse_args()

    labels = load_labels()
    if not args.table:
        llm = llm_from_env()
        if llm is None:
            print("Set LLM_BASE_URL, LLM_API_KEY and LLM_MODEL first.")
            return 1
        conn, alerts = connect(), {alert.id: alert for alert in load_alerts()}
        modes = list(RUNNERS) if args.mode == "both" else [args.mode]
        for alert_id in labels:
            if args.only and alert_id != args.only:
                continue
            for mode in modes:
                if load_run(alert_id, mode) and not args.force:
                    continue
                record = RUNNERS[mode](alerts[alert_id], conn, llm)
                if record.error and record.error.startswith("LLM unavailable"):
                    print(f"stopped at {alert_id} ({mode}): {record.error}")
                    print("Nothing was saved for this alert. Run the script again later to resume.")
                    write_results(labels)
                    return 1
                save_run(record)
                got = record.verdict.verdict if record.verdict else f"no verdict ({record.error})"
                print(f"{alert_id} {mode}: {got}, expected {labels[alert_id]['verdict']}")
                time.sleep(args.sleep)
    results = write_results(labels)
    print(results_table(results))
    missing = {mode: len(labels) - results[mode]["summary"]["n"] for mode in RUNNERS}
    if any(missing.values()):
        print(f"INCOMPLETE: alerts not yet run - {missing}. Do not publish these numbers.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
