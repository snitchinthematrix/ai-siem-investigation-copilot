# AI SIEM Investigation Copilot

An AI agent that investigates a SIEM alert the way a SOC analyst would: it queries the logs, decides whether the alert is real, and cites the log events behind every claim.

> Status: the code and data are complete and tested. The evaluation has not been run yet, so there are no results or recorded investigations in the repository, and the app is not deployed. See [What is left](#what-is-left).

## What it does

- **Alert queue.** Six deliberately broad detection rules run over Windows event logs and produce 21 alerts, a mix of real attacks and benign activity.
- **Investigation agent.** For one alert, an LLM works through a tool-calling loop with four read-only tools: search events, walk a process tree, summarize what a host, user or IP did around a time, and look up a MITRE ATT&CK technique.
- **Structured verdict.** True positive, false positive or needs more information, with confidence, severity, ATT&CK technique IDs, a timeline, evidence, next actions and a short incident report.
- **Citation check.** Every event ID the verdict cites is checked: it must exist, and the agent must have retrieved it during that run. Anything else is flagged in the UI and counted in the scorecard.
- **Scorecard.** Accuracy on the 21 labeled alerts, next to the same model given only the alert text and no tools.

## Results

Not available yet. This section will hold the table printed by `python scripts/run_evals.py --table`, the model used, and the failure analysis.

## Architecture

```
public attack logs ──> normalize ──> DuckDB (events)
                                        │
              detection rules (SQL) ────┤──> alert queue
                                        │
   alert ──> agent loop ──(tools)───────┘
                │
                └──> verdict + evidence + ATT&CK + timeline + report
                              │
                     citation validator ──> UI
```

| Path | Responsibility |
|---|---|
| `copilot/normalize.py` | Raw record to `events` row, clock correction |
| `copilot/synthetic.py` | Hand-written scenarios (benign activity and a prompt-injection attack) |
| `copilot/db.py` | Paths, schema, create and connect |
| `copilot/rules.py` | Detection rules to alerts |
| `copilot/schema.py` | Pydantic models shared by everything |
| `copilot/attack.py` | MITRE ATT&CK technique lookup |
| `copilot/tools.py` | The four query tools, their specs, dispatch |
| `copilot/validate.py` | Citation validator |
| `copilot/llm.py` | Provider interface and OpenAI-compatible client |
| `copilot/agent.py` | Investigation loop and no-tools baseline |
| `copilot/runs.py` | Saved runs, live-to-recorded fallback |
| `copilot/scoring.py` | Labels, per-run scores, summary |
| `scripts/build_data.py` | Download the captures and build `data/` |
| `scripts/smoke_llm.py` | Check a provider supports what the agent needs |
| `scripts/run_evals.py` | Run agent and baseline over the labeled alerts |
| `app.py`, `pages/1_Scorecard.py` | Streamlit UI |

## Design decisions

**The model gets tools, not SQL.** The four tools take typed arguments and build parameterized queries. The model cannot write a query, so it cannot read outside the events table, and a keyword containing `%`, `_` or a quote is treated as literal text. Results are capped at 15 events with long fields truncated, and report the true match count so the model knows when to narrow a search.

**Citations are validated, within limits.** A cited event must exist and must have appeared in a tool result (or the alert) during that run. This catches invented and guessed event IDs. It does not prove the model read the event correctly; that is what the verdict accuracy measures.

**Log content is untrusted input.** Command lines and other attacker-controlled fields reach the model. The system prompt says tool results are data, never instructions, and one synthetic attack plants a note in a command line telling the "AI analyst" to mark the alert as a false positive. Two labeled alerts carry that note, and the scorecard reports whether the agent still judged them correctly. Model-written text is also shown with Markdown image syntax neutralized, so it cannot make the viewer's browser fetch an attacker-chosen URL.

**The demo does not depend on a free quota.** Every eval run is saved as JSON. The app replays those recordings by default and offers a limited number of live runs per session. If a live run fails because the provider is rate-limited or down, the app shows the recording with a notice.

**Timestamps needed correcting.** In these captures, Sysmon events carry `UtcTime` while other events carry a different field that runs 0, 4 or 16 hours off, depending on the capture. The normalizer measures the offset on records that have both fields and applies it to the rest, so events from the same second line up.

## Limitations

- The evaluation set is 21 alerts. Each one is several percentage points.
- 9 of the 21 alerts come from hand-written scenarios, not real telemetry.
- Seven false-positive labels on the public captures are a judgment: the capture documents one simulated technique, and those alerts fire on ordinary system processes around it.
- Windows data only, mostly Sysmon. Only nine extra raw fields are kept beyond the main columns.
- Each alert is run once, so run-to-run variation is not measured.
- This is not connected to a real SIEM and does not ingest live logs.

## Data and attribution

- **Attack telemetry:** [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) (MIT License), four Windows captures: LSASS memory dump via comsvcs.dll, Empire Run-key persistence, Empire scheduled-task creation, and a bitsadmin download.
- **Synthetic scenarios:** `copilot/synthetic.py` holds seven hand-written scenarios, six benign and one attack carrying a prompt injection. They are tagged `synthetic` in the database and in `evals/labels.yaml`.
- **MITRE ATT&CK:** technique names and descriptions come from the [MITRE CTI repository](https://github.com/mitre/cti). © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

## Run it locally

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

Recorded runs need no API key. For live runs and for the evaluation, set `LLM_BASE_URL`, `LLM_API_KEY` and `LLM_MODEL` to any OpenAI-compatible chat endpoint that supports tool calling.

- Check a provider: `python scripts/smoke_llm.py`
- Run the evaluation: `python scripts/run_evals.py`
- Rebuild the data from source: `python scripts/build_data.py`
- Run the tests: `python -m pytest`

## What is left

1. Choose a free-tier LLM provider with `scripts/smoke_llm.py` and record the model here.
2. Run `scripts/run_evals.py` once, commit `runs/` and `evals/results.json`, and fill in Results and the failure analysis.
3. Record a short demo GIF, deploy to Streamlit Community Cloud, and add the link.
