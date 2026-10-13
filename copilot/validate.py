"""Check a verdict's citations against the events the run actually saw."""
from __future__ import annotations

from copilot.schema import CitationReport, Verdict


def validate_citations(verdict: Verdict, retrieved_ids: set[str], conn) -> CitationReport:
    cited = []
    for item in [*verdict.evidence, *verdict.timeline]:
        for event_id in item.event_ids:
            if event_id not in cited:
                cited.append(event_id)
    existing = set()
    if cited:
        placeholders = ", ".join("?" * len(cited))
        rows = conn.execute(f"SELECT event_id FROM events WHERE event_id IN ({placeholders})", cited).fetchall()
        existing = {row[0] for row in rows}
    nonexistent = [e for e in cited if e not in existing]
    not_retrieved = [e for e in cited if e in existing and e not in retrieved_ids]
    return CitationReport(
        cited=len(cited),
        valid=len(cited) - len(nonexistent) - len(not_retrieved),
        not_retrieved=not_retrieved,
        nonexistent=nonexistent,
        uncited_claims=sum(1 for item in verdict.evidence if not item.event_ids),
    )
