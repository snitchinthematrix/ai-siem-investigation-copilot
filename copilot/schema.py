"""Data shapes shared across the project."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Alert(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: str
    host: str
    ts: str
    summary: str
    event_count: int
    trigger_event_ids: list[str]


class EvidenceItem(BaseModel):
    claim: str
    event_ids: list[str] = []


class TimelineEntry(BaseModel):
    ts: str
    description: str
    event_ids: list[str] = []


class Verdict(BaseModel):
    verdict: Literal["true_positive", "false_positive", "needs_more_info"]
    confidence: float = Field(ge=0, le=1)
    severity: Literal["informational", "low", "medium", "high", "critical"]
    techniques: list[str] = []
    timeline: list[TimelineEntry] = []
    evidence: list[EvidenceItem]
    next_actions: list[str] = []
    report_md: str


class CitationReport(BaseModel):
    cited: int
    valid: int
    not_retrieved: list[str]
    nonexistent: list[str]
    uncited_claims: int


class Step(BaseModel):
    kind: Literal["tool_call", "error"]
    tool: str | None = None
    arguments: dict | None = None
    result: dict | None = None
    message: str | None = None


class Usage(BaseModel):
    llm_calls: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0


class RunRecord(BaseModel):
    alert_id: str
    mode: Literal["agent", "baseline"]
    model: str
    steps: list[Step] = []
    verdict: Verdict | None = None
    citations: CitationReport | None = None
    usage: Usage = Usage()
    error: str | None = None
