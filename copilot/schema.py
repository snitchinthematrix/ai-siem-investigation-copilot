"""Data shapes shared across the project."""
from __future__ import annotations

from pydantic import BaseModel


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
