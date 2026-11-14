from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_id: int
    computer: str
    user: str
    source_ip: str
    outcome: str
    action: str
    details: str
    source_record: int


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    explanation: str
    recommendation: str
    evidence: list[Event] = field(default_factory=list)


@dataclass(frozen=True)
class EvidenceFile:
    path: str
    sha256: str
    size_bytes: int

