"""Core data structures."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .severity import Severity
from .utils import to_iso


@dataclass
class Alert:
    """A finding produced by a detector and persisted in SQLite."""

    detector: str
    severity: Severity
    title: str
    description: str
    entity: str
    entity_type: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    evidence: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    id: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        self.severity = Severity.parse(self.severity)
        self.first_seen = _ensure_aware(self.first_seen)
        self.last_seen = _ensure_aware(self.last_seen)
        if self.first_seen > self.last_seen:
            self.first_seen, self.last_seen = self.last_seen, self.first_seen
        if not self.fingerprint:
            self.fingerprint = make_fingerprint(
                self.detector, self.entity, self.first_seen
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "detector": self.detector,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "entity": self.entity,
            "entity_type": self.entity_type,
            "event_count": int(self.event_count),
            "first_seen": to_iso(self.first_seen),
            "last_seen": to_iso(self.last_seen),
            "evidence": self.evidence,
            "created_at": to_iso(self.created_at) if self.created_at else None,
            "updated_at": to_iso(self.updated_at) if self.updated_at else None,
        }


def make_fingerprint(detector: str, entity: str, first_seen: datetime) -> str:
    """Stable identity so re-running a scan does not duplicate alerts."""

    payload = f"{detector}|{entity}|{to_iso(first_seen)}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:20]


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
