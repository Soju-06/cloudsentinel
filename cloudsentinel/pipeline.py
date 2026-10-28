"""Scan orchestration: ingest -> detect -> persist, with de-duplication."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

from .config import Config
from .db import AlertStore
from .detectors import run_all
from .ingest import load_events
from .models import Alert
from .paths import DEFAULT_DB_PATH, RAW_DIR
from .severity import Severity


@dataclass
class ScanResult:
    events_scanned: int
    alerts: list[Alert]
    inserted: int = 0
    updated: int = 0
    merged: int = 0
    files: list[str] = field(default_factory=list)
    dropped_events: int = 0
    duplicate_events: int = 0

    @property
    def by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for alert in self.alerts:
            counts[alert.severity.value] += 1
        return counts

    def summary(self) -> dict[str, Any]:
        return {
            "events_scanned": self.events_scanned,
            "alerts": len(self.alerts),
            "by_severity": self.by_severity,
            "inserted": self.inserted,
            "updated": self.updated,
            "merged": self.merged,
            "files": self.files,
            "dropped_events": self.dropped_events,
            "duplicate_events": self.duplicate_events,
        }


def collect_alerts(events: pd.DataFrame, config: Config | None = None) -> list[Alert]:
    """Run every detector and return alerts sorted by severity."""

    config = config or Config()
    alerts = run_all(events, config)
    return sorted(
        alerts,
        key=lambda alert: (-alert.severity.score, alert.first_seen),
    )


def run_scan(
    events: pd.DataFrame,
    store: AlertStore,
    config: Config | None = None,
    alerts: list[Alert] | None = None,
) -> ScanResult:
    """Detect findings in *events* and persist them through *store*.

    Pass *alerts* when detection already ran (for example in a batch job) to
    skip a second detection pass.
    """

    config = config or Config()
    store.init()
    if alerts is None:
        alerts = collect_alerts(events, config)
    stats = store.upsert_many(alerts, suppression_minutes=config.suppression_minutes)
    return ScanResult(
        events_scanned=int(len(events)),
        alerts=alerts,
        inserted=stats["inserted"],
        updated=stats["updated"],
        merged=stats["merged"],
        files=list(events.attrs.get("files", [])),
        dropped_events=int(events.attrs.get("dropped", 0)),
        duplicate_events=int(events.attrs.get("duplicates", 0)),
    )


def scan_files(
    raw_dir: str | Path | None = None,
    db_path: str | Path | None = None,
    config: Config | None = None,
    reset: bool = False,
) -> ScanResult:
    """Convenience pipeline used by the CLI and dashboard."""

    config = config or Config()
    events = load_events(raw_dir or RAW_DIR)
    store = AlertStore(db_path or DEFAULT_DB_PATH)
    if reset:
        store.init().clear()
    return run_scan(events, store, config)
