"""SQLite persistence for alerts.

Raw audit events intentionally stay in files (``data/raw``); only alerts are
persisted so history, de-duplication and dashboard filtering survive between
runs.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .models import Alert
from .paths import DEFAULT_DB_PATH
from .severity import Severity, highest
from .utils import as_list, json_dumps, parse_timestamp, to_iso, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL UNIQUE,
    detector      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    entity        TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    event_count   INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_detector  ON alerts(detector);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_entity    ON alerts(entity);
"""


class AlertStore:
    """Thin SQLite repository for :class:`Alert` records."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or DEFAULT_DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> "AlertStore":
        with self.connection() as conn:
            conn.executescript(SCHEMA)
        return self

    # ------------------------------------------------------------------ write

    def upsert(self, alert: Alert, suppression_minutes: int = 60) -> tuple[str, int]:
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            return self._upsert(conn, alert, suppression_minutes)

    def upsert_many(
        self, alerts: Iterable[Alert], suppression_minutes: int = 60
    ) -> dict[str, int]:
        stats = {"inserted": 0, "updated": 0, "merged": 0}
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            for alert in alerts:
                action, _ = self._upsert(conn, alert, suppression_minutes)
                stats[action] += 1
        return stats

    def _upsert(
        self, conn: sqlite3.Connection, alert: Alert, suppression_minutes: int
    ) -> tuple[str, int]:
        now = to_iso(utcnow())

        # 1. Exact same finding (same detector/entity/time bucket) -> update.
        row = conn.execute(
            "SELECT * FROM alerts WHERE fingerprint = ?", (alert.fingerprint,)
        ).fetchone()
        if row is not None:
            severity = highest(row["severity"], alert.severity).value
            conn.execute(
                """
                UPDATE alerts
                   SET severity = ?, description = ?, event_count = ?,
                       last_seen = ?, evidence = ?, updated_at = ?
                 WHERE id = ?
                """,
                (
                    severity,
                    alert.description,
                    max(int(row["event_count"]), alert.event_count),
                    max(row["last_seen"], to_iso(alert.last_seen)),
                    json_dumps(alert.evidence),
                    now,
                    row["id"],
                ),
            )
            return "updated", int(row["id"])

        # 2. Nearby finding for the same detector/entity -> merge (suppression).
        suppression = timedelta(minutes=max(0, suppression_minutes))
        lower = to_iso(alert.first_seen - suppression)
        upper = to_iso(alert.last_seen + suppression)
        row = conn.execute(
            """
            SELECT * FROM alerts
             WHERE detector = ? AND entity = ?
               AND last_seen >= ? AND first_seen <= ?
             ORDER BY last_seen DESC
             LIMIT 1
            """,
            (alert.detector, alert.entity, lower, upper),
        ).fetchone()
        if row is not None:
            first_seen = min(
                parse_timestamp(row["first_seen"]) or alert.first_seen,
                alert.first_seen,
            )
            last_seen = max(
                parse_timestamp(row["last_seen"]) or alert.last_seen,
                alert.last_seen,
            )
            severity = highest(row["severity"], alert.severity).value
            evidence = _merge_evidence(row["evidence"], alert.evidence)
            conn.execute(
                """
                UPDATE alerts
                   SET severity = ?, last_seen = ?, event_count = ?,
                       description = ?, evidence = ?, updated_at = ?
                 WHERE id = ?
                """,
                (
                    severity,
                    to_iso(last_seen),
                    int(row["event_count"]) + alert.event_count,
                    alert.description,
                    json_dumps(evidence),
                    now,
                    row["id"],
                ),
            )
            return "merged", int(row["id"])

        # 3. Brand new finding.
        cursor = conn.execute(
            """
            INSERT INTO alerts (
                fingerprint, detector, severity, title, description, entity,
                entity_type, event_count, first_seen, last_seen, evidence,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.fingerprint,
                alert.detector,
                alert.severity.value,
                alert.title,
                alert.description,
                alert.entity,
                alert.entity_type,
                alert.event_count,
                to_iso(alert.first_seen),
                to_iso(alert.last_seen),
                json_dumps(alert.evidence),
                now,
                now,
            ),
        )
        return "inserted", int(cursor.lastrowid)

    # ------------------------------------------------------------------- read

    def fetch_alerts(
        self,
        severity: Sequence[Severity | str] | Severity | str | None = None,
        detector: Sequence[str] | str | None = None,
        since: datetime | str | None = None,
        until: datetime | str | None = None,
        search: str | None = None,
        limit: int | None = None,
    ) -> list[Alert]:
        query = ["SELECT * FROM alerts WHERE 1 = 1"]
        params: list[Any] = []

        severities = [Severity.parse(item).value for item in as_list(severity)]
        if severities:
            query.append(f"AND severity IN ({','.join('?' * len(severities))})")
            params.extend(severities)

        detectors = [str(item) for item in as_list(detector)]
        if detectors:
            query.append(f"AND detector IN ({','.join('?' * len(detectors))})")
            params.extend(detectors)

        if since is not None:
            query.append("AND last_seen >= ?")
            params.append(since if isinstance(since, str) else to_iso(since))
        if until is not None:
            query.append("AND first_seen <= ?")
            params.append(until if isinstance(until, str) else to_iso(until))

        if search:
            like = f"%{search.strip()}%"
            query.append(
                "AND (entity LIKE ? OR title LIKE ? OR description LIKE ? OR detector LIKE ?)"
            )
            params.extend([like, like, like, like])

        query.append(
            """
            ORDER BY CASE severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                     END,
                     last_seen DESC
            """
        )
        if limit is not None:
            query.append("LIMIT ?")
            params.append(int(limit))

        with self.connection() as conn:
            conn.executescript(SCHEMA)
            rows = conn.execute(" ".join(query), params).fetchall()
        return [_row_to_alert(row) for row in rows]

    def get(self, alert_id: int) -> Alert | None:
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (int(alert_id),)
            ).fetchone()
        return _row_to_alert(row) if row else None

    def count(self) -> int:
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            return int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])

    def stats(self) -> dict[str, Any]:
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            total = int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            by_severity = {
                row["severity"]: int(row["n"])
                for row in conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
                )
            }
            by_detector = {
                row["detector"]: int(row["n"])
                for row in conn.execute(
                    "SELECT detector, COUNT(*) AS n FROM alerts GROUP BY detector"
                )
            }
            entities = int(
                conn.execute(
                    "SELECT COUNT(DISTINCT entity) FROM alerts"
                ).fetchone()[0]
            )
            latest = conn.execute("SELECT MAX(updated_at) FROM alerts").fetchone()[0]
        return {
            "total": total,
            "by_severity": by_severity,
            "by_detector": by_detector,
            "entities": entities,
            "latest_update": latest,
        }

    def last_scan_time(self) -> str | None:
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            row = conn.execute("SELECT MAX(updated_at) FROM alerts").fetchone()
        return row[0] if row else None

    def clear(self) -> int:
        with self.connection() as conn:
            conn.executescript(SCHEMA)
            cursor = conn.execute("DELETE FROM alerts")
            return int(cursor.rowcount or 0)


def _row_to_alert(row: sqlite3.Row) -> Alert:
    try:
        evidence = json.loads(row["evidence"] or "{}")
    except (ValueError, TypeError):
        evidence = {}
    return Alert(
        id=int(row["id"]),
        fingerprint=row["fingerprint"],
        detector=row["detector"],
        severity=Severity.parse(row["severity"]),
        title=row["title"],
        description=row["description"],
        entity=row["entity"],
        entity_type=row["entity_type"],
        event_count=int(row["event_count"]),
        first_seen=parse_timestamp(row["first_seen"]) or utcnow(),
        last_seen=parse_timestamp(row["last_seen"]) or utcnow(),
        evidence=evidence,
        created_at=parse_timestamp(row["created_at"]),
        updated_at=parse_timestamp(row["updated_at"]),
    )


def _merge_evidence(existing: str, new: dict[str, Any]) -> dict[str, Any]:
    try:
        data = json.loads(existing or "{}")
    except (ValueError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    for key, value in new.items():
        if key in data and isinstance(data[key], list) and isinstance(value, list):
            data[key] = sorted({*map(str, data[key]), *map(str, value)})
        else:
            data[key] = value
    return data
