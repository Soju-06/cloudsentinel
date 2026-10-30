"""Root-account usage detection.

The root user bypasses every IAM guardrail, so any activity is worth recording.
Routine root actions are HIGH; security-sensitive changes (keys, trails, IAM,
password policy) escalate to CRITICAL.
"""

from __future__ import annotations

import pandas as pd

from ..config import RootUsageConfig
from ..models import Alert
from ..severity import Severity, highest
from ._cloud import is_root, iter_records

DETECTOR = "root_usage"


def detect(
    events: pd.DataFrame, config: RootUsageConfig | None = None
) -> list[Alert]:
    """Flag every action performed by the account root user."""

    config = config or RootUsageConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"])
    users = frame["user"].fillna("").astype(str).str.lower()
    candidates = frame[users.eq("root") | users.str.endswith(":root")]
    if candidates.empty:
        return []

    critical_actions = {action.lower() for action in config.critical_actions}
    records = [
        record
        for record in iter_records(
            candidates,
            ["timestamp", "event_id", "user", "source_ip", "raw", "event_name"],
        )
        if is_root(record)
    ]
    if not records:
        return []

    severity = Severity.INFO
    actions: set[str] = set()
    source_ips: set[str] = set()
    event_ids: list[str] = []
    first_seen = records[0]["timestamp"]
    last_seen = records[0]["timestamp"]

    for event in records:
        action = str(event.get("event_name") or "unknown")
        actions.add(action)
        if action.lower() in critical_actions:
            severity = highest(severity, Severity.CRITICAL)
        else:
            severity = highest(severity, Severity.HIGH)

        ip = str(event.get("source_ip") or "").strip()
        if ip:
            source_ips.add(ip)
        first_seen = min(first_seen, event["timestamp"])
        last_seen = max(last_seen, event["timestamp"])
        if len(event_ids) < 20:
            event_ids.append(str(event.get("event_id", "")))

    ordered_actions = sorted(actions)
    description = (
        f"The root account performed {len(records)} action(s), including "
        + ", ".join(ordered_actions[:8])
        + (", ..." if len(ordered_actions) > 8 else "")
        + ". Root access bypasses IAM controls and should be rare."
    )

    return [
        Alert(
            detector=DETECTOR,
            severity=severity,
            title="Root account activity",
            description=description,
            entity="root",
            entity_type="account",
            event_count=len(records),
            first_seen=first_seen.to_pydatetime(),
            last_seen=last_seen.to_pydatetime(),
            evidence={
                "account": "root",
                "actions": ordered_actions,
                "source_ips": sorted(source_ips),
                "event_ids": event_ids,
            },
        )
    ]
