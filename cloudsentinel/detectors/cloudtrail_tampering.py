"""CloudTrail tampering detection.

Attackers disable or re-scope audit logging to hide their tracks. Stopping or
deleting a trail is CRITICAL; changing trail configuration or event selectors is
HIGH.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from ..config import CloudTrailConfig
from ..models import Alert
from ..severity import Severity, highest
from ._cloud import iter_records, parameter, request_parameters

DETECTOR = "cloudtrail_tampering"

# event_name (lower-case) -> (severity, past-tense description, disables logging)
_ACTIONS: dict[str, tuple[Severity, str, bool]] = {
    "stoplogging": (Severity.CRITICAL, "logging stopped", True),
    "deletetrail": (Severity.CRITICAL, "trail deleted", True),
    "deleteeventdatastore": (
        Severity.CRITICAL,
        "event data store deleted",
        True,
    ),
    "updatetrail": (Severity.HIGH, "trail updated", False),
    "puteventselectors": (Severity.HIGH, "event selectors changed", False),
    "putinsightselectors": (Severity.HIGH, "insight selectors changed", False),
    "updateeventdatastore": (
        Severity.HIGH,
        "event data store updated",
        False,
    ),
}

_TRAIL_KEYS = (
    "trailName",
    "trail_name",
    "name",
    "trailARN",
    "trail_arn",
    "eventDataStoreArn",
    "event_data_store_arn",
    "eventDataStoreId",
    "event_data_store_id",
)


def detect(
    events: pd.DataFrame, config: CloudTrailConfig | None = None
) -> list[Alert]:
    """Flag attempts to stop, delete or weaken CloudTrail logging."""

    config = config or CloudTrailConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"])
    names = frame["event_name"].fillna("").astype(str).str.lower()
    frame = frame[names.isin(_ACTIONS)]
    if frame.empty:
        return []

    by_trail: dict[str, dict[str, Any]] = {}

    for event in iter_records(
        frame, ["timestamp", "event_id", "user", "source_ip", "raw", "event_name"]
    ):
        action = str(event["event_name"]).lower()
        severity, description, disables_logging = _ACTIONS[action]
        params = request_parameters(event)
        trail = _trail_name(params)

        entry = by_trail.setdefault(
            trail,
            {
                "severity": Severity.INFO,
                "actions": set(),
                "actors": set(),
                "source_ips": set(),
                "disables_logging": False,
                "events": 0,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [],
            },
        )
        entry["severity"] = highest(entry["severity"], severity)
        entry["actions"].add(description)
        entry["actors"].add(str(event.get("user") or "unknown"))
        ip = str(event.get("source_ip") or "").strip()
        if ip:
            entry["source_ips"].add(ip)
        entry["disables_logging"] = entry["disables_logging"] or disables_logging
        entry["events"] += 1
        entry["first_seen"] = min(entry["first_seen"], event["timestamp"])
        entry["last_seen"] = max(entry["last_seen"], event["timestamp"])
        if len(entry["event_ids"]) < 20:
            entry["event_ids"].append(str(event.get("event_id", "")))

    alerts: list[Alert] = []
    for trail, data in by_trail.items():
        actions = sorted(data["actions"])
        description = (
            f"CloudTrail configuration for '{trail}' was modified: "
            + "; ".join(actions)
            + ". Weakening audit logging can hide attacker activity."
        )
        title = (
            f"CloudTrail logging disabled: {trail}"
            if data["disables_logging"]
            else f"CloudTrail configuration changed: {trail}"
        )
        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=data["severity"],
                title=title,
                description=description,
                entity=trail,
                entity_type="audit_trail",
                event_count=int(data["events"]),
                first_seen=data["first_seen"].to_pydatetime(),
                last_seen=data["last_seen"].to_pydatetime(),
                evidence={
                    "trail": trail,
                    "actions": actions,
                    "actors": sorted(data["actors"]),
                    "source_ips": sorted(data["source_ips"]),
                    "event_ids": data["event_ids"],
                },
            )
        )
    return alerts


def _trail_name(params: dict[str, Any]) -> str:
    value = parameter(params, *_TRAIL_KEYS)
    if value:
        return str(value).strip()
    return "account"
