"""MFA removal detection.

Flags ``DeactivateMFADevice`` and ``DeleteVirtualMFADevice``: both remove a
second factor from an account. Self-service removal is suspicious but can be
legitimate; removing another principal's device (or touching the root user) is
treated as an active attack.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from ..config import MFAConfig
from ..models import Alert
from ..severity import Severity, highest
from ._cloud import is_root, iter_records, parameter, request_parameters

DETECTOR = "mfa_changes"

# event_name (lower-case) -> past-tense action used in findings
_REMOVAL_EVENTS = {
    "deactivatemfadevice": "disabled",
    "deletevirtualmfadevice": "deleted",
}


def detect(events: pd.DataFrame, config: MFAConfig | None = None) -> list[Alert]:
    """Flag MFA devices that were disabled or deleted."""

    config = config or MFAConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"])
    names = frame["event_name"].fillna("").astype(str).str.lower()
    frame = frame[names.isin(_REMOVAL_EVENTS)]
    if frame.empty:
        return []

    by_target: dict[str, dict[str, Any]] = {}

    for event in iter_records(
        frame, ["timestamp", "event_id", "user", "raw", "event_name"]
    ):
        action = _REMOVAL_EVENTS[str(event["event_name"]).lower()]
        params = request_parameters(event)
        actor = _text(event.get("user")) or "unknown"
        target = _text(
            parameter(params, "userName", "user_name", "targetUser", "target_user")
        ) or actor

        severity = Severity.HIGH
        if is_root(event) or target.lower() == "root" or actor.lower() != target.lower():
            severity = Severity.CRITICAL

        entry = by_target.setdefault(
            target,
            {
                "severity": Severity.INFO,
                "actions": set(),
                "actors": set(),
                "events": 0,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [],
            },
        )
        entry["severity"] = highest(entry["severity"], severity)
        entry["actions"].add(action)
        entry["actors"].add(actor)
        entry["events"] += 1
        entry["first_seen"] = min(entry["first_seen"], event["timestamp"])
        entry["last_seen"] = max(entry["last_seen"], event["timestamp"])
        if len(entry["event_ids"]) < 20:
            entry["event_ids"].append(str(event.get("event_id", "")))

    alerts: list[Alert] = []
    for target, data in by_target.items():
        actions = sorted(data["actions"])
        actors = sorted(data["actors"])
        description = (
            f"MFA device {', '.join(actions)} for user '{target}' by "
            f"{', '.join(actors)}. Removing a second factor weakens account "
            "protection and can be the first step of an account takeover."
        )
        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=data["severity"],
                title=f"MFA removed: {target}",
                description=description,
                entity=target,
                entity_type="user",
                event_count=int(data["events"]),
                first_seen=data["first_seen"].to_pydatetime(),
                last_seen=data["last_seen"].to_pydatetime(),
                evidence={
                    "target_user": target,
                    "actions": actions,
                    "actors": actors,
                    "event_ids": data["event_ids"],
                },
            )
        )
    return alerts


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""
