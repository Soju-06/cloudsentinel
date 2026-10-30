"""IAM access-key creation detection.

Long-lived access keys are a common persistence mechanism: an attacker creates
one after compromising an account and uses it after the password is rotated.
Severity reflects who created the key for whom.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from ..config import AccessKeyConfig
from ..models import Alert
from ..severity import Severity, highest
from ._cloud import (
    is_root,
    iter_records,
    parameter,
    request_parameters,
    response_elements,
)

DETECTOR = "access_key_creation"


def detect(
    events: pd.DataFrame, config: AccessKeyConfig | None = None
) -> list[Alert]:
    """Flag ``CreateAccessKey`` calls, grouped by the target identity."""

    config = config or AccessKeyConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"])
    names = frame["event_name"].fillna("").astype(str).str.lower()
    frame = frame[names.eq("createaccesskey")]
    if frame.empty:
        return []

    by_target: dict[str, dict[str, Any]] = {}

    for event in iter_records(
        frame, ["timestamp", "event_id", "user", "raw", "event_name"]
    ):
        params = request_parameters(event)
        actor = str(event.get("user") or "unknown").strip() or "unknown"
        target = _text(
            parameter(params, "userName", "user_name", "targetUser", "target_user")
        ) or actor

        if is_root(event) or actor.lower() == "root":
            severity = Severity.CRITICAL
        elif target.lower() != actor.lower():
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        entry = by_target.setdefault(
            target,
            {
                "severity": Severity.INFO,
                "actors": set(),
                "key_ids": set(),
                "events": 0,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [],
            },
        )
        entry["severity"] = highest(entry["severity"], severity)
        entry["actors"].add(actor)

        elements = response_elements(event)
        access_key = elements.get("accessKey")
        key_id = None
        if isinstance(access_key, dict):
            key_id = _text(access_key.get("accessKeyId"))
        key_id = key_id or _text(parameter(params, "accessKeyId", "access_key_id"))
        if key_id:
            entry["key_ids"].add(key_id)

        entry["events"] += 1
        entry["first_seen"] = min(entry["first_seen"], event["timestamp"])
        entry["last_seen"] = max(entry["last_seen"], event["timestamp"])
        if len(entry["event_ids"]) < 20:
            entry["event_ids"].append(str(event.get("event_id", "")))

    alerts: list[Alert] = []
    for target, data in by_target.items():
        actors = sorted(data["actors"])
        key_ids = sorted(data["key_ids"])
        description = (
            f"Access key created for '{target}' by {', '.join(actors)}. "
            "Long-lived keys survive password resets and are frequently used "
            "for persistence."
        )
        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=data["severity"],
                title=f"Access key created: {target}",
                description=description,
                entity=target,
                entity_type="user",
                event_count=int(data["events"]),
                first_seen=data["first_seen"].to_pydatetime(),
                last_seen=data["last_seen"].to_pydatetime(),
                evidence={
                    "target_user": target,
                    "actors": actors,
                    "access_key_ids": key_ids,
                    "event_ids": data["event_ids"],
                },
            )
        )
    return alerts


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""
