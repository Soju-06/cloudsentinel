"""Repeated failed-login detection."""

from __future__ import annotations

from datetime import datetime, timedelta

import pandas as pd

from ..config import BruteForceConfig
from ..models import Alert
from ..severity import Severity
from ..utils import to_iso

DETECTOR = "brute_force"

FAILURE_STATES = {
    "failure",
    "failed",
    "fail",
    "error",
    "denied",
    "deny",
    "unauthorized",
    "forbidden",
    "rejected",
}
SUCCESS_STATES = {"success", "succeeded", "allowed", "allow", "ok", "accepted"}
LOGIN_HINTS = ("login", "signin", "sign-in", "consolelogin", "authenticate")


def is_login_event(event_name: object, login_events: list[str]) -> bool:
    if event_name is None:
        return False
    name = str(event_name).strip().lower()
    if not name:
        return False
    if name in {candidate.lower() for candidate in login_events}:
        return True
    return any(hint in name for hint in LOGIN_HINTS)


def detect(events: pd.DataFrame, config: BruteForceConfig | None = None) -> list[Alert]:
    """Flag repeated failed logins inside a sliding time window."""

    config = config or BruteForceConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"]).copy()
    if frame.empty:
        return []

    frame["_login"] = frame["event_name"].map(
        lambda name: is_login_event(name, config.login_events)
    )
    frame["_failed"] = frame["status"].map(
        lambda value: str(value).strip().lower() in FAILURE_STATES
    )
    frame["_succeeded"] = frame["status"].map(
        lambda value: str(value).strip().lower() in SUCCESS_STATES
    )
    frame["_user"] = (
        frame["user"].fillna("").astype(str).str.strip().replace("", "unknown")
    )
    frame["_ip"] = (
        frame["source_ip"].fillna("").astype(str).str.strip().replace("", "unknown")
    )

    failures = frame[frame["_login"] & frame["_failed"]]
    if failures.empty:
        return []

    successes = frame[frame["_login"] & frame["_succeeded"]]
    key_columns = {
        "user_ip": ["_user", "_ip"],
        "user": ["_user"],
        "ip": ["_ip"],
    }[config.group_by]

    window = timedelta(minutes=config.window_minutes)
    alerts: list[Alert] = []

    for key, group in failures.groupby(key_columns, dropna=False):
        user, ip = _unpack_key(key, config.group_by)
        group = group.sort_values("timestamp")
        times = list(group["timestamp"])
        count, start, end = _max_window(times, window)
        if count < config.threshold:
            continue

        in_window = group[
            (group["timestamp"] >= start) & (group["timestamp"] <= end)
        ]
        compromised = _has_followup_login(
            successes, user, ip, start, end, config
        )

        severity = Severity.HIGH
        if compromised or count >= config.threshold * config.critical_multiplier:
            severity = Severity.CRITICAL

        if config.group_by == "ip":
            entity, entity_type = ip, "ip"
            actor = f"IP {ip}"
        else:
            entity, entity_type = user, "user"
            actor = f"user '{user}'"
            if ip != "unknown":
                actor += f" from {ip}"

        elapsed = max(int((end - start).total_seconds() // 60), 1)
        description = (
            f"{count} failed login attempts for {actor} within {elapsed} minute(s)."
        )
        if compromised:
            description += (
                " A successful login followed the failed attempts —"
                " possible account compromise."
            )
        if count >= config.threshold * config.critical_multiplier:
            description += (
                f" Volume is at least {config.critical_multiplier}x the alert threshold."
            )

        evidence = {
            "window_start": to_iso(start),
            "window_end": to_iso(end),
            "threshold": config.threshold,
            "window_minutes": config.window_minutes,
            "source_ips": sorted(str(value) for value in in_window["_ip"].unique())[:10],
            "users": sorted(str(value) for value in in_window["_user"].unique())[:10],
            "event_ids": [str(value) for value in in_window["event_id"].head(20)],
            "success_after_failures": compromised,
        }

        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=severity,
                title=(
                    "Possible credential compromise"
                    if compromised
                    else "Repeated failed logins"
                ),
                description=description,
                entity=entity,
                entity_type=entity_type,
                event_count=int(count),
                first_seen=start.to_pydatetime(),
                last_seen=end.to_pydatetime(),
                evidence=evidence,
            )
        )

    if config.correlate_across_ips and config.group_by == "user_ip":
        alerts.extend(_correlated_alerts(failures, successes, config, alerts))

    return alerts


def _correlated_alerts(
    failures: pd.DataFrame,
    successes: pd.DataFrame,
    config: BruteForceConfig,
    existing: list[Alert],
) -> list[Alert]:
    """Catch bursts split across IPs so no single IP reaches the threshold."""

    alerts: list[Alert] = []
    window = timedelta(minutes=config.window_minutes)

    for user, group in failures.groupby("_user", dropna=False):
        user = str(user)
        group = group.sort_values("timestamp")
        count, start, end = _max_window(list(group["timestamp"]), window)
        if count < config.threshold:
            continue

        in_window = group[
            (group["timestamp"] >= start) & (group["timestamp"] <= end)
        ]
        ips = sorted(str(value) for value in in_window["_ip"].unique())
        if len(ips) < 2:
            continue

        # A single-IP alert already covers this burst; do not double-report.
        if int(in_window.groupby("_ip").size().max()) >= config.threshold:
            continue

        start_dt = start.to_pydatetime()
        end_dt = end.to_pydatetime()
        if any(
            alert.entity == user
            and alert.first_seen <= end_dt
            and alert.last_seen >= start_dt
            for alert in existing
        ):
            continue

        compromised = _has_followup_login_any_ip(
            successes, user, start, end, config
        )
        severity = Severity.HIGH
        if compromised or count >= config.threshold * config.critical_multiplier:
            severity = Severity.CRITICAL

        elapsed = max(int((end - start).total_seconds() // 60), 1)
        description = (
            f"{count} failed login attempts for user '{user}' across"
            f" {len(ips)} source IPs within {elapsed} minute(s)."
        )
        if compromised:
            description += (
                " A successful login followed the failures —"
                " possible account compromise."
            )

        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=severity,
                title="Distributed failed logins",
                description=description,
                entity=user,
                entity_type="user",
                event_count=int(count),
                first_seen=start_dt,
                last_seen=end_dt,
                evidence={
                    "window_start": to_iso(start_dt),
                    "window_end": to_iso(end_dt),
                    "source_ips": ips[:10],
                    "distinct_ips": len(ips),
                    "correlated_across_ips": True,
                    "success_after_failures": compromised,
                    "event_ids": [str(value) for value in in_window["event_id"].head(20)],
                },
            )
        )

    return alerts


def _has_followup_login_any_ip(
    successes: pd.DataFrame,
    user: str,
    start: pd.Timestamp,
    end: pd.Timestamp,
    config: BruteForceConfig,
) -> bool:
    if not config.detect_compromise or successes.empty:
        return False
    cutoff = end + timedelta(minutes=config.compromise_window_minutes)
    candidates = successes[
        (successes["_user"] == user)
        & (successes["timestamp"] >= start)
        & (successes["timestamp"] <= cutoff)
    ]
    return not candidates.empty


def _max_window(
    times: list[pd.Timestamp], window: timedelta
) -> tuple[int, pd.Timestamp, pd.Timestamp]:
    """Largest number of events inside any window of *window* duration."""

    left = 0
    best_count = 0
    best_start = times[0]
    best_end = times[0]

    for right, current in enumerate(times):
        while current - times[left] > window:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start = times[left]
            best_end = current

    return best_count, best_start, best_end


def _has_followup_login(
    successes: pd.DataFrame,
    user: str,
    ip: str,
    start: datetime,
    end: datetime,
    config: BruteForceConfig,
) -> bool:
    if not config.detect_compromise or successes.empty:
        return False

    cutoff = end + timedelta(minutes=config.compromise_window_minutes)
    candidates = successes[
        (successes["_user"] == user)
        & (successes["timestamp"] >= start)
        & (successes["timestamp"] <= cutoff)
    ]
    if config.group_by == "user_ip":
        candidates = candidates[candidates["_ip"] == ip]
    return not candidates.empty


def _unpack_key(key: object, group_by: str) -> tuple[str, str]:
    if isinstance(key, tuple):
        if group_by == "user_ip":
            return str(key[0]), str(key[1])
        key = key[0] if key else "unknown"

    value = str(key)
    return (value, "unknown") if group_by == "user" else ("unknown", value)
