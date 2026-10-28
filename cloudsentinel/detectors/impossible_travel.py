"""Impossible-travel detection based on login geolocation."""

from __future__ import annotations

from datetime import datetime

import pandas as pd

from ..config import ImpossibleTravelConfig
from ..geoip import GeoIPService, Location, haversine_km
from ..models import Alert
from ..severity import Severity
from ..utils import to_iso, truncate
from .brute_force import is_login_event

DETECTOR = "impossible_travel"

_SUCCESS_STATES = {"success", "succeeded", "allowed", "allow", "ok", "accepted"}


def detect(
    events: pd.DataFrame, config: ImpossibleTravelConfig | None = None
) -> list[Alert]:
    """Compare consecutive successful logins for physically impossible moves."""

    config = config or ImpossibleTravelConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"]).copy()
    if frame.empty:
        return []

    login = frame["event_name"].map(
        lambda name: is_login_event(name, config.login_events)
    )
    succeeded = frame["status"].map(
        lambda value: str(value).strip().lower() in _SUCCESS_STATES
    )
    logins = frame[login & succeeded]
    if logins.empty:
        return []

    service = GeoIPService(config.geoip)
    alerts: list[Alert] = []

    for user, group in logins.groupby("user", dropna=False):
        if str(user).strip().lower() in {"", "unknown", "nan"}:
            continue

        located: list[tuple[datetime, Location, str, str]] = []
        for _, event in group.sort_values("timestamp").iterrows():
            record = event.get("raw")
            location = service.locate(
                event.get("source_ip"), record if isinstance(record, dict) else None
            )
            if location is None:
                continue
            located.append(
                (
                    event["timestamp"].to_pydatetime(),
                    location,
                    str(event.get("source_ip") or ""),
                    str(event.get("event_id") or ""),
                )
            )

        for previous, current in zip(located, located[1:]):
            alert = _evaluate(user, previous, current, config)
            if alert is not None:
                alerts.append(alert)

    return alerts


def _evaluate(
    user: object,
    previous: tuple[datetime, Location, str, str],
    current: tuple[datetime, Location, str, str],
    config: ImpossibleTravelConfig,
) -> Alert | None:
    previous_time, previous_location, previous_ip, previous_id = previous
    current_time, current_location, current_ip, current_id = current

    distance = haversine_km(previous_location, current_location)
    hours = (current_time - previous_time).total_seconds() / 3600.0

    if distance < config.min_distance_km:
        return None
    if hours > config.max_travel_hours:
        return None

    severity = Severity.HIGH
    if (
        distance >= config.critical_distance_km
        and hours <= config.critical_travel_hours
    ):
        severity = Severity.CRITICAL

    speed = distance / max(hours, 0.001)
    description = (
        f"User '{user}' authenticated from {previous_location.label} "
        f"({truncate(previous_ip or 'unknown IP', 40)}) and then from "
        f"{current_location.label} ({truncate(current_ip or 'unknown IP', 40)}) "
        f"— {distance:,.0f} km apart within {hours:.1f} hour(s) "
        f"(≈{speed:,.0f} km/h)."
    )

    return Alert(
        detector=DETECTOR,
        severity=severity,
        title=f"Impossible travel: {user}",
        description=description,
        entity=str(user),
        entity_type="user",
        event_count=2,
        first_seen=previous_time,
        last_seen=current_time,
        evidence={
            "from": {
                "ip": previous_ip,
                "country": previous_location.country,
                "city": previous_location.city,
                "latitude": previous_location.latitude,
                "longitude": previous_location.longitude,
                "timestamp": to_iso(previous_time),
                "event_id": previous_id,
            },
            "to": {
                "ip": current_ip,
                "country": current_location.country,
                "city": current_location.city,
                "latitude": current_location.latitude,
                "longitude": current_location.longitude,
                "timestamp": to_iso(current_time),
                "event_id": current_id,
            },
            "distance_km": round(distance, 1),
            "elapsed_hours": round(hours, 2),
            "implied_speed_kmh": round(speed, 1),
            "backend": config.geoip.backend,
        },
    )
