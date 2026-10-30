"""Internet-exposed security-group detection.

Flags ingress rules that allow ``0.0.0.0/0`` or ``::/0``. Administrative or
database ports (SSH, RDP, SQL, Redis, ...) and all-port rules are CRITICAL;
other exposed ports are HIGH.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from ..config import SecurityGroupConfig
from ..models import Alert
from ..severity import Severity, highest
from ._cloud import items, iter_records, parameter, request_parameters

DETECTOR = "security_group_open"

_INGRESS_EVENTS = {"authorizesecuritygroupingress"}
_PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def detect(
    events: pd.DataFrame, config: SecurityGroupConfig | None = None
) -> list[Alert]:
    """Flag ingress rules open to the whole internet."""

    config = config or SecurityGroupConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"])
    names = frame["event_name"].fillna("").astype(str).str.lower()
    frame = frame[names.isin(_INGRESS_EVENTS)]
    if frame.empty:
        return []

    by_group: dict[str, dict[str, Any]] = {}

    for event in iter_records(
        frame, ["timestamp", "event_id", "user", "resource", "raw", "event_name"]
    ):
        params = request_parameters(event)
        rules = _public_rules(params, config.sensitive_ports)
        if not rules:
            continue

        group = _group_id(event, params)
        entry = by_group.setdefault(
            group,
            {
                "severity": Severity.INFO,
                "rules": set(),
                "actors": set(),
                "events": 0,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [],
            },
        )
        for rule in rules:
            entry["severity"] = highest(entry["severity"], rule["severity"])
            entry["rules"].add(rule["description"])
        entry["actors"].add(str(event.get("user") or "unknown"))
        entry["events"] += 1
        entry["first_seen"] = min(entry["first_seen"], event["timestamp"])
        entry["last_seen"] = max(entry["last_seen"], event["timestamp"])
        if len(entry["event_ids"]) < 20:
            entry["event_ids"].append(str(event.get("event_id", "")))

    alerts: list[Alert] = []
    for group, data in by_group.items():
        findings = sorted(data["rules"])
        description = (
            f"Security group '{group}' allows inbound traffic from the "
            "internet: " + "; ".join(findings) + "."
        )
        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=data["severity"],
                title=f"Security group open to the internet: {group}",
                description=description,
                entity=group,
                entity_type="security_group",
                event_count=int(data["events"]),
                first_seen=data["first_seen"].to_pydatetime(),
                last_seen=data["last_seen"].to_pydatetime(),
                evidence={
                    "group_id": group,
                    "open_rules": findings,
                    "actors": sorted(data["actors"]),
                    "event_ids": data["event_ids"],
                },
            )
        )
    return alerts


def _public_rules(
    params: dict[str, Any], sensitive_ports: list[int]
) -> list[dict[str, Any]]:
    """Return one entry per internet-facing ingress rule."""

    permissions = items(parameter(params, "ipPermissions", "ip_permissions"))
    if not permissions:
        permissions = [params]

    sensitive = set(sensitive_ports)
    rules: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None, int | None]] = set()

    for permission in permissions:
        if not isinstance(permission, dict):
            continue

        protocol = str(
            parameter(permission, "ipProtocol", "ip_protocol", "protocol") or "-1"
        ).lower()
        from_port = _port(parameter(permission, "fromPort", "from_port", "port"))
        to_port = _port(parameter(permission, "toPort", "to_port", "port", "toPort"))
        if from_port is None and to_port is None and protocol in {"-1", "all"}:
            from_port, to_port = 0, 65535

        cidrs = _cidrs(permission)
        if not cidrs:
            continue

        all_traffic = protocol in {"-1", "all"} or (
            from_port == 0 and to_port == 65535
        )
        touches_sensitive = _touches_sensitive(from_port, to_port, sensitive)

        for cidr in cidrs:
            if cidr not in _PUBLIC_CIDRS:
                continue
            key = (cidr, protocol, from_port, to_port)
            if key in seen:
                continue
            seen.add(key)

            severity = (
                Severity.CRITICAL if all_traffic or touches_sensitive else Severity.HIGH
            )
            rules.append(
                {
                    "severity": severity,
                    "description": (
                        f"{_port_label(protocol, from_port, to_port)} open to {cidr}"
                    ),
                }
            )
    return rules


def _cidrs(permission: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for key in ("ipRanges", "ipv6Ranges", "ip_ranges", "ipv6_ranges"):
        for entry in items(permission.get(key)):
            found.extend(_cidr_values(entry))

    if not found:
        found.extend(_cidr_values(permission))
    return found


def _cidr_values(entry: Any) -> list[str]:
    if isinstance(entry, str):
        return [entry.strip().lower()]
    if not isinstance(entry, dict):
        return []

    values: list[str] = []
    lowered = {str(key).lower(): value for key, value in entry.items()}
    for key in (
        "cidrip",
        "cidr_ip",
        "cidripv6",
        "cidr_ipv6",
        "cidr",
        "cidrblock",
        "cidr_block",
        "ip",
        "range",
        "sourceip",
        "source_ip",
        "iprange",
        "ip_range",
    ):
        value = lowered.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip().lower())
    return values


def _touches_sensitive(
    from_port: int | None, to_port: int | None, sensitive: set[int]
) -> bool:
    if from_port is None and to_port is None:
        return False
    low = 0 if from_port is None else from_port
    high = low if to_port is None else to_port
    return any(low <= port <= high for port in sensitive)


def _port(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _port_label(protocol: str, from_port: int | None, to_port: int | None) -> str:
    if protocol in {"-1", "all"} or (from_port == 0 and to_port == 65535):
        return "all traffic"
    if from_port is None and to_port is None:
        return f"{protocol} traffic"
    if from_port == to_port or to_port is None:
        return f"{protocol}/{from_port}"
    return f"{protocol}/{from_port}-{to_port}"


def _group_id(event: dict[str, Any], params: dict[str, Any]) -> str:
    group = parameter(
        params,
        "groupId",
        "group_id",
        "groupName",
        "group_name",
        "securityGroupId",
        "security_group_id",
    )
    if group:
        return str(group).strip()
    resource = str(event.get("resource") or "").strip()
    return resource or "unknown-security-group"
