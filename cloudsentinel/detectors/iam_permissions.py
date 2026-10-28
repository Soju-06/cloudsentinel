"""Excessive IAM permission detection."""

from __future__ import annotations

import re
from typing import Any

import pandas as pd

from ..config import IAMConfig
from ..models import Alert
from ..severity import Severity, highest
from ..utils import is_blank, walk_json
from ._policies import (
    as_statements,
    iter_policy_documents,
    statement_has_wildcard_action,
    statement_has_wildcard_resource,
    statement_is_allow,
)

DETECTOR = "iam_permissions"

_PRINCIPAL_KEYS = ("roleName", "userName", "groupName")

_IAM_EVENT_NAMES = {
    "attachuserpolicy",
    "detachuserpolicy",
    "attachrolepolicy",
    "detachrolepolicy",
    "attachgrouppolicy",
    "putuserpolicy",
    "putrolepolicy",
    "putgrouppolicy",
    "createpolicy",
    "createpolicyversion",
    "setdefaultpolicyversion",
    "createuser",
    "createrole",
    "createaccesskey",
    "updateassumerolepolicy",
}

# Cheap name-level hints that avoid walking policy trees for read-only IAM
# traffic such as GetUser/ListRoles on large scans.
_PERMISSION_NAME_HINTS = (
    "policy",
    "attach",
    "detach",
    "grant",
    "permission",
    "accesskey",
    "assumerole",
)


def detect(events: pd.DataFrame, config: IAMConfig | None = None) -> list[Alert]:
    """Flag policies that grant wildcard actions/resources or full admin."""

    config = config or IAMConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"]).copy()
    frame = _iam_candidates(frame)
    if frame.empty:
        return []

    by_principal: dict[str, dict[str, Any]] = {}

    columns = ["timestamp", "event_id", "user", "resource", "event_source", "event_name", "raw"]
    for event in frame[columns].to_dict("records"):
        analysis = _analyze_event(event, config)
        if analysis is None:
            continue

        severity, findings = analysis
        principal = _principal_target(event)
        entry = by_principal.setdefault(
            principal,
            {
                "severity": Severity.INFO,
                "findings": set(),
                "events": 0,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [],
            },
        )
        entry["severity"] = highest(entry["severity"], severity)
        entry["findings"].update(findings)
        entry["events"] += 1
        entry["first_seen"] = min(entry["first_seen"], event["timestamp"])
        entry["last_seen"] = max(entry["last_seen"], event["timestamp"])
        if len(entry["event_ids"]) < 20:
            entry["event_ids"].append(str(event.get("event_id", "")))

    alerts: list[Alert] = []
    for principal, data in by_principal.items():
        findings = sorted(data["findings"])
        description = (
            f"Principal '{principal}' has excessive IAM permissions: "
            + "; ".join(findings)
            + "."
        )
        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=data["severity"],
                title=f"Excessive IAM permissions: {principal}",
                description=description,
                entity=principal,
                entity_type="iam_principal",
                event_count=int(data["events"]),
                first_seen=data["first_seen"].to_pydatetime(),
                last_seen=data["last_seen"].to_pydatetime(),
                evidence={
                    "principal": principal,
                    "findings": findings,
                    "event_ids": data["event_ids"],
                },
            )
        )
    return alerts


def _analyze_event(
    event: dict[str, Any], config: IAMConfig
) -> tuple[Severity, list[str]] | None:
    raw = event.get("raw")
    if not isinstance(raw, dict):
        raw = {}
    if not _looks_like_iam(event):
        return None

    documents = iter_policy_documents(raw) if config.scan_inline_policies else []
    admin_references = _admin_policy_references(raw, config.admin_policy_hints)
    if not documents and not admin_references:
        return None

    severity = Severity.INFO
    findings: set[str] = set()

    for document in documents:
        for statement in as_statements(document):
            if not statement_is_allow(statement):
                continue
            wildcard_action = statement_has_wildcard_action(statement)
            wildcard_resource = statement_has_wildcard_resource(statement)

            if wildcard_action and wildcard_resource:
                severity = highest(severity, Severity.CRITICAL)
                findings.add(
                    "allows all actions on all resources (Action '*', Resource '*')"
                )
            elif wildcard_action:
                severity = highest(severity, Severity.HIGH)
                findings.add("allows all actions (Action '*')")
            elif wildcard_resource:
                severity = highest(severity, Severity.MEDIUM)
                findings.add("applies to all resources (Resource '*')")

    if admin_references:
        severity = highest(severity, Severity.HIGH)
        for reference in sorted(admin_references):
            findings.add(f"grants managed administrative policy '{reference}'")

    if severity == Severity.INFO or not findings:
        return None
    return severity, sorted(findings)


def _admin_policy_references(raw: dict[str, Any], hints: list[str]) -> set[str]:
    references: set[str] = set()
    lowered_hints = [hint.lower() for hint in hints if hint]

    for path, node in walk_json(raw):
        if not isinstance(node, str):
            continue
        key = path.rsplit(".", 1)[-1].lower()
        if "policyarn" not in key and key not in {
            "arn",
            "policy",
            "policyname",
            "policy_name",
        }:
            continue
        lowered = node.lower()
        if any(hint in lowered for hint in lowered_hints):
            references.add(node)
    return references


def _iam_candidates(frame: pd.DataFrame) -> pd.DataFrame:
    """Only IAM-related events can contain IAM permission grants."""

    name = frame["event_name"].fillna("").astype(str).str.lower()
    hints = "|".join(
        re.escape(hint) for hint in _PERMISSION_NAME_HINTS
    )
    mask = name.isin(_IAM_EVENT_NAMES) | name.str.contains(hints, regex=True)
    return frame[mask]


def _looks_like_iam(event: dict[str, Any]) -> bool:
    source = str(event.get("event_source", "")).lower()
    name = str(event.get("event_name", "")).lower()
    return "iam" in source or name in _IAM_EVENT_NAMES


def _principal_target(event: dict[str, Any]) -> str:
    raw = event.get("raw")
    if isinstance(raw, dict):
        params = raw.get("requestParameters") or raw.get("request_parameters")
        if isinstance(params, dict):
            for key in _PRINCIPAL_KEYS:
                value = params.get(key)
                if not is_blank(value):
                    return str(value)

    user = event.get("user")
    if not is_blank(user) and str(user).lower() != "unknown":
        return str(user)

    resource = event.get("resource")
    if not is_blank(resource):
        return str(resource)
    return "unknown-principal"
