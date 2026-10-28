"""Public cloud-storage exposure detection."""

from __future__ import annotations

import json
import re
from typing import Any

import pandas as pd

from ..config import PublicStorageConfig
from ..models import Alert
from ..severity import Severity, highest
from ..utils import is_blank
from ._policies import (
    as_statements,
    principal_is_public,
    scan_policy_documents,
    statement_has_wildcard_action,
    statement_is_allow,
)

DETECTOR = "public_storage"

_PUBLIC_FLAGS = {
    "public",
    "ispublic",
    "is_public",
    "publiclyaccessible",
    "publicly_accessible",
    "publicaccess",
    "public_access",
}

_ACL_KEYS = frozenset({"acl", "grant", "grants", "cannedacl", "x-amz-acl"})


def detect(
    events: pd.DataFrame, config: PublicStorageConfig | None = None
) -> list[Alert]:
    """Flag storage events that expose buckets/objects to the public."""

    config = config or PublicStorageConfig()
    if not config.enabled or events is None or events.empty:
        return []

    frame = events.dropna(subset=["timestamp"]).copy()
    frame = _storage_candidates(frame, config)
    if frame.empty:
        return []

    findings_by_resource: dict[str, dict[str, Any]] = {}

    # ``to_dict("records")`` is several times faster than ``iterrows`` and
    # avoids constructing a Series per event on large scans.
    columns = ["event_source", "event_name", "timestamp", "event_id", "resource", "raw"]
    for event in frame[columns].to_dict("records"):
        analysis = _analyze_event(event, config)
        if analysis is None:
            continue

        severity, findings = analysis
        resource = _extract_resource(event)
        bucket = findings_by_resource.setdefault(
            resource,
            {
                "severity": Severity.INFO,
                "findings": set(),
                "events": 0,
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_ids": [],
            },
        )
        bucket["severity"] = highest(bucket["severity"], severity)
        bucket["findings"].update(findings)
        bucket["events"] += 1
        bucket["first_seen"] = min(bucket["first_seen"], event["timestamp"])
        bucket["last_seen"] = max(bucket["last_seen"], event["timestamp"])
        if len(bucket["event_ids"]) < 20:
            bucket["event_ids"].append(str(event.get("event_id", "")))

    alerts: list[Alert] = []
    for resource, data in findings_by_resource.items():
        findings = sorted(data["findings"])
        description = (
            f"Storage resource '{resource}' is potentially public: "
            + "; ".join(findings)
            + "."
        )
        alerts.append(
            Alert(
                detector=DETECTOR,
                severity=data["severity"],
                title=f"Publicly accessible storage: {resource}",
                description=description,
                entity=resource,
                entity_type="storage",
                event_count=int(data["events"]),
                first_seen=data["first_seen"].to_pydatetime(),
                last_seen=data["last_seen"].to_pydatetime(),
                evidence={
                    "resource": resource,
                    "indicators": findings,
                    "event_ids": data["event_ids"],
                },
            )
        )
    return alerts


def _storage_candidates(
    frame: pd.DataFrame, config: PublicStorageConfig
) -> pd.DataFrame:
    """Cheap vectorised pre-filter before the recursive policy analysis."""

    hints = [hint.lower() for hint in config.storage_hints if hint]
    if not hints:
        return frame
    pattern = "|".join(re.escape(hint) for hint in hints)
    source = frame["event_source"].fillna("").astype(str).str.lower()
    name = frame["event_name"].fillna("").astype(str).str.lower()
    mask = source.str.contains(pattern, regex=True) | name.str.contains(
        pattern, regex=True
    )
    return frame[mask]


def _analyze_event(
    event: dict[str, Any], config: PublicStorageConfig
) -> tuple[Severity, list[str]] | None:
    raw = event.get("raw")
    if not isinstance(raw, dict):
        raw = {}

    storage_related = _looks_like_storage(event, config)
    documents, explicit_public = scan_policy_documents(raw, _PUBLIC_FLAGS)
    if not storage_related and not explicit_public:
        return None

    severity = Severity.INFO
    findings: list[str] = []

    # 1. Bucket/object policy documents granting a wildcard principal.
    for document in documents:
        for statement in as_statements(document):
            if not statement_is_allow(statement):
                continue
            if not principal_is_public(statement.get("Principal")):
                continue
            if statement_has_wildcard_action(statement):
                severity = highest(severity, Severity.CRITICAL)
                findings.append(
                    "bucket policy grants Principal '*' all actions (Action '*')"
                )
            else:
                severity = highest(severity, Severity.HIGH)
                findings.append("bucket policy grants access to Principal '*'")
            break

    # 2. Public canned ACLs / group grants.
    text = _flatten(raw)

    critical_token = _first_token(text, config.critical_acl_tokens)
    public_token = _first_token(text, config.public_acl_tokens)
    authenticated_token = _first_token(text, config.authenticated_acl_tokens)

    if critical_token:
        severity = highest(severity, Severity.CRITICAL)
        findings.append(f"ACL allows public read/write ({critical_token})")
    elif public_token:
        severity = highest(severity, Severity.HIGH)
        findings.append(f"ACL allows public access ({public_token})")
    elif authenticated_token:
        severity = highest(severity, Severity.MEDIUM)
        findings.append(
            f"ACL allows any authenticated cloud user ({authenticated_token})"
        )

    # 3. Vendor-neutral explicit flags (e.g. "public": true).
    if explicit_public:
        severity = highest(severity, Severity.HIGH)
        findings.append("event marks the resource as publicly accessible")

    if severity == Severity.INFO:
        return None
    return severity, findings


def _looks_like_storage(event: dict[str, Any], config: PublicStorageConfig) -> bool:
    text = (
        f"{event.get('event_source', '')} {event.get('event_name', '')}"
    ).lower()
    return any(hint.lower() in text for hint in config.storage_hints)


def _flatten(raw: dict[str, Any]) -> str:
    try:
        text = json.dumps(raw, default=str)
    except (TypeError, ValueError):
        text = str(raw)
    # URL-unquote once so CloudTrail's percent-encoded policies are searchable.
    from urllib.parse import unquote

    return unquote(text).lower()


def _first_token(text: str, tokens: list[str]) -> str | None:
    for token in tokens:
        if token and token.lower() in text:
            return token
    return None


def _extract_resource(event: dict[str, Any]) -> str:
    resource = event.get("resource")
    if not is_blank(resource):
        return str(resource)

    raw = event.get("raw")
    if isinstance(raw, dict):
        params = raw.get("requestParameters") or raw.get("request_parameters")
        if isinstance(params, dict):
            for key in ("bucketName", "bucket", "container", "blobName", "objectKey"):
                if not is_blank(params.get(key)):
                    return str(params[key])
        try:
            text = json.dumps(raw, default=str)
        except (TypeError, ValueError):
            text = ""
        match = re.search(r"arn:aws:s3:::([A-Za-z0-9._-]+)", text)
        if match:
            return match.group(1)

    return "unknown-storage"
