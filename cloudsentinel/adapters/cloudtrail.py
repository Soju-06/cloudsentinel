"""AWS CloudTrail record adapter.

CloudTrail records appear in several real-world containers:

* an S3 object: ``{"Records": [ ... ]}``
* a CloudWatch Logs subscription payload where each ``logEvents[].message`` is
  a JSON-encoded CloudTrail record
* a bare list of records

The adapter normalises all of these shapes onto the vendor-neutral schema.
"""

from __future__ import annotations

import json
from typing import Any

_CLAIM_KEYS = (
    "bucketName",
    "bucket",
    "roleName",
    "userName",
    "groupName",
    "policyArn",
    "policyName",
    "functionName",
    "instanceId",
    "tableName",
    "secretId",
    "keyId",
    "queueUrl",
)

_MAX_DEPTH = 6


def looks_like_cloudtrail(record: Any) -> bool:
    """Heuristic: CloudTrail events always carry eventSource + eventName."""

    return (
        isinstance(record, dict)
        and "eventSource" in record
        and "eventName" in record
        and ("eventTime" in record or "awsRegion" in record)
    )


def extract_records(payload: Any) -> list[dict[str, Any]]:
    """Unwrap every supported container into a flat list of records."""

    return _extract(payload, depth=0)


def _extract(payload: Any, depth: int) -> list[dict[str, Any]]:
    if depth > _MAX_DEPTH:
        return []

    if isinstance(payload, list):
        records: list[dict[str, Any]] = []
        for item in payload:
            records.extend(_extract(item, depth + 1))
        return records

    if not isinstance(payload, dict):
        return []

    # S3-delivered CloudTrail file.
    records = payload.get("Records")
    if isinstance(records, list):
        extracted: list[dict[str, Any]] = []
        for item in records:
            extracted.extend(_extract(item, depth + 1))
        return extracted

    # CloudWatch Logs subscription payload.
    log_events = payload.get("logEvents")
    if isinstance(log_events, list):
        extracted = []
        for item in log_events:
            if isinstance(item, dict) and isinstance(item.get("message"), str):
                try:
                    message = json.loads(item["message"])
                except ValueError:
                    continue
                extracted.extend(_extract(message, depth + 1))
            else:
                extracted.extend(_extract(item, depth + 1))
        return extracted

    # A record wrapped in a "message" field.
    message = payload.get("message")
    if isinstance(message, str) and (
        '"eventSource"' in message or '"eventName"' in message
    ):
        try:
            inner = json.loads(message)
        except ValueError:
            return [payload]
        return _extract(inner, depth + 1)

    return [payload]


def map_record(record: dict[str, Any]) -> dict[str, Any]:
    """Convert one CloudTrail record to the canonical event dictionary."""

    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, dict) else {}

    user = (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or identity.get("invokedBy")
        or "unknown"
    )
    error_code = record.get("errorCode") or ""
    status = "failure" if error_code else "success"

    return {
        "event_id": record.get("eventID") or "",
        "timestamp": record.get("eventTime"),
        "event_source": record.get("eventSource") or "aws.cloudtrail",
        "event_name": record.get("eventName") or "",
        "user": str(user),
        "source_ip": record.get("sourceIPAddress") or "",
        "resource": _extract_resource(record),
        "status": status,
        "error_code": str(error_code),
        "raw": record,
    }


def _extract_resource(record: dict[str, Any]) -> str:
    params = record.get("requestParameters")
    if isinstance(params, dict):
        for key in _CLAIM_KEYS:
            value = params.get(key)
            if value not in (None, ""):
                return str(value)

    resources = record.get("resources")
    if isinstance(resources, list):
        for item in resources:
            if isinstance(item, dict) and item.get("ARN"):
                return str(item["ARN"])

    # S3 policies reference the bucket inside their ARN.
    try:
        text = json.dumps(record, default=str)
    except (TypeError, ValueError):
        return ""
    marker = "arn:aws:s3:::"
    index = text.find(marker)
    if index != -1:
        remainder = text[index + len(marker) :]
        bucket = remainder.split("/")[0].split('"')[0].split("\\")[0]
        if bucket:
            return bucket
    return ""
