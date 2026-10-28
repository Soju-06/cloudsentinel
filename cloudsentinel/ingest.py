"""Raw audit-log ingestion.

Raw events stay file-based (``data/raw``) and are normalised into a canonical
Pandas DataFrame consumed by the detectors. Supported inputs:

* JSON arrays of generic events, JSON Lines, and CSV exports
* AWS CloudTrail ``{"Records": [...]}`` dumps

Canonical columns
-----------------
``event_id, timestamp, event_source, event_name, user, source_ip, resource,
status, error_code, raw``
"""

from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path
from typing import Any, Iterable, Sequence

import pandas as pd

from .adapters.cloudtrail import (
    extract_records,
    looks_like_cloudtrail,
    map_record,
)
from .paths import RAW_DIR, SUPPORTED_SUFFIXES
from .utils import is_blank, maybe_decode_json, parse_timestamp

logger = logging.getLogger(__name__)

EVENT_COLUMNS = [
    "event_id",
    "timestamp",
    "event_source",
    "event_name",
    "user",
    "source_ip",
    "resource",
    "status",
    "error_code",
    "raw",
]

_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp",
        "time",
        "datetime",
        "eventtime",
        "event_time",
        "@timestamp",
        "ts",
        "occurred_at",
    ),
    "event_source": (
        "event_source",
        "eventsource",
        "source",
        "service",
        "provider",
        "event_type",
    ),
    "event_name": (
        "event_name",
        "eventname",
        "action",
        "operation",
        "event",
        "activity",
    ),
    "user": (
        "user",
        "username",
        "user_name",
        "actor",
        "principal",
        "identity",
        "email",
    ),
    "source_ip": (
        "source_ip",
        "sourceip",
        "source_ip_address",
        "ip",
        "ip_address",
        "src_ip",
        "client_ip",
    ),
    "resource": (
        "resource",
        "resource_name",
        "target",
        "object",
        "bucket",
        "asset",
    ),
    "status": ("status", "result", "outcome", "state"),
    "error_code": ("error_code", "errorcode", "error", "reason"),
}

_FAILURE_STATES = {
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
_SUCCESS_STATES = {"success", "succeeded", "allowed", "allow", "ok", "accepted"}


def normalize_status(value: Any) -> str | None:
    """Map arbitrary status strings onto ``success`` / ``failure``."""

    if is_blank(value):
        return None
    if isinstance(value, bool):
        return "success" if value else "failure"
    text = str(value).strip().lower()
    if text in _FAILURE_STATES:
        return "failure"
    if text in _SUCCESS_STATES:
        return "success"
    return text


def records_to_dataframe(records: Iterable[Any]) -> pd.DataFrame:
    """Normalise a list of raw records into the canonical DataFrame."""

    rows: list[dict[str, Any]] = []
    dropped = 0
    duplicates = 0
    seen_ids: set[str] = set()

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            dropped += 1
            continue

        row = (
            map_record(record)
            if looks_like_cloudtrail(record)
            else _normalize_generic(record)
        )

        timestamp = parse_timestamp(row.get("timestamp"))
        if timestamp is None:
            dropped += 1
            continue

        event_id = row.get("event_id")
        if event_id:
            key = str(event_id)
            if key in seen_ids:
                duplicates += 1
                continue
            seen_ids.add(key)

        row["timestamp"] = timestamp
        row["event_id"] = event_id or f"evt-{index + 1:05d}"
        row["raw"] = record
        rows.append(row)

    if dropped:
        logger.warning("Dropped %d record(s) without a valid timestamp", dropped)
    if duplicates:
        logger.warning("Skipped %d duplicate record(s) by event ID", duplicates)

    if not rows:
        frame = pd.DataFrame(columns=EVENT_COLUMNS)
        frame.attrs["dropped"] = dropped
        frame.attrs["duplicates"] = duplicates
        return frame

    frame = pd.DataFrame(rows, columns=EVENT_COLUMNS)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    frame = frame.sort_values("timestamp").reset_index(drop=True)
    frame.attrs["dropped"] = dropped
    frame.attrs["duplicates"] = duplicates
    return frame


def load_events(source: str | Path | Sequence[str | Path] | None = None) -> pd.DataFrame:
    """Load events from a file, directory, or sequence of paths."""

    paths = _expand_paths(source)
    all_records: list[Any] = []
    files: list[str] = []

    for path in paths:
        records = read_records(path)
        if records:
            files.append(str(path))
            all_records.extend(records)

    frame = records_to_dataframe(all_records)
    frame.attrs["files"] = files
    return frame


def read_records(path: str | Path) -> list[Any]:
    """Read raw records from one JSON, JSONL, CSV or gzip file."""

    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return _read_csv(path)

    text = _read_text(path)

    if suffix in (".jsonl", ".ndjson"):
        return _records_from_jsonl_text(text, path)

    try:
        payload = json.loads(text or "null")
    except ValueError:
        # A .gz file may contain newline-delimited JSON; try that before giving up.
        return _records_from_jsonl_text(text, path)
    return extract_records(payload)


def _read_text(path: Path) -> str:
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8")


def _records_from_jsonl_text(text: str, path: Path) -> list[Any]:
    records: list[Any] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except ValueError as exc:
            logger.warning("%s:%d skipped (%s)", path, line_number, exc)
            continue
        records.extend(extract_records(payload))
    return records


def _read_csv(path: Path) -> list[Any]:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    return frame.to_dict(orient="records")


def _expand_paths(
    source: str | Path | Sequence[str | Path] | None,
) -> list[Path]:
    if source is None:
        source = RAW_DIR
    if isinstance(source, (str, Path)):
        source = [source]

    resolved: list[Path] = []
    for item in source:
        path = Path(item)
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                    resolved.append(candidate)
        elif path.is_file():
            resolved.append(path)
        else:
            logger.warning("Input path not found: %s", path)
    return resolved


def _normalize_generic(record: dict[str, Any]) -> dict[str, Any]:
    # Lower-case the keys once instead of once per alias lookup.
    flat = {str(key).lower(): value for key, value in record.items()}

    user = _pick(flat, _ALIASES["user"])
    if is_blank(user):
        identity = record.get("userIdentity")
        if isinstance(identity, dict):
            user = (
                identity.get("userName")
                or identity.get("arn")
                or identity.get("principalId")
            )

    error_code = _pick(flat, _ALIASES["error_code"])
    status = normalize_status(_pick(flat, _ALIASES["status"]))
    if status is None:
        status = "failure" if not is_blank(error_code) else "success"

    resource = _pick(flat, _ALIASES["resource"])
    if is_blank(resource):
        params = record.get("request_parameters") or record.get("requestParameters")
        if isinstance(params, dict):
            for key in ("bucketName", "bucket", "container", "blob", "object"):
                if not is_blank(params.get(key)):
                    resource = params[key]
                    break

    return {
        "event_id": _pick(flat, ("event_id", "eventid", "id")),
        "timestamp": _pick(flat, _ALIASES["timestamp"]),
        "event_source": _pick(flat, _ALIASES["event_source"]) or "generic",
        "event_name": _pick(flat, _ALIASES["event_name"]) or "",
        "user": str(user) if not is_blank(user) else "unknown",
        "source_ip": _pick(flat, _ALIASES["source_ip"]) or "",
        "resource": str(resource) if not is_blank(resource) else "",
        "status": status,
        "error_code": "" if is_blank(error_code) else str(error_code),
        "raw": record,
    }


def _pick(flat: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in flat and not is_blank(flat[name]):
            value = flat[name]
            return maybe_decode_json(value) if name == "identity" else value
    return None
