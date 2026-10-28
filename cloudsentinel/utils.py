"""Small helpers shared across ingestion and detectors."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import unquote


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(value: datetime | str | None) -> str:
    """Serialise a datetime as a sortable UTC ISO-8601 string."""

    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return isinstance(value, str) and not value.strip()


def parse_timestamp(value: Any) -> datetime | None:
    """Best-effort parse of ISO strings and epoch numbers into aware UTC datetimes."""

    if is_blank(value):
        return None

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, (int, float)):
        # Heuristic: > 10^11 means milliseconds, otherwise seconds.
        seconds = float(value) / (1000.0 if float(value) > 1e11 else 1.0)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def walk_json(obj: Any, path: str = "root") -> Iterator[tuple[str, Any]]:
    """Yield ``(dotted_path, node)`` for every value in a nested JSON structure."""

    yield path, obj
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from walk_json(value, f"{path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            yield from walk_json(value, f"{path}[{index}]")


def maybe_decode_json(value: Any) -> Any:
    """Return parsed JSON when *value* is a JSON/URL-encoded JSON string."""

    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return value
    if "%" in text:
        text = unquote(text)
    stripped = text.lstrip()
    if stripped[:1] in "{[":
        try:
            return json.loads(stripped)
        except (ValueError, TypeError):
            return value
    return value


def json_dumps(value: Any, **kwargs: Any) -> str:
    kwargs.setdefault("default", str)
    kwargs.setdefault("sort_keys", True)
    return json.dumps(value, **kwargs)


def truncate(text: str, limit: int = 160) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
