"""Helpers shared by the AWS control-plane detectors.

CloudTrail records arrive as ``raw`` dictionaries, while generic JSON logs use
snake_case keys. These helpers accept both spellings so a detector never has to
care which ingestion path produced the event.
"""

from __future__ import annotations

from typing import Any, Iterator

from ..utils import is_blank


def raw_record(event: dict[str, Any]) -> dict[str, Any]:
    """Return the original record stored on a normalised event."""

    raw = event.get("raw")
    return raw if isinstance(raw, dict) else {}


def request_parameters(event: dict[str, Any]) -> dict[str, Any]:
    """Request parameters, accepting CloudTrail and generic key spellings."""

    raw = raw_record(event)
    params = raw.get("requestParameters")
    if not isinstance(params, dict):
        params = raw.get("request_parameters")
    return params if isinstance(params, dict) else {}


def response_elements(event: dict[str, Any]) -> dict[str, Any]:
    raw = raw_record(event)
    elements = raw.get("responseElements")
    if not isinstance(elements, dict):
        elements = raw.get("response_elements")
    return elements if isinstance(elements, dict) else {}


def user_identity(event: dict[str, Any]) -> dict[str, Any]:
    raw = raw_record(event)
    identity = raw.get("userIdentity")
    if not isinstance(identity, dict):
        identity = raw.get("user_identity")
    return identity if isinstance(identity, dict) else {}


def identity_type(event: dict[str, Any]) -> str:
    return str(user_identity(event).get("type") or "").strip().lower()


def is_root(event: dict[str, Any]) -> bool:
    """True when the actor is the account root user."""

    if identity_type(event) == "root":
        return True
    arn = str(user_identity(event).get("arn") or "").rstrip("/")
    if arn.lower().endswith(":root"):
        return True
    return str(event.get("user") or "").strip().lower() == "root"


def parameter(params: dict[str, Any], *names: str) -> Any:
    """Look up the first non-blank parameter, ignoring key casing."""

    lowered = {str(key).lower(): value for key, value in params.items()}
    for name in names:
        value = lowered.get(name.lower())
        if not is_blank(value):
            return value
    return None


def items(value: Any) -> list[Any]:
    """Unwrap the ``{"items": [...]}`` list shape used by the AWS SDK/CLI.

    CloudTrail stores repeated fields either as a plain list (generic logs) or
    as ``{"items": [...]}`` (Go SDK marshalling). Both collapse to a list here.
    """

    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        inner = value.get("items")
        if isinstance(inner, list):
            return inner
        if inner is not None:
            return [inner]
        return [value]
    return []


def iter_records(events, columns: list[str]) -> Iterator[dict[str, Any]]:
    """Yield only the columns a detector needs, as plain dictionaries."""

    return iter(events[columns].to_dict("records"))
