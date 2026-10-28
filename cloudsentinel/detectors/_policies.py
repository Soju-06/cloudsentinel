"""Helpers for reading IAM policy documents embedded in audit events."""

from __future__ import annotations

import json
from typing import Any, Iterable

from ..utils import maybe_decode_json, walk_json

POLICY_KEYS = {
    "policy",
    "policydocument",
    "inlinepolicy",
    "bucketpolicy",
    "accesspolicy",
    "document",
    "newpolicy",
    "rolepolicydocument",
    "policybody",
}


def iter_policy_documents(obj: Any) -> list[dict[str, Any] | list[Any]]:
    """Find policy-shaped values anywhere in a raw event."""

    return scan_policy_documents(obj)[0]


def scan_policy_documents(
    obj: Any, flag_keys: Iterable[str] = ()
) -> tuple[list[dict[str, Any] | list[Any]], bool]:
    """Collect policy documents and enabled flags in a single tree walk.

    Returns ``(documents, has_enabled_flag)``. Doing both in one pass keeps
    large scans cheap, since every event is walked at most once.
    """

    documents: list[dict[str, Any] | list[Any]] = []
    seen: set[str] = set()
    wanted_flags = {str(key).lower() for key in flag_keys}
    enabled_flag = False

    for path, node in walk_json(obj):
        key = path.rsplit(".", 1)[-1].lower()
        if key in POLICY_KEYS:
            decoded = maybe_decode_json(node)
            if isinstance(decoded, (dict, list)):
                marker = _doc_marker(decoded)
                if marker not in seen:
                    seen.add(marker)
                    documents.append(decoded)
        if wanted_flags and key in wanted_flags and is_enabled_flag(node):
            enabled_flag = True

    return documents, enabled_flag


def is_enabled_flag(value: Any) -> bool:
    """True for boolean/string values that mean 'this is switched on'."""

    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "public", "enabled"}
    return False


def as_statements(document: Any) -> list[dict[str, Any]]:
    """Return the statement dicts from an IAM policy document."""

    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]

    if not isinstance(document, dict):
        return []

    statement = (
        document.get("Statement")
        or document.get("statement")
        or document.get("Statements")
        or document.get("statements")
    )
    if statement is None:
        statement = document
    if isinstance(statement, dict):
        return [statement]
    if isinstance(statement, list):
        return [item for item in statement if isinstance(item, dict)]
    return []


def has_wildcard(value: Any) -> bool:
    """True when the value is exactly ``"*"`` (or a list containing it)."""

    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() == "*"
    if isinstance(value, (list, tuple, set)):
        return any(has_wildcard(item) for item in value)
    return False


def principal_is_public(principal: Any) -> bool:
    """True when an IAM principal grants access to ``"*"``."""

    if principal is None:
        return False
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, (list, tuple, set)):
        return any(principal_is_public(item) for item in principal)
    if isinstance(principal, dict):
        return any(principal_is_public(value) for value in principal.values())
    return False


def statement_has_wildcard_action(statement: dict[str, Any]) -> bool:
    return has_wildcard(statement.get("Action")) or has_wildcard(
        statement.get("NotAction")
    )


def statement_has_wildcard_resource(statement: dict[str, Any]) -> bool:
    return has_wildcard(statement.get("Resource")) or has_wildcard(
        statement.get("NotResource")
    )


def statement_is_allow(statement: dict[str, Any]) -> bool:
    return str(statement.get("Effect", "Allow")).strip().lower() == "allow"


def allows_everything(document: Any) -> bool:
    """True when any Allow statement has both Action and Resource wildcards."""

    return any(
        statement_is_allow(stmt)
        and statement_has_wildcard_action(stmt)
        and statement_has_wildcard_resource(stmt)
        for stmt in as_statements(document)
    )


def _doc_marker(document: Any) -> str:
    try:
        return json.dumps(document, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return repr(document)


def strings_under(obj: Any, key_fragments: Iterable[str]) -> list[str]:
    """Collect string values whose JSON path ends with one of the fragments."""

    fragments = tuple(fragment.lower() for fragment in key_fragments)
    values: list[str] = []
    for path, node in walk_json(obj):
        key = path.rsplit(".", 1)[-1].lower()
        if isinstance(node, str) and any(fragment in key for fragment in fragments):
            values.append(node)
    return values
