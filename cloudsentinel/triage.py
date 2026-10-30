"""Alert triage state machine.

Every alert starts ``open``. An analyst can acknowledge it (taking ownership),
assign it to a person, close it once resolved, or reopen a closed finding.
Triage is orthogonal to detection: re-scans keep updating an alert's evidence
without resetting the analyst's decision.
"""

from __future__ import annotations

STATUSES = ("open", "acknowledged", "closed")
DEFAULT_STATUS = "open"

# Allowed moves. Staying in the same state is always allowed (idempotent).
TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"acknowledged", "closed"}),
    "acknowledged": frozenset({"open", "closed"}),
    "closed": frozenset({"open"}),
}


class TriageError(ValueError):
    """Base class for triage validation failures."""


class InvalidStatusError(TriageError):
    """Raised when a caller supplies a status that does not exist."""


class InvalidTransitionError(TriageError):
    """Raised when a status change is not part of the workflow."""


def normalize_status(value: str | None) -> str:
    """Return the canonical status name, raising for unknown values."""

    if value is None:
        return DEFAULT_STATUS
    status = str(value).strip().lower()
    if status not in STATUSES:
        raise InvalidStatusError(
            f"unknown status {value!r}; expected one of {', '.join(STATUSES)}"
        )
    return status


def validate_transition(current: str, target: str) -> str:
    """Return ``target`` if moving from ``current`` is allowed."""

    current = normalize_status(current)
    target = normalize_status(target)
    if target == current:
        return target
    if target not in TRANSITIONS[current]:
        raise InvalidTransitionError(
            f"cannot move an alert from {current} to {target}"
        )
    return target
