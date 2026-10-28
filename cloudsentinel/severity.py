"""Severity levels shared by every detector and the dashboard."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Ordered alert severity. Higher score == more urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def parse(cls, value: "Severity | str") -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INFO

    @property
    def score(self) -> int:
        return _SCORES[self]

    @property
    def color(self) -> str:
        return _COLORS[self]

    @property
    def label(self) -> str:
        return self.value.upper()

    def __str__(self) -> str:  # nicer f-strings than "Severity.HIGH"
        return self.value


_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#ff2d55",
    Severity.HIGH: "#ff9f0a",
    Severity.MEDIUM: "#ffd60a",
    Severity.LOW: "#30d158",
    Severity.INFO: "#64d2ff",
}

ALL_SEVERITIES: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def highest(*values: "Severity | str") -> Severity:
    """Return the most severe value, defaulting to INFO when empty."""

    parsed = [Severity.parse(v) for v in values if v is not None]
    if not parsed:
        return Severity.INFO
    return max(parsed, key=lambda item: item.score)


def sort_key(value: "Severity | str") -> int:
    """Sort helper: critical first when used with ``sorted``/``sort_values``."""

    return -Severity.parse(value).score
