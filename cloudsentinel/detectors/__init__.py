"""Detectors that turn normalised events into alerts."""

from __future__ import annotations

import pandas as pd

from .brute_force import detect as detect_brute_force
from .iam_permissions import detect as detect_iam_permissions
from .impossible_travel import detect as detect_impossible_travel
from .public_storage import detect as detect_public_storage

DETECTOR_NAMES = (
    "brute_force",
    "impossible_travel",
    "public_storage",
    "iam_permissions",
)

__all__ = [
    "DETECTOR_NAMES",
    "detect_brute_force",
    "detect_iam_permissions",
    "detect_impossible_travel",
    "detect_public_storage",
    "run_all",
]


def run_all(events: pd.DataFrame, config=None) -> list:
    """Run every enabled detector and return the combined alert list."""

    from ..config import Config

    config = config or Config()
    alerts = []
    alerts.extend(detect_brute_force(events, config.brute_force))
    alerts.extend(detect_impossible_travel(events, config.impossible_travel))
    alerts.extend(detect_public_storage(events, config.public_storage))
    alerts.extend(detect_iam_permissions(events, config.iam))
    return alerts
