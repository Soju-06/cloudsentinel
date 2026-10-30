"""Detectors that turn normalised events into alerts."""

from __future__ import annotations

import pandas as pd

from .access_keys import detect as detect_access_key_creation
from .brute_force import detect as detect_brute_force
from .cloudtrail_tampering import detect as detect_cloudtrail_tampering
from .iam_permissions import detect as detect_iam_permissions
from .impossible_travel import detect as detect_impossible_travel
from .mfa_changes import detect as detect_mfa_changes
from .public_storage import detect as detect_public_storage
from .root_usage import detect as detect_root_usage
from .security_groups import detect as detect_open_security_groups

DETECTOR_NAMES = (
    "brute_force",
    "impossible_travel",
    "public_storage",
    "iam_permissions",
    "mfa_changes",
    "root_usage",
    "access_key_creation",
    "security_group_open",
    "cloudtrail_tampering",
)

__all__ = [
    "DETECTOR_NAMES",
    "detect_access_key_creation",
    "detect_brute_force",
    "detect_cloudtrail_tampering",
    "detect_iam_permissions",
    "detect_impossible_travel",
    "detect_mfa_changes",
    "detect_open_security_groups",
    "detect_public_storage",
    "detect_root_usage",
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
    alerts.extend(detect_mfa_changes(events, config.mfa))
    alerts.extend(detect_root_usage(events, config.root_usage))
    alerts.extend(detect_access_key_creation(events, config.access_keys))
    alerts.extend(detect_open_security_groups(events, config.security_groups))
    alerts.extend(detect_cloudtrail_tampering(events, config.cloudtrail))
    return alerts
