"""Repeated failed-login detector tests."""

from __future__ import annotations

import pytest

from cloudsentinel.config import BruteForceConfig
from cloudsentinel.detectors import detect_brute_force
from cloudsentinel.severity import Severity


def failures(build_events, count: int, spacing: int = 30, **overrides):
    rows = [{"offset": index * spacing, **overrides} for index in range(count)]
    return build_events(rows)


def test_threshold_triggers_high_alert(build_events):
    events = failures(build_events, 5, user="alice", source_ip="203.0.113.5")

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "brute_force"
    assert alert.severity == Severity.HIGH
    assert alert.entity == "alice"
    assert alert.event_count == 5


def test_below_threshold_does_not_alert(build_events):
    events = failures(build_events, 4)
    assert detect_brute_force(events) == []


def test_exact_window_boundary_triggers(build_events):
    # Five events spanning exactly 600 seconds (10 minutes) qualify.
    events = build_events([{"offset": offset} for offset in (0, 150, 300, 450, 600)])
    assert len(detect_brute_force(events)) == 1


def test_outside_window_does_not_alert(build_events):
    # No 600-second window contains five of these events.
    events = build_events([{"offset": offset} for offset in (0, 150, 300, 450, 601)])
    assert detect_brute_force(events) == []


def test_high_volume_escalates_to_critical(build_events):
    events = failures(build_events, 15, spacing=20)

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_success_after_failures_marks_compromise(build_events):
    rows = [{"offset": index * 30} for index in range(5)]
    rows.append({"offset": 300, "status": "success", "error_code": ""})
    events = build_events(rows)

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert "compromise" in alerts[0].title.lower()
    assert alerts[0].evidence["success_after_failures"] is True


def test_success_from_other_ip_does_not_escalate(build_events):
    rows = [{"offset": index * 30, "source_ip": "203.0.113.5"} for index in range(5)]
    rows.append({"offset": 300, "status": "success", "source_ip": "10.0.0.2"})
    events = build_events(rows)

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_failures_grouped_per_ip(build_events):
    rows = [
        {"offset": index * 30, "source_ip": "203.0.113.5"} for index in range(3)
    ] + [
        {"offset": index * 30, "source_ip": "198.51.100.9"} for index in range(3)
    ]
    events = build_events(rows)
    # Per-IP grouping alone stays below threshold; cross-IP correlation is
    # covered separately in test_hardening.py.
    config = BruteForceConfig(correlate_across_ips=False)
    assert detect_brute_force(events, config) == []


def test_group_by_ip_aggregates_users(build_events):
    rows = [
        {"offset": index * 30, "user": f"user{index}", "source_ip": "203.0.113.99"}
        for index in range(5)
    ]
    events = build_events(rows)
    config = BruteForceConfig(group_by="ip")

    alerts = detect_brute_force(events, config)

    assert len(alerts) == 1
    assert alerts[0].entity == "203.0.113.99"
    assert alerts[0].entity_type == "ip"


def test_non_login_failures_are_ignored(build_events):
    events = build_events(
        [
            {
                "offset": index * 10,
                "event_name": "GetObject",
                "status": "failure",
                "error_code": "AccessDenied",
            }
            for index in range(10)
        ]
    )
    assert detect_brute_force(events) == []


def test_custom_threshold(build_events):
    events = failures(build_events, 3)
    assert detect_brute_force(events, BruteForceConfig(threshold=7)) == []
    assert len(detect_brute_force(events, BruteForceConfig(threshold=3))) == 1


def test_empty_input():
    import pandas as pd

    assert detect_brute_force(pd.DataFrame()) == []


@pytest.mark.parametrize("group_by", ["user", "user_ip", "ip"])
def test_supported_group_modes(build_events, group_by):
    events = failures(build_events, 5)
    alerts = detect_brute_force(events, BruteForceConfig(group_by=group_by))
    assert len(alerts) == 1


def test_invalid_group_mode_rejected():
    with pytest.raises(ValueError):
        BruteForceConfig(group_by="planet")
