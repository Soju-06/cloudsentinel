"""MFA-removal detector tests."""

from __future__ import annotations

import pandas as pd

from cloudsentinel.config import MFAConfig
from cloudsentinel.detectors import detect_mfa_changes
from cloudsentinel.severity import Severity


def _mfa_event(build_events, **overrides):
    row = {
        "event_source": "aws.iam",
        "event_name": "DeactivateMFADevice",
        "user": "alice",
        "status": "success",
        "resource": "bob",
        "request_parameters": {
            "userName": "bob",
            "serialNumber": "arn:aws:iam::123456789012:mfa/bob",
        },
    }
    row.update(overrides)
    return build_events([row])


def test_removing_another_users_mfa_is_critical(build_events):
    alerts = detect_mfa_changes(_mfa_event(build_events))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "mfa_changes"
    assert alert.severity == Severity.CRITICAL
    assert alert.entity == "bob"
    assert alert.entity_type == "user"
    assert "disabled" in alert.description


def test_removing_own_mfa_is_high(build_events):
    events = _mfa_event(
        build_events,
        user="alice",
        request_parameters={"userName": "alice"},
    )

    alerts = detect_mfa_changes(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].entity == "alice"


def test_deleting_virtual_device_is_detected(build_events):
    events = _mfa_event(build_events, event_name="DeleteVirtualMFADevice")

    alerts = detect_mfa_changes(events)

    assert len(alerts) == 1
    assert "deleted" in alerts[0].description
    assert alerts[0].evidence["actions"] == ["deleted"]


def test_root_actor_or_target_escalates(build_events):
    by_root = _mfa_event(
        build_events,
        user="root",
        request_parameters={"userName": "root"},
    )
    assert detect_mfa_changes(by_root)[0].severity == Severity.CRITICAL

    against_root = _mfa_event(
        build_events,
        user="alice",
        request_parameters={"userName": "root"},
    )
    assert detect_mfa_changes(against_root)[0].severity == Severity.CRITICAL


def test_events_aggregate_per_target(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.iam",
                "event_name": "DeactivateMFADevice",
                "user": "alice",
                "status": "success",
                "offset": 0,
                "request_parameters": {"userName": "bob"},
            },
            {
                "event_source": "aws.iam",
                "event_name": "DeleteVirtualMFADevice",
                "user": "alice",
                "status": "success",
                "offset": 60,
                "request_parameters": {"userName": "bob"},
            },
        ]
    )

    alerts = detect_mfa_changes(events)

    assert len(alerts) == 1
    assert alerts[0].event_count == 2
    assert alerts[0].evidence["actions"] == ["deleted", "disabled"]
    assert alerts[0].first_seen < alerts[0].last_seen


def test_unrelated_events_are_ignored(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.iam",
                "event_name": "CreateUser",
                "user": "alice",
                "status": "success",
                "request_parameters": {"userName": "bob"},
            }
        ]
    )

    assert detect_mfa_changes(events) == []


def test_disabled_config_and_empty_input(build_events):
    events = _mfa_event(build_events)

    assert detect_mfa_changes(events, MFAConfig(enabled=False)) == []
    assert detect_mfa_changes(pd.DataFrame()) == []
