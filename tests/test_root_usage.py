"""Root-account usage detector tests."""

from __future__ import annotations

import pandas as pd

from cloudsentinel.config import RootUsageConfig
from cloudsentinel.detectors import detect_root_usage
from cloudsentinel.severity import Severity

ROOT_ARN = "arn:aws:iam::123456789012:root"


def _root_event(build_events, **overrides):
    row = {
        "event_source": "aws.signin",
        "event_name": "ConsoleLogin",
        "user": "root",
        "status": "success",
        "source_ip": "198.51.100.77",
    }
    row.update(overrides)
    return build_events([row])


def test_root_console_login_is_high(build_events):
    alerts = detect_root_usage(_root_event(build_events))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "root_usage"
    assert alert.severity == Severity.HIGH
    assert alert.entity == "root"
    assert alert.entity_type == "account"
    assert alert.evidence["source_ips"] == ["198.51.100.77"]


def test_sensitive_root_action_is_critical(build_events):
    events = _root_event(
        build_events,
        event_source="aws.iam",
        event_name="CreateAccessKey",
        request_parameters={"userName": "root"},
    )

    alerts = detect_root_usage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_cloudtrail_root_identity_is_detected(build_events):
    events = build_events(
        [
            {
                "event_source": "iam.amazonaws.com",
                "event_name": "CreateUser",
                "user": ROOT_ARN,
                "status": "success",
                "userIdentity": {"type": "Root", "arn": ROOT_ARN},
                "request_parameters": {"userName": "backdoor"},
            }
        ]
    )

    alerts = detect_root_usage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].evidence["actions"] == ["CreateUser"]


def test_non_root_activity_is_ignored(build_events):
    events = _root_event(build_events, user="alice")
    assert detect_root_usage(events) == []


def test_root_events_aggregate_into_one_alert(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.signin",
                "event_name": "ConsoleLogin",
                "user": "root",
                "status": "success",
                "source_ip": "198.51.100.77",
                "offset": 0,
            },
            {
                "event_source": "aws.cloudtrail",
                "event_name": "StopLogging",
                "user": "root",
                "status": "success",
                "source_ip": "198.51.100.77",
                "offset": 120,
            },
        ]
    )

    alerts = detect_root_usage(events)

    assert len(alerts) == 1
    assert alerts[0].event_count == 2
    assert alerts[0].severity == Severity.CRITICAL
    assert set(alerts[0].evidence["actions"]) == {"ConsoleLogin", "StopLogging"}


def test_custom_critical_actions(build_events):
    events = _root_event(build_events, event_name="GetCallerIdentity")
    config = RootUsageConfig(critical_actions=["getcalleridentity"])

    alerts = detect_root_usage(events, config)

    assert alerts[0].severity == Severity.CRITICAL


def test_disabled_config_and_empty_input(build_events):
    events = _root_event(build_events)

    assert detect_root_usage(events, RootUsageConfig(enabled=False)) == []
    assert detect_root_usage(pd.DataFrame()) == []
