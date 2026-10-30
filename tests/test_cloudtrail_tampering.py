"""CloudTrail tampering detector tests."""

from __future__ import annotations

import pandas as pd

from cloudsentinel.config import CloudTrailConfig
from cloudsentinel.detectors import detect_cloudtrail_tampering
from cloudsentinel.severity import Severity


def _trail_event(build_events, **overrides):
    row = {
        "event_source": "aws.cloudtrail",
        "event_name": "StopLogging",
        "user": "alice",
        "status": "success",
        "resource": "prod-trail",
        "request_parameters": {"name": "prod-trail"},
    }
    row.update(overrides)
    return build_events([row])


def test_stop_logging_is_critical(build_events):
    alerts = detect_cloudtrail_tampering(_trail_event(build_events))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "cloudtrail_tampering"
    assert alert.severity == Severity.CRITICAL
    assert alert.entity == "prod-trail"
    assert alert.entity_type == "audit_trail"
    assert "logging disabled" in alert.title


def test_delete_trail_is_critical(build_events):
    events = _trail_event(build_events, event_name="DeleteTrail")

    alerts = detect_cloudtrail_tampering(events)

    assert alerts[0].severity == Severity.CRITICAL
    assert "trail deleted" in alerts[0].description


def test_configuration_changes_are_high(build_events):
    for name in ("UpdateTrail", "PutEventSelectors", "PutInsightSelectors"):
        events = _trail_event(build_events, event_name=name)
        alerts = detect_cloudtrail_tampering(events)

        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert "configuration changed" in alerts[0].title


def test_events_aggregate_per_trail(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.cloudtrail",
                "event_name": "UpdateTrail",
                "user": "alice",
                "status": "success",
                "offset": 0,
                "request_parameters": {"name": "prod-trail"},
            },
            {
                "event_source": "aws.cloudtrail",
                "event_name": "StopLogging",
                "user": "root",
                "status": "success",
                "offset": 60,
                "request_parameters": {"trailName": "prod-trail"},
            },
        ]
    )

    alerts = detect_cloudtrail_tampering(events)

    assert len(alerts) == 1
    assert alerts[0].event_count == 2
    assert alerts[0].severity == Severity.CRITICAL
    assert set(alerts[0].evidence["actors"]) == {"alice", "root"}


def test_missing_trail_name_falls_back_to_account(build_events):
    events = _trail_event(build_events, request_parameters={})

    alerts = detect_cloudtrail_tampering(events)

    assert alerts[0].entity == "account"


def test_unrelated_events_are_ignored(build_events):
    events = _trail_event(build_events, event_name="LookupEvents")
    assert detect_cloudtrail_tampering(events) == []


def test_disabled_config_and_empty_input(build_events):
    events = _trail_event(build_events)

    assert (
        detect_cloudtrail_tampering(events, CloudTrailConfig(enabled=False)) == []
    )
    assert detect_cloudtrail_tampering(pd.DataFrame()) == []
