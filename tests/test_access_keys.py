"""Access-key creation detector tests."""

from __future__ import annotations

import pandas as pd

from cloudsentinel.config import AccessKeyConfig
from cloudsentinel.detectors import detect_access_key_creation
from cloudsentinel.severity import Severity


def _key_event(build_events, **overrides):
    row = {
        "event_source": "aws.iam",
        "event_name": "CreateAccessKey",
        "user": "alice",
        "status": "success",
        "resource": "alice",
        "request_parameters": {"userName": "alice"},
    }
    row.update(overrides)
    return build_events([row])


def test_self_service_key_is_medium(build_events):
    alerts = detect_access_key_creation(_key_event(build_events))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detector == "access_key_creation"
    assert alert.severity == Severity.MEDIUM
    assert alert.entity == "alice"


def test_key_created_for_another_user_is_high(build_events):
    events = _key_event(
        build_events,
        user="alice",
        resource="carol",
        request_parameters={"userName": "carol"},
    )

    alerts = detect_access_key_creation(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].entity == "carol"
    assert alerts[0].evidence["actors"] == ["alice"]


def test_root_key_creation_is_critical(build_events):
    events = _key_event(
        build_events,
        user="root",
        resource="root",
        request_parameters={"userName": "root"},
    )

    alerts = detect_access_key_creation(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_key_id_is_captured_from_response_elements(build_events):
    events = _key_event(
        build_events,
        responseElements={
            "accessKey": {"accessKeyId": "AKIAEXAMPLE123", "userName": "alice"}
        },
    )

    alerts = detect_access_key_creation(events)

    assert alerts[0].evidence["access_key_ids"] == ["AKIAEXAMPLE123"]


def test_creations_aggregate_per_target(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.iam",
                "event_name": "CreateAccessKey",
                "user": "alice",
                "status": "success",
                "offset": 0,
                "request_parameters": {"userName": "carol"},
                "responseElements": {"accessKey": {"accessKeyId": "AKIA1"}},
            },
            {
                "event_source": "aws.iam",
                "event_name": "CreateAccessKey",
                "user": "bob",
                "status": "success",
                "offset": 60,
                "request_parameters": {"userName": "carol"},
                "responseElements": {"accessKey": {"accessKeyId": "AKIA2"}},
            },
        ]
    )

    alerts = detect_access_key_creation(events)

    assert len(alerts) == 1
    assert alerts[0].event_count == 2
    assert alerts[0].evidence["access_key_ids"] == ["AKIA1", "AKIA2"]
    assert alerts[0].evidence["actors"] == ["alice", "bob"]


def test_other_iam_events_are_ignored(build_events):
    events = _key_event(build_events, event_name="UpdateAccessKey")
    assert detect_access_key_creation(events) == []


def test_disabled_config_and_empty_input(build_events):
    events = _key_event(build_events)

    assert detect_access_key_creation(events, AccessKeyConfig(enabled=False)) == []
    assert detect_access_key_creation(pd.DataFrame()) == []
