"""Ingestion and normalisation tests."""

from __future__ import annotations

import json

import pandas as pd

from cloudsentinel.ingest import (
    EVENT_COLUMNS,
    load_events,
    normalize_status,
    records_to_dataframe,
)


def test_generic_json_array(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-01-01T12:00:00Z",
                    "event_source": "aws.signin",
                    "event_name": "ConsoleLogin",
                    "user": "alice",
                    "source_ip": "203.0.113.5",
                    "status": "failed",
                    "error_code": "Failed authentication",
                }
            ]
        ),
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 1
    assert list(frame.columns) == EVENT_COLUMNS
    assert frame.loc[0, "user"] == "alice"
    assert frame.loc[0, "status"] == "failure"
    assert frame.loc[0, "timestamp"] == pd.Timestamp("2026-01-01T12:00:00Z")


def test_jsonl_is_supported(tmp_path):
    lines = [
        {"timestamp": "2026-01-01T12:00:00Z", "event_name": "GetObject", "user": "a"},
        {"timestamp": "2026-01-01T12:05:00Z", "event_name": "GetObject", "user": "b"},
    ]
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines), encoding="utf-8")

    frame = load_events(path)

    assert len(frame) == 2
    assert set(frame["user"]) == {"a", "b"}


def test_csv_is_supported(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text(
        "timestamp,event_name,user,source_ip,status\n"
        "2026-01-01T12:00:00Z,ConsoleLogin,carol,10.0.0.9,success\n",
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 1
    assert frame.loc[0, "event_name"] == "ConsoleLogin"
    assert frame.loc[0, "source_ip"] == "10.0.0.9"


def test_cloudtrail_records_are_mapped(tmp_path):
    record = {
        "eventVersion": "1.09",
        "eventID": "abc-123",
        "eventTime": "2026-02-01T09:30:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachRolePolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.11",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/heidi",
            "userName": "heidi",
        },
        "requestParameters": {"roleName": "ct-deploy"},
        "errorCode": "AccessDenied",
    }
    path = tmp_path / "cloudtrail.json"
    path.write_text(json.dumps({"Records": [record]}), encoding="utf-8")

    frame = load_events(path)

    assert len(frame) == 1
    row = frame.iloc[0]
    assert row["event_id"] == "abc-123"
    assert row["user"] == "heidi"
    assert row["event_source"] == "iam.amazonaws.com"
    assert row["resource"] == "ct-deploy"
    assert row["status"] == "failure"
    assert row["error_code"] == "AccessDenied"


def test_invalid_timestamps_are_dropped(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps([{"timestamp": "not-a-date", "event_name": "ConsoleLogin"}]),
        encoding="utf-8",
    )

    frame = load_events(path)

    assert frame.empty
    assert frame.attrs["dropped"] == 1


def test_epoch_timestamps_and_alias_fields(tmp_path):
    path = tmp_path / "epoch.json"
    path.write_text(
        json.dumps(
            [
                {
                    "time": 1767268800,
                    "action": "ConsoleLogin",
                    "username": "dave",
                    "ip": "198.51.100.4",
                    "result": "denied",
                }
            ]
        ),
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 1
    assert frame.loc[0, "event_name"] == "ConsoleLogin"
    assert frame.loc[0, "user"] == "dave"
    assert frame.loc[0, "status"] == "failure"


def test_normalize_status_variants():
    assert normalize_status("FAILED") == "failure"
    assert normalize_status("Denied") == "failure"
    assert normalize_status("SUCCESS") == "success"
    assert normalize_status("allowed") == "success"
    assert normalize_status(None) is None


def test_records_to_dataframe_sorted_by_timestamp(build_events):
    frame = build_events([{"offset": 60}, {"offset": 0}, {"offset": 30}])
    assert list(frame["timestamp"]) == sorted(frame["timestamp"])
