"""Adversarial and real-world-shaped ingestion/detection tests (Phase 12).

These cover the failure modes that only show up with production data:
CloudWatch Logs wrappers, gzip CloudTrail objects, duplicate delivery,
corrupt records, mixed timezone offsets, distributed bursts, and the
different shapes an IAM ``Principal`` can take.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pandas as pd
import pytest

from cloudsentinel.adapters.cloudtrail import extract_records
from cloudsentinel.config import BruteForceConfig, PublicStorageConfig
from cloudsentinel.detectors import detect_brute_force, detect_public_storage
from cloudsentinel.ingest import load_events, records_to_dataframe
from cloudsentinel.paths import SUPPORTED_SUFFIXES
from cloudsentinel.severity import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _cloudtrail(event_id: str, moment: str = "2026-02-01T09:30:00Z", **extra):
    record = {
        "eventVersion": "1.09",
        "eventID": event_id,
        "eventTime": moment,
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.11",
        "userIdentity": {"type": "IAMUser", "userName": "alice"},
    }
    record.update(extra)
    return record


# --------------------------------------------------------------- containers


def test_real_cloudwatch_logs_fixture_is_ingested():
    frame = load_events(FIXTURES / "aws-cloudtrail-log-example.json")

    assert len(frame) == 2
    assert set(frame["event_name"]) == {"ConsoleLogin", "DescribeTrails"}
    assert set(frame["event_source"]) == {
        "signin.amazonaws.com",
        "cloudtrail.amazonaws.com",
    }
    assert frame.loc[frame["event_name"] == "ConsoleLogin", "user"].iloc[0].endswith(
        "root"
    )


def test_cloudwatch_wrapper_with_broken_message_is_skipped():
    payload = {
        "messageType": "DATA_MESSAGE",
        "logEvents": [
            {"id": "1", "message": "not json at all"},
            {"id": "2", "message": json.dumps(_cloudtrail("ok-1"))},
        ],
    }

    assert extract_records(payload) == [_cloudtrail("ok-1")]


def test_s3_records_wrapper_and_bare_list_agree():
    wrapped = extract_records({"Records": [_cloudtrail("a")]})
    bare = extract_records([_cloudtrail("a")])

    assert wrapped == bare == [_cloudtrail("a")]


def test_double_wrapped_message_is_unwrapped():
    inner = json.dumps(_cloudtrail("nested-1"))
    payload = {"Records": [{"message": inner}]}

    assert extract_records(payload) == [_cloudtrail("nested-1")]


# ------------------------------------------------------------------- gzip


def test_gzip_is_a_supported_suffix():
    assert ".gz" in SUPPORTED_SUFFIXES


def test_gzipped_cloudtrail_object(tmp_path):
    path = tmp_path / "cloudtrail.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump({"Records": [_cloudtrail("gz-1"), _cloudtrail("gz-2")]}, handle)

    frame = load_events(path)

    assert len(frame) == 2
    assert list(frame["event_id"]) == ["gz-1", "gz-2"]


def test_gzipped_jsonl(tmp_path):
    path = tmp_path / "events.jsonl.gz"
    lines = [
        {"timestamp": "2026-01-01T12:00:00Z", "event_name": "GetObject", "user": "a"},
        {"timestamp": "2026-01-01T12:01:00Z", "event_name": "GetObject", "user": "b"},
    ]
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("\n".join(json.dumps(line) for line in lines))

    frame = load_events(path)

    assert len(frame) == 2
    assert set(frame["user"]) == {"a", "b"}


def test_gzipped_directory_scan(tmp_path):
    with gzip.open(tmp_path / "one.json.gz", "wt", encoding="utf-8") as handle:
        json.dump([_cloudtrail("dir-1")], handle)
    (tmp_path / "two.json").write_text(json.dumps([_cloudtrail("dir-2")]), encoding="utf-8")

    frame = load_events(tmp_path)

    assert set(frame["event_id"]) == {"dir-1", "dir-2"}


# --------------------------------------------------------------- duplicates


def test_duplicate_event_ids_are_skipped_once():
    records = [
        _cloudtrail("dup-1"),
        _cloudtrail("dup-1", moment="2026-02-01T09:31:00Z"),
        _cloudtrail("dup-2"),
    ]

    frame = records_to_dataframe(records)

    assert len(frame) == 2
    assert frame.attrs["duplicates"] == 1
    # The first delivery wins.
    assert frame.loc[frame["event_id"] == "dup-1", "timestamp"].iloc[0] == pd.Timestamp(
        "2026-02-01T09:30:00Z"
    )


def test_duplicates_across_files_are_skipped(tmp_path):
    record = _cloudtrail("shared-1")
    (tmp_path / "a.json").write_text(json.dumps({"Records": [record]}), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps({"Records": [record]}), encoding="utf-8")

    frame = load_events(tmp_path)

    assert len(frame) == 1
    assert frame.attrs["duplicates"] == 1


def test_records_without_ids_still_load():
    frame = records_to_dataframe(
        [
            {"timestamp": "2026-01-01T00:00:00Z", "event_name": "A"},
            {"timestamp": "2026-01-01T00:00:01Z", "event_name": "B"},
        ]
    )

    assert len(frame) == 2
    assert frame["event_id"].is_unique


# ------------------------------------------------------------------ corrupt


def test_corrupt_records_are_dropped_not_fatal():
    frame = records_to_dataframe(
        [
            _cloudtrail("good-1"),
            "a bare string",
            None,
            42,
            {"eventName": "NoTimestamp"},
            {"timestamp": "not-a-date", "eventName": "BadTimestamp"},
            {"eventTime": "2026-02-01T09:30:00Z", "eventName": "NoSourceButValid"},
        ]
    )

    assert len(frame) == 2
    assert frame.attrs["dropped"] == 5
    assert set(frame["event_id"]) == {"good-1", "evt-00007"}


def test_corrupt_json_lines_are_skipped(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text(
        '{"timestamp": "2026-01-01T00:00:00Z", "event_name": "A"}\n'
        "{ this is not json }\n"
        "\n"
        '{"timestamp": "2026-01-01T00:00:02Z", "event_name": "B"}\n',
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 2
    assert set(frame["event_name"]) == {"A", "B"}


def test_empty_and_null_payloads(tmp_path):
    (tmp_path / "null.json").write_text("null", encoding="utf-8")
    (tmp_path / "empty.json").write_text("", encoding="utf-8")
    (tmp_path / "empty_list.json").write_text("[]", encoding="utf-8")

    assert load_events(tmp_path).empty


def test_unexpected_nested_types_do_not_break_policy_scan():
    record = {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_source": "aws.s3",
        "event_name": "PutBucketPolicy",
        "user": "alice",
        "resource": "weird-bucket",
        "request_parameters": {
            "bucketPolicy": {
                "Statement": "a string instead of a list",
                "Principal": 12,
            }
        },
    }
    frame = records_to_dataframe([record])

    assert detect_public_storage(frame) == []


# ---------------------------------------------------------------- timezones


def test_mixed_timezone_offsets_normalise_to_utc():
    frame = records_to_dataframe(
        [
            {
                "timestamp": "2026-01-01T14:00:00+02:00",
                "event_name": "ConsoleLogin",
                "user": "alice",
            },
            {
                "timestamp": "2026-01-01T12:00:00Z",
                "event_name": "ConsoleLogin",
                "user": "bob",
            },
            {
                "timestamp": "2026-01-01T07:00:00-05:00",
                "event_name": "ConsoleLogin",
                "user": "carol",
            },
        ]
    )

    assert frame["timestamp"].dt.tz is not None
    assert len(frame["timestamp"].unique()) == 1
    assert frame["timestamp"].iloc[0] == pd.Timestamp("2026-01-01T12:00:00Z")


def test_naive_and_aware_timestamps_coexist():
    frame = records_to_dataframe(
        [
            {"timestamp": "2026-01-01T12:00:00", "event_name": "A"},
            {"timestamp": "2026-01-01T12:00:01Z", "event_name": "B"},
        ]
    )

    assert len(frame) == 2
    assert frame["timestamp"].dt.tz is not None


def test_offset_events_still_form_one_window(build_events):
    """Three failures at +02:00 and two at Z are all inside one UTC window."""

    events = build_events(
        [
            {"offset": 0, "timestamp": "2026-01-01T14:00:00+02:00"},
            {"offset": 60, "timestamp": "2026-01-01T12:01:00Z"},
            {"offset": 120, "timestamp": "2026-01-01T12:02:00Z"},
            {"offset": 180, "timestamp": "2026-01-01T12:03:00Z"},
            {"offset": 240, "timestamp": "2026-01-01T12:04:00Z"},
        ]
    )

    alerts = detect_brute_force(events, BruteForceConfig(threshold=5))

    assert len(alerts) == 1
    assert alerts[0].event_count == 5


# ------------------------------------------------------------ distributed IPs


def _failed(ip: str, offset: int, user: str = "alice"):
    return {
        "offset": offset,
        "user": user,
        "source_ip": ip,
        "status": "failure",
        "error_code": "Failed authentication",
    }


def test_burst_split_across_ips_is_correlated(build_events):
    events = build_events(
        [
            _failed("198.51.100.1", 0),
            _failed("198.51.100.2", 30),
            _failed("198.51.100.3", 60),
            _failed("198.51.100.1", 90),
            _failed("198.51.100.2", 120),
            _failed("198.51.100.3", 150),
        ]
    )

    alerts = detect_brute_force(events, BruteForceConfig(threshold=5))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.title == "Distributed failed logins"
    assert alert.event_count == 6
    assert alert.evidence["correlated_across_ips"] is True
    assert alert.evidence["distinct_ips"] == 3
    assert len(alert.evidence["source_ips"]) == 3


def test_split_burst_with_followup_success_is_critical(build_events):
    rows = [
        _failed("198.51.100.1", 0),
        _failed("198.51.100.2", 20),
        _failed("198.51.100.3", 40),
        _failed("198.51.100.1", 60),
        _failed("198.51.100.2", 80),
        {
            "offset": 200,
            "user": "alice",
            "source_ip": "198.51.100.9",
            "status": "success",
        },
    ]

    alerts = detect_brute_force(build_events(rows), BruteForceConfig(threshold=5))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].evidence["success_after_failures"] is True


def test_single_ip_burst_is_not_duplicated_by_correlation(build_events):
    rows = [_failed("198.51.100.1", index * 20) for index in range(6)]

    alerts = detect_brute_force(build_events(rows), BruteForceConfig(threshold=5))

    assert len(alerts) == 1
    assert alerts[0].title != "Distributed failed logins"


def test_correlation_can_be_disabled(build_events):
    rows = [
        _failed("198.51.100.1", 0),
        _failed("198.51.100.2", 30),
        _failed("198.51.100.3", 60),
        _failed("198.51.100.1", 90),
        _failed("198.51.100.2", 120),
    ]

    alerts = detect_brute_force(
        build_events(rows),
        BruteForceConfig(threshold=5, correlate_across_ips=False),
    )

    assert alerts == []


def test_different_users_are_not_correlated(build_events):
    rows = [
        _failed("198.51.100.1", 0, user="alice"),
        _failed("198.51.100.2", 10, user="bob"),
        _failed("198.51.100.3", 20, user="carol"),
        _failed("198.51.100.4", 30, user="dave"),
        _failed("198.51.100.5", 40, user="erin"),
    ]

    assert detect_brute_force(build_events(rows), BruteForceConfig(threshold=5)) == []


# ------------------------------------------------------- Principal variants


def _s3_policy_event(principal, event_id="pol-1"):
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_source": "aws.s3",
        "event_name": "PutBucketPolicy",
        "user": "alice",
        "resource": "public-bucket",
        "event_id": event_id,
        "request_parameters": {
            "bucketName": "public-bucket",
            "bucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": principal,
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::public-bucket/*",
                    }
                ],
            },
        },
    }


@pytest.mark.parametrize(
    "principal",
    [
        "*",
        ["*"],
        {"AWS": "*"},
        {"AWS": ["*"]},
        {"AWS": ["arn:aws:iam::123456789012:root", "*"]},
    ],
)
def test_public_principal_shapes_are_detected(principal):
    frame = records_to_dataframe([_s3_policy_event(principal)])

    alerts = detect_public_storage(frame)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].entity == "public-bucket"


@pytest.mark.parametrize(
    "principal",
    [
        {"AWS": "arn:aws:iam::123456789012:root"},
        {"Service": "cloudfront.amazonaws.com"},
        ["arn:aws:iam::123456789012:role/app"],
        None,
    ],
)
def test_private_principals_are_not_flagged(principal):
    frame = records_to_dataframe([_s3_policy_event(principal)])

    assert detect_public_storage(frame) == []


def test_public_wildcard_action_is_critical():
    event = _s3_policy_event("*")
    statement = event["request_parameters"]["bucketPolicy"]["Statement"][0]
    statement["Action"] = "*"
    statement["Resource"] = "*"

    alerts = detect_public_storage(records_to_dataframe([event]))

    assert alerts[0].severity == Severity.CRITICAL


def test_url_encoded_policy_is_decoded():
    policy = {
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]
    }
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_source": "aws.s3",
        "event_name": "PutBucketPolicy",
        "user": "alice",
        "resource": "encoded",
        "request_parameters": {"bucketPolicy": json.dumps(policy).replace('"', "%22")},
    }

    alerts = detect_public_storage(records_to_dataframe([event]))

    assert len(alerts) == 1


def test_public_storage_disabled_still_parses_input():
    frame = records_to_dataframe([_s3_policy_event({"AWS": "*"})])

    assert detect_public_storage(frame, PublicStorageConfig(enabled=False)) == []


# ---------------------------------------------------------------- robustness


def test_random_malformed_records_do_not_crash_any_detector():
    """Fuzz ingestion + all detectors with mixed, invalid record shapes."""

    import random

    from cloudsentinel.config import Config
    from cloudsentinel.pipeline import collect_alerts

    rng = random.Random(20261028)
    scalar = [None, True, False, 0, 1, 3.14, "", "text", "*", "{}", "[]"]
    timestamps = [
        "2026-01-01T00:00:00Z",
        "2026-01-01T02:00:00+02:00",
        1767225600,
        1767225600000,
        "invalid",
        "",
        None,
    ]
    names = ["ConsoleLogin", "PutBucketPolicy", "PutRolePolicy", "GetObject", ""]

    records: list[object] = []
    for _ in range(300):
        kind = rng.randrange(4)
        if kind == 0:
            records.append(rng.choice(scalar))
        elif kind == 1:
            records.append(
                {
                    "timestamp": rng.choice(timestamps),
                    "event_name": rng.choice(names),
                    "event_source": rng.choice(["aws.s3", "aws.iam", "generic", ""]),
                    "user": rng.choice(scalar),
                    "source_ip": rng.choice(scalar),
                    "status": rng.choice(scalar),
                }
            )
        elif kind == 2:
            records.append(
                {
                    "timestamp": rng.choice(timestamps),
                    "event_name": rng.choice(names),
                    "request_parameters": {
                        "bucketPolicy": {"Statement": rng.choice(scalar)},
                        "roleName": rng.choice(scalar),
                        "latitude": rng.choice(scalar),
                        "longitude": rng.choice(scalar),
                    },
                }
            )
        else:
            records.append(
                {
                    "timestamp": rng.choice(timestamps),
                    "event_name": rng.choice(names),
                    "nested": [{"a": [1, 2, {"principal": "*"}]}, rng.choice(scalar)],
                }
            )

    frame = records_to_dataframe(records)

    # Must not raise, and the frame must still satisfy the canonical schema.
    alerts = collect_alerts(frame, Config())
    assert isinstance(alerts, list)
    assert set(frame.columns) >= {"timestamp", "event_name", "user", "raw"}
    assert all(alert.detector for alert in alerts)
