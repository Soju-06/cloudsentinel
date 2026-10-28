"""End-to-end pipeline and sample-data tests."""

from __future__ import annotations

import json

from cloudsentinel.config import Config
from cloudsentinel.db import AlertStore
from cloudsentinel.ingest import load_events
from cloudsentinel.pipeline import collect_alerts, scan_files
from cloudsentinel.sampledata import write_sample_data
from cloudsentinel.severity import Severity


def _write_incident_log(path):
    events = [
        # Credential attack
        *[
            {
                "timestamp": f"2026-03-01T10:0{index}:00Z",
                "event_source": "aws.signin",
                "event_name": "ConsoleLogin",
                "user": "carol",
                "source_ip": "203.0.113.50",
                "status": "failure",
                "error_code": "Failed authentication",
            }
            for index in range(6)
        ],
        # Public bucket
        {
            "timestamp": "2026-03-01T11:00:00Z",
            "event_source": "aws.s3",
            "event_name": "PutBucketPolicy",
            "user": "alice",
            "source_ip": "10.0.0.5",
            "resource": "public-bucket",
            "status": "success",
            "request_parameters": {
                "bucketName": "public-bucket",
                "bucketPolicy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ]
                },
            },
        },
        # Excessive IAM
        {
            "timestamp": "2026-03-01T12:00:00Z",
            "event_source": "aws.iam",
            "event_name": "PutRolePolicy",
            "user": "alice",
            "source_ip": "10.0.0.5",
            "resource": "ci-deployer",
            "status": "success",
            "request_parameters": {
                "roleName": "ci-deployer",
                "policyDocument": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}
                    ]
                },
            },
        },
    ]
    path.write_text(json.dumps(events, indent=2), encoding="utf-8")


def test_scan_files_end_to_end(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    _write_incident_log(raw / "incidents.json")
    db_path = tmp_path / "alerts.db"

    result = scan_files(raw, db_path, reset=True)

    assert result.events_scanned == 8
    assert len(result.alerts) == 3
    assert {alert.detector for alert in result.alerts} == {
        "brute_force",
        "public_storage",
        "iam_permissions",
    }
    assert AlertStore(db_path).count() == 3

    # Re-scanning the same data must not duplicate alerts.
    again = scan_files(raw, db_path)
    assert again.updated == 3
    assert AlertStore(db_path).count() == 3


def test_reset_clears_previous_alerts(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    _write_incident_log(raw / "incidents.json")
    db_path = tmp_path / "alerts.db"

    scan_files(raw, db_path, reset=True)
    scan_files(raw, db_path)
    assert AlertStore(db_path).count() == 3

    scan_files(raw, db_path, reset=True)
    assert AlertStore(db_path).count() == 3


def test_empty_input_produces_no_alerts(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    result = scan_files(raw, tmp_path / "alerts.db", reset=True)

    assert result.events_scanned == 0
    assert result.alerts == []
    assert AlertStore(tmp_path / "alerts.db").count() == 0


def test_duplicate_events_are_reported_in_scan_stats(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    record = {
        "eventID": "same-event-1",
        "eventTime": "2026-03-02T10:00:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {"userName": "erin"},
    }
    payload = json.dumps({"Records": [record]})
    (raw / "delivery-a.json").write_text(payload, encoding="utf-8")
    (raw / "delivery-b.json").write_text(payload, encoding="utf-8")

    result = scan_files(raw, tmp_path / "alerts.db", reset=True)

    assert result.events_scanned == 1
    assert result.duplicate_events == 1
    assert result.summary()["duplicate_events"] == 1


def test_sample_data_triggers_every_detector(tmp_path):
    write_sample_data(tmp_path)
    events = load_events(tmp_path)

    alerts = collect_alerts(events, Config())

    detectors = {alert.detector for alert in alerts}
    assert detectors == {
        "brute_force",
        "public_storage",
        "iam_permissions",
        "impossible_travel",
    }
    assert any(alert.severity == Severity.CRITICAL for alert in alerts)
    assert any(alert.severity == Severity.HIGH for alert in alerts)
    assert len(events) > 100


def test_cloudtrail_sample_is_ingested(tmp_path):
    write_sample_data(tmp_path)
    events = load_events(tmp_path / "cloudtrail_sample.json")

    assert not events.empty
    assert (events["event_source"] == "iam.amazonaws.com").any()
    assert (events["status"] == "failure").any()

    alerts = collect_alerts(events, Config())
    entities = {alert.entity for alert in alerts}
    assert "frank" in entities  # brute force
    assert "ct-public-artifacts" in entities  # public bucket
    assert "ct-deploy" in entities  # admin policy
