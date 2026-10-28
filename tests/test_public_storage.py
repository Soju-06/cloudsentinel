"""Public storage detector tests."""

from __future__ import annotations

import pytest

from cloudsentinel.detectors import detect_public_storage
from cloudsentinel.severity import Severity


def s3_event(build_events, **overrides):
    row = {
        "event_source": "aws.s3",
        "event_name": "PutBucketPolicy",
        "user": "alice",
        "status": "success",
        "resource": "acme-backups",
    }
    row.update(overrides)
    return build_events([row])


def policy(**statement_overrides):
    statement = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::acme-backups/*",
    }
    statement.update(statement_overrides)
    return {
        "Version": "2012-10-17",
        "Statement": [statement],
    }


def test_public_principal_is_high(build_events):
    events = s3_event(
        build_events,
        request_parameters={
            "bucketName": "acme-backups",
            "bucketPolicy": policy(),
        },
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].entity == "acme-backups"
    assert alerts[0].entity_type == "storage"


def test_wildcard_public_policy_is_critical(build_events):
    events = s3_event(
        build_events,
        request_parameters={
            "bucketName": "acme-backups",
            "bucketPolicy": policy(Action="*", Resource="*"),
        },
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_public_read_acl_is_high(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "acme-marketing",
                "status": "success",
                "request_parameters": {
                    "bucketName": "acme-marketing",
                    "acl": "public-read",
                },
            }
        ]
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert "public-read" in alerts[0].description


def test_public_read_write_acl_is_critical(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "acme-data",
                "status": "success",
                "request_parameters": {"acl": "public-read-write"},
            }
        ]
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL


def test_authenticated_read_is_medium(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "acme-internal",
                "status": "success",
                "request_parameters": {"acl": "authenticated-read"},
            }
        ]
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM


def test_private_acl_is_ignored(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "acme-private",
                "status": "success",
                "request_parameters": {"acl": "private"},
            }
        ]
    )
    assert detect_public_storage(events) == []


def test_explicit_public_flag(build_events):
    events = build_events(
        [
            {
                "event_source": "generic.storage",
                "event_name": "UpdateContainer",
                "status": "success",
                "resource": "logs-container",
                "is_public": True,
            }
        ]
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_iam_public_trust_policy_not_flagged_as_storage(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.iam",
                "event_name": "PutRolePolicy",
                "status": "success",
                "resource": "ci-deployer",
                "request_parameters": {
                    "roleName": "ci-deployer",
                    "policyDocument": policy(),
                },
            }
        ]
    )
    assert detect_public_storage(events) == []


def test_events_grouped_per_bucket(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "bucket-a",
                "status": "success",
                "offset": 0,
                "request_parameters": {"acl": "public-read"},
            },
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "bucket-a",
                "status": "success",
                "offset": 60,
                "request_parameters": {"acl": "public-read"},
            },
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketAcl",
                "resource": "bucket-b",
                "status": "success",
                "offset": 120,
                "request_parameters": {"acl": "public-read"},
            },
        ]
    )

    alerts = detect_public_storage(events)

    assert len(alerts) == 2
    by_entity = {alert.entity: alert for alert in alerts}
    assert by_entity["bucket-a"].event_count == 2
    assert by_entity["bucket-b"].event_count == 1


def test_empty_input():
    import pandas as pd

    assert detect_public_storage(pd.DataFrame()) == []


@pytest.mark.parametrize(
    ("acl", "expected"),
    [
        ("public-read", Severity.HIGH),
        ("public-read-write", Severity.CRITICAL),
        ("authenticated-read", Severity.MEDIUM),
    ],
)
def test_acl_severity_matrix(build_events, acl, expected):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutObjectAcl",
                "resource": "matrix-bucket",
                "status": "success",
                "request_parameters": {"acl": acl},
            }
        ]
    )
    alerts = detect_public_storage(events)
    assert alerts and alerts[0].severity == expected
