"""Excessive IAM permission detector tests."""

from __future__ import annotations

import json
from urllib.parse import quote

from cloudsentinel.detectors import detect_iam_permissions
from cloudsentinel.severity import Severity


def iam_event(build_events, **overrides):
    row = {
        "event_source": "aws.iam",
        "event_name": "PutRolePolicy",
        "user": "alice",
        "status": "success",
        "resource": "ci-deployer",
        "request_parameters": {
            "roleName": "ci-deployer",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            },
        },
    }
    row.update(overrides)
    return build_events([row])


def test_wildcard_action_and_resource_is_critical(build_events):
    alerts = detect_iam_permissions(iam_event(build_events))

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].entity == "ci-deployer"
    assert alerts[0].entity_type == "iam_principal"


def test_wildcard_action_only_is_high(build_events):
    events = iam_event(
        build_events,
        request_parameters={
            "roleName": "ci-deployer",
            "policyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "arn:aws:s3:::reports/*",
                    }
                ]
            },
        },
    )

    alerts = detect_iam_permissions(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH


def test_wildcard_resource_only_is_medium(build_events):
    events = iam_event(
        build_events,
        request_parameters={
            "roleName": "ci-deployer",
            "policyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ]
            },
        },
    )

    alerts = detect_iam_permissions(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.MEDIUM


def test_administrator_access_attachment_is_high(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.iam",
                "event_name": "AttachUserPolicy",
                "user": "dave",
                "status": "success",
                "resource": "dave",
                "request_parameters": {
                    "userName": "dave",
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
            }
        ]
    )

    alerts = detect_iam_permissions(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.HIGH
    assert alerts[0].entity == "dave"


def test_scoped_policy_is_ignored(build_events):
    events = iam_event(
        build_events,
        request_parameters={
            "roleName": "reader",
            "policyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::reports/*",
                    }
                ]
            },
        },
    )
    assert detect_iam_permissions(events) == []


def test_deny_statements_are_ignored(build_events):
    events = iam_event(
        build_events,
        request_parameters={
            "roleName": "guardrail",
            "policyDocument": {
                "Statement": [
                    {"Effect": "Deny", "Action": "*", "Resource": "*"}
                ]
            },
        },
    )
    assert detect_iam_permissions(events) == []


def test_url_encoded_cloudtrail_policy_is_decoded(build_events):
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    events = build_events(
        [
            {
                "event_source": "iam.amazonaws.com",
                "event_name": "PutRolePolicy",
                "user": "grace",
                "status": "success",
                "resource": "ct-deploy",
                "request_parameters": {
                    "roleName": "ct-deploy",
                    "policyDocument": quote(json.dumps(document)),
                },
            }
        ]
    )

    alerts = detect_iam_permissions(events)

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL
    assert alerts[0].entity == "ct-deploy"


def test_non_iam_events_do_not_trigger(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.s3",
                "event_name": "PutBucketPolicy",
                "status": "success",
                "resource": "bucket",
                "request_parameters": {
                    "bucketName": "bucket",
                    "bucketPolicy": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ]
                    },
                },
            }
        ]
    )
    assert detect_iam_permissions(events) == []


def test_multiple_findings_aggregate_per_principal(build_events):
    events = build_events(
        [
            {
                "event_source": "aws.iam",
                "event_name": "PutUserPolicy",
                "status": "success",
                "user": "alice",
                "offset": 0,
                "request_parameters": {
                    "userName": "alice",
                    "policyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"}
                        ]
                    },
                },
            },
            {
                "event_source": "aws.iam",
                "event_name": "AttachUserPolicy",
                "status": "success",
                "user": "alice",
                "offset": 60,
                "request_parameters": {
                    "userName": "alice",
                    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
            },
        ]
    )

    alerts = detect_iam_permissions(events)

    assert len(alerts) == 1
    assert alerts[0].entity == "alice"
    assert alerts[0].event_count == 2
    assert "administrative policy" in alerts[0].description


def test_empty_input():
    import pandas as pd

    assert detect_iam_permissions(pd.DataFrame()) == []
