"""Deterministic synthetic audit data used for demos and manual testing.

The generated files intentionally contain a mix of benign activity and
realistic incident patterns so every detector has something to find:

* credential-stuffing bursts against two users (one followed by a success)
* a public bucket policy and a public-read ACL
* a wildcard IAM policy and an administrative managed-policy attachment
* MFA removal, access-key creation, root usage, an open SSH rule and
  CloudTrail logging being stopped
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .paths import RAW_DIR

_USERS = ["alice", "bob", "carol", "dave", "erin", "svc-backup", "svc-ci"]
_NORMAL_IPS = ["10.0.4.12", "10.0.4.18", "10.0.4.22", "192.0.2.44"]


def build_generic_events(seed: int = 1337, days: int = 7, noise: int = 140) -> list[dict]:
    rng = random.Random(seed)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(days=days)
    events: list[dict[str, Any]] = []

    def emit(
        moment: datetime,
        source: str,
        name: str,
        user: str,
        ip: str,
        resource: str = "",
        status: str = "success",
        error_code: str = "",
        geo: dict[str, Any] | None = None,
        **params: Any,
    ) -> None:
        record: dict[str, Any] = {
            "timestamp": moment.isoformat(timespec="seconds"),
            "event_source": source,
            "event_name": name,
            "user": user,
            "source_ip": ip,
            "resource": resource,
            "status": status,
            "error_code": error_code,
        }
        if geo:
            record.update(geo)
        if params:
            record["request_parameters"] = params
        events.append(record)

    # ---------------------------------------------------------- benign noise
    normal_actions = [
        ("aws.s3", "GetObject", "reports"),
        ("aws.s3", "ListBucket", "reports"),
        ("aws.s3", "PutObject", "reports"),
        ("aws.ec2", "DescribeInstances", "i-0a1b2c3d"),
        ("aws.iam", "GetUser", ""),
        ("aws.cloudtrail", "LookupEvents", ""),
        ("aws.lambda", "InvokeFunction", "report-builder"),
    ]
    for _ in range(noise):
        source, action, resource = rng.choice(normal_actions)
        moment = start + timedelta(seconds=rng.randint(0, days * 86_400))
        failed = rng.random() < 0.06 and action == "GetObject"
        emit(
            moment,
            source,
            action,
            rng.choice(_USERS),
            rng.choice(_NORMAL_IPS),
            resource=resource,
            status="failure" if failed else "success",
            error_code="AccessDenied" if failed else "",
        )

    # ------------------------------------------- critical credential attack
    carol_burst = start + timedelta(days=2, hours=9)
    emit(
        carol_burst - timedelta(minutes=70),
        "aws.signin",
        "ConsoleLogin",
        "carol",
        "10.0.4.18",
        status="success",
        geo={
            "country": "United States",
            "city": "Ashburn",
            "latitude": 39.0438,
            "longitude": -77.4874,
        },
    )
    for index in range(18):
        emit(
            carol_burst + timedelta(seconds=index * 27),
            "aws.signin",
            "ConsoleLogin",
            "carol",
            "203.0.113.50",
            status="failure",
            error_code="Failed authentication",
        )
    emit(
        carol_burst + timedelta(minutes=11),
        "aws.signin",
        "ConsoleLogin",
        "carol",
        "203.0.113.50",
        status="success",
        geo={
            "country": "Russia",
            "city": "Moscow",
            "latitude": 55.7558,
            "longitude": 37.6173,
        },
    )

    # --------------------------------------------- high-volume failed logins
    bob_burst = start + timedelta(days=4, hours=17)
    for index in range(6):
        emit(
            bob_burst + timedelta(seconds=index * 41),
            "aws.signin",
            "ConsoleLogin",
            "bob",
            "198.51.100.23",
            status="failure",
            error_code="Failed authentication",
        )

    # --------------------------------------------------- public storage risk
    emit(
        start + timedelta(days=3, hours=11),
        "aws.s3",
        "PutBucketPolicy",
        "alice",
        "10.0.4.12",
        resource="acme-backups",
        bucketName="acme-backups",
        bucketPolicy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::acme-backups/*",
                }
            ],
        },
    )
    emit(
        start + timedelta(days=3, hours=12),
        "aws.s3",
        "PutBucketAcl",
        "bob",
        "10.0.4.18",
        resource="acme-marketing",
        bucketName="acme-marketing",
        acl="public-read",
    )

    # -------------------------------------------------- excessive IAM grants
    emit(
        start + timedelta(days=5, hours=10),
        "aws.iam",
        "PutRolePolicy",
        "alice",
        "10.0.4.12",
        resource="ci-deployer",
        roleName="ci-deployer",
        policyName="deployer-everything",
        policyDocument={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ],
        },
    )
    emit(
        start + timedelta(days=5, hours=13),
        "aws.iam",
        "AttachUserPolicy",
        "dave",
        "10.0.4.22",
        resource="dave",
        userName="dave",
        policyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    # ------------------------------------------------------ identity attacks
    emit(
        start + timedelta(days=5, hours=16),
        "aws.iam",
        "DeactivateMFADevice",
        "alice",
        "10.0.4.12",
        resource="bob",
        userName="bob",
        serialNumber="arn:aws:iam::123456789012:mfa/bob",
    )
    emit(
        start + timedelta(days=5, hours=17),
        "aws.iam",
        "CreateAccessKey",
        "alice",
        "10.0.4.12",
        resource="carol",
        userName="carol",
    )
    emit(
        start + timedelta(days=6, hours=2),
        "aws.signin",
        "ConsoleLogin",
        "root",
        "198.51.100.77",
        status="success",
    )
    emit(
        start + timedelta(days=6, hours=3),
        "aws.iam",
        "CreateAccessKey",
        "root",
        "198.51.100.77",
        resource="root",
        userName="root",
    )

    # ------------------------------------------------------ network exposure
    emit(
        start + timedelta(days=6, hours=5),
        "aws.ec2",
        "AuthorizeSecurityGroupIngress",
        "bob",
        "10.0.4.18",
        resource="sg-0a1b2c3d",
        groupId="sg-0a1b2c3d",
        ipPermissions={
            "items": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                }
            ]
        },
    )

    # -------------------------------------------------- audit-log tampering
    emit(
        start + timedelta(days=6, hours=6),
        "aws.cloudtrail",
        "StopLogging",
        "dave",
        "10.0.4.22",
        resource="acme-trail",
        trailName="acme-trail",
    )

    events.sort(key=lambda item: item["timestamp"])
    return events


def build_cloudtrail_events(seed: int = 1337) -> list[dict]:
    """CloudTrail-shaped records to exercise the AWS adapter."""

    rng = random.Random(seed + 1)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(days=5)
    records: list[dict[str, Any]] = []
    counter = {"value": 0}

    def emit(
        moment: datetime,
        name: str,
        user: str,
        ip: str,
        *,
        source: str = "s3.amazonaws.com",
        error_code: str = "",
        request_parameters: dict[str, Any] | None = None,
        resources: list[dict[str, str]] | None = None,
        identity: dict[str, Any] | None = None,
    ) -> None:
        counter["value"] += 1
        record: dict[str, Any] = {
            "eventVersion": "1.09",
            "eventID": f"ct-{seed}-{counter['value']:05d}",
            "eventTime": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": source,
            "eventName": name,
            "awsRegion": "us-east-1",
            "sourceIPAddress": ip,
            "userIdentity": identity
            or {
                "type": "IAMUser",
                "principalId": f"AIDA{seed}{counter['value']:04d}",
                "arn": f"arn:aws:iam::123456789012:user/{user}",
                "userName": user,
            },
            "userAgent": "aws-cli/2.17.0 Python/3.12 boto3/1.34",
        }
        if error_code:
            record["errorCode"] = error_code
            record["errorMessage"] = "Failed authentication"
        if request_parameters is not None:
            record["requestParameters"] = request_parameters
        if resources is not None:
            record["resources"] = resources
        records.append(record)

    # Brute force against a second identity, followed by a success.
    burst = start + timedelta(days=1, hours=20)
    for index in range(7):
        emit(
            burst + timedelta(seconds=index * 32),
            "ConsoleLogin",
            "frank",
            "203.0.113.99",
            source="signin.amazonaws.com",
            error_code="Failed authentication",
            request_parameters={"loginTo": "https://console.aws.amazon.com/"},
        )
    emit(
        burst + timedelta(minutes=7),
        "ConsoleLogin",
        "frank",
        "203.0.113.99",
        source="signin.amazonaws.com",
        request_parameters={"loginTo": "https://console.aws.amazon.com/"},
    )

    # Public bucket policy (CloudTrail URL-encodes the policy document).
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "*",
                "Resource": "arn:aws:s3:::ct-public-artifacts/*",
            }
        ],
    }
    emit(
        start + timedelta(days=2, hours=14),
        "PutBucketPolicy",
        "grace",
        "203.0.113.10",
        request_parameters={
            "bucketName": "ct-public-artifacts",
            "bucketPolicy": quote(json.dumps(public_policy)),
        },
    )

    # Administrative managed policy attached to a deployment role.
    emit(
        start + timedelta(days=3, hours=9),
        "AttachRolePolicy",
        "heidi",
        "203.0.113.11",
        source="iam.amazonaws.com",
        request_parameters={
            "roleName": "ct-deploy",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
    )

    # MFA removed for a different user.
    emit(
        start + timedelta(days=3, hours=12),
        "DeactivateMFADevice",
        "heidi",
        "203.0.113.11",
        source="iam.amazonaws.com",
        request_parameters={"userName": "grace"},
    )

    # Access key created for a different user.
    emit(
        start + timedelta(days=3, hours=13),
        "CreateAccessKey",
        "frank",
        "203.0.113.99",
        source="iam.amazonaws.com",
        request_parameters={"userName": "grace"},
    )

    # Root user stopping audit logging.
    emit(
        start + timedelta(days=4, hours=2),
        "StopLogging",
        "root",
        "198.51.100.77",
        source="cloudtrail.amazonaws.com",
        request_parameters={"name": "ct-audit-trail"},
        identity={
            "type": "Root",
            "principalId": "123456789012",
            "arn": "arn:aws:iam::123456789012:root",
            "accountId": "123456789012",
        },
    )

    # SSH open to the internet added through the CLI/SDK list shape.
    emit(
        start + timedelta(days=4, hours=4),
        "AuthorizeSecurityGroupIngress",
        "grace",
        "203.0.113.10",
        source="ec2.amazonaws.com",
        request_parameters={
            "groupId": "sg-ct-open",
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {
                            "items": [{"cidrIp": "0.0.0.0/0"}],
                        },
                    }
                ]
            },
        },
    )

    # Benign traffic.
    for _ in range(30):
        moment = start + timedelta(seconds=rng.randint(0, 5 * 86_400))
        action = rng.choice(["DescribeInstances", "GetObject", "ListBuckets"])
        source = "ec2.amazonaws.com" if action == "DescribeInstances" else "s3.amazonaws.com"
        params = (
            {"bucketName": "ct-artifacts"} if action in {"GetObject", "ListBuckets"} else {}
        )
        emit(
            moment,
            action,
            rng.choice(["grace", "frank", "heidi"]),
            rng.choice(["10.0.8.5", "10.0.8.9"]),
            source=source,
            request_parameters=params,
        )

    records.sort(key=lambda item: item["eventTime"])
    return records


def write_sample_data(
    out_dir: str | Path | None = None, seed: int = 1337
) -> list[Path]:
    destination = Path(out_dir or RAW_DIR)
    destination.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    generic_path = destination / "sample_logs.json"
    generic_path.write_text(
        json.dumps(build_generic_events(seed), indent=2), encoding="utf-8"
    )
    created.append(generic_path)

    cloudtrail_path = destination / "cloudtrail_sample.json"
    cloudtrail_path.write_text(
        json.dumps({"Records": build_cloudtrail_events(seed)}, indent=2),
        encoding="utf-8",
    )
    created.append(cloudtrail_path)

    return created


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate CloudSentinel sample logs")
    parser.add_argument("-o", "--out-dir", default=str(RAW_DIR))
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args(argv)

    for path in write_sample_data(args.out_dir, seed=args.seed):
        print(f"Generated {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
