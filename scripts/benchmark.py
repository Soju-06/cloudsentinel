"""Benchmark ingestion, detection and persistence on large synthetic logs.

Usage:
    python scripts/benchmark.py --events 100000
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cloudsentinel.config import Config  # noqa: E402
from cloudsentinel.db import AlertStore  # noqa: E402
from cloudsentinel.ingest import load_events  # noqa: E402
from cloudsentinel.pipeline import collect_alerts, run_scan  # noqa: E402


def generate(path: Path, count: int, seed: int = 7) -> None:
    rng = random.Random(seed)
    base = datetime.now(timezone.utc) - timedelta(days=7)
    users = [f"user{index:03d}" for index in range(200)]
    ips = [f"10.0.{index // 10}.{index % 250}" for index in range(60)]
    actions = [
        ("aws.s3", "GetObject", "reports"),
        ("aws.s3", "PutObject", "reports"),
        ("aws.ec2", "DescribeInstances", "i-01"),
        ("aws.lambda", "InvokeFunction", "builder"),
        ("aws.iam", "GetUser", ""),
        ("aws.cloudtrail", "LookupEvents", ""),
    ]
    buckets = ["reports", "artifacts", "backups", "logs"]

    events = []
    for index in range(count):
        source, name, resource = actions[index % len(actions)]
        moment = base + timedelta(seconds=rng.randint(0, 7 * 86_400))
        status = "failure" if index % 97 == 0 and name == "GetObject" else "success"
        events.append(
            {
                "timestamp": moment.isoformat(timespec="seconds"),
                "event_source": source,
                "event_name": name,
                "user": rng.choice(users),
                "source_ip": rng.choice(ips),
                "resource": resource,
                "status": status,
                "error_code": "AccessDenied" if status == "failure" else "",
                "bucketName": rng.choice(buckets),
            }
        )

    # Seed a handful of findings so detectors do real work.
    attack = base + timedelta(days=3, hours=12)
    for index in range(18):
        events.append(
            {
                "timestamp": (attack + timedelta(seconds=index * 25)).isoformat(),
                "event_source": "aws.signin",
                "event_name": "ConsoleLogin",
                "user": "attacked-user",
                "source_ip": "203.0.113.77",
                "resource": "",
                "status": "failure",
                "error_code": "Failed authentication",
            }
        )
    events.append(
        {
            "timestamp": (attack + timedelta(days=1)).isoformat(),
            "event_source": "aws.s3",
            "event_name": "PutBucketPolicy",
            "user": "user000",
            "source_ip": "10.0.0.1",
            "resource": "public-demo",
            "status": "success",
            "request_parameters": {
                "bucketName": "public-demo",
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
        }
    )

    path.write_text(json.dumps(events), encoding="utf-8")


def _timed(callable_, repeats: int) -> tuple[float, float, object]:
    """Run *callable_* several times and return (median, best, last result)."""

    timings: list[float] = []
    result: object = None
    for _ in range(max(repeats, 1)):
        start = time.perf_counter()
        result = callable_()
        timings.append(time.perf_counter() - start)
    return statistics.median(timings), min(timings), result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloudSentinel benchmark")
    parser.add_argument("--events", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="run each phase N times and report the median",
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="cloudsentinel-bench-") as tmp:
        tmp_path = Path(tmp)
        raw = tmp_path / "events.json"
        print(f"Generating {args.events:,} events …")
        generate(raw, args.events, seed=args.seed)
        size_mb = raw.stat().st_size / (1024 * 1024)
        print(f"  file size: {size_mb:.1f} MB")

        load_seconds, load_best, events = _timed(
            lambda: load_events(raw), args.repeats
        )

        detect_seconds, detect_best, alerts = _timed(
            lambda: collect_alerts(events, Config()), args.repeats
        )

        def persist() -> object:
            return run_scan(
                events, AlertStore(tmp_path / "alerts.db"), Config(), alerts=alerts
            )

        persist_seconds, persist_best, result = _timed(persist, args.repeats)

        total = load_seconds + detect_seconds + persist_seconds

        print()
        print(f"Events loaded      : {len(events):,}")
        print(f"Alerts detected    : {len(alerts)}")
        print(f"Repeats            : {max(args.repeats, 1)} (median reported)")
        print(f"Ingest             : {load_seconds:6.2f}s  (best {load_best:.2f}s)")
        print(f"Detect             : {detect_seconds:6.2f}s  (best {detect_best:.2f}s)")
        print(f"Persist (SQLite)   : {persist_seconds:6.2f}s  (best {persist_best:.2f}s)")
        print(f"Total (median)     : {total:6.2f}s")
        if load_seconds:
            print(f"Ingest throughput  : {len(events) / load_seconds:,.0f} events/s")
        if total:
            print(f"End-to-end         : {len(events) / total:,.0f} events/s")
        print(f"DB alerts          : {result.inserted + result.updated + result.merged}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
