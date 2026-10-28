"""Shared pytest fixtures and helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from cloudsentinel.ingest import records_to_dataframe
from cloudsentinel.models import Alert
from cloudsentinel.severity import Severity

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def build_events():
    """Build a normalised event DataFrame from compact dicts.

    Supported keys mirror the canonical schema. ``offset`` is seconds after a
    fixed UTC base timestamp, which keeps window tests readable.
    """

    def build(rows: list[dict]) -> pd.DataFrame:
        records = []
        for row in rows:
            data = dict(row)
            offset = data.pop("offset", 0)
            moment = data.pop("timestamp", None) or (BASE + timedelta(seconds=offset))
            record = {
                "timestamp": moment.isoformat()
                if isinstance(moment, datetime)
                else moment,
                "event_source": data.pop("event_source", "aws.signin"),
                "event_name": data.pop("event_name", "ConsoleLogin"),
                "user": data.pop("user", "alice"),
                "source_ip": data.pop("source_ip", "10.0.0.1"),
                "resource": data.pop("resource", ""),
                "status": data.pop("status", "failure"),
                "error_code": data.pop("error_code", ""),
                "request_parameters": data.pop("request_parameters", {}),
            }
            record.update(data)
            records.append(record)
        return records_to_dataframe(records)

    return build


@pytest.fixture
def make_alert():
    def factory(**overrides) -> Alert:
        values = {
            "detector": "brute_force",
            "severity": Severity.HIGH,
            "title": "Repeated failed logins",
            "description": "5 failed login attempts.",
            "entity": "alice",
            "entity_type": "user",
            "event_count": 5,
            "first_seen": BASE,
            "last_seen": BASE + timedelta(minutes=5),
            "evidence": {"event_ids": ["evt-1"]},
        }
        values.update(overrides)
        return Alert(**values)

    return factory
