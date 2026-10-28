"""SQLite alert store tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloudsentinel.db import AlertStore
from cloudsentinel.severity import Severity

BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_insert_and_count(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()

    action, alert_id = store.upsert(make_alert())

    assert action == "inserted"
    assert alert_id > 0
    assert store.count() == 1


def test_rerun_updates_instead_of_duplicating(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    alert = make_alert()

    assert store.upsert(alert)[0] == "inserted"
    assert store.upsert(alert)[0] == "updated"
    assert store.count() == 1


def test_nearby_alert_is_merged(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    first = make_alert(event_count=5)
    second = make_alert(
        first_seen=BASE + timedelta(minutes=20),
        last_seen=BASE + timedelta(minutes=25),
        event_count=3,
    )

    assert store.upsert(first, suppression_minutes=60)[0] == "inserted"
    assert store.upsert(second, suppression_minutes=60)[0] == "merged"

    stored = store.fetch_alerts()[0]
    assert store.count() == 1
    assert stored.event_count == 8
    assert stored.last_seen == second.last_seen


def test_alerts_outside_suppression_are_separate(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    first = make_alert()
    second = make_alert(
        first_seen=BASE + timedelta(hours=3),
        last_seen=BASE + timedelta(hours=3, minutes=5),
    )

    store.upsert(first, suppression_minutes=60)
    store.upsert(second, suppression_minutes=60)

    assert store.count() == 2


def test_fetch_filters_by_severity_and_detector(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    store.upsert(make_alert(severity=Severity.CRITICAL, entity="carol"))
    store.upsert(
        make_alert(
            severity=Severity.MEDIUM,
            detector="public_storage",
            entity="bucket",
            entity_type="storage",
        )
    )

    assert len(store.fetch_alerts(severity="critical")) == 1
    assert len(store.fetch_alerts(detector="public_storage")) == 1
    assert len(store.fetch_alerts(search="carol")) == 1
    assert len(store.fetch_alerts(search="nothing-here")) == 0
    assert len(store.fetch_alerts()) == 2


def test_fetch_sorted_critical_first(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    store.upsert(make_alert(severity=Severity.LOW, entity="low"))
    store.upsert(make_alert(severity=Severity.CRITICAL, entity="crit"))
    store.upsert(make_alert(severity=Severity.HIGH, entity="high"))

    severities = [alert.severity for alert in store.fetch_alerts()]

    assert severities == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]


def test_stats(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    store.upsert(make_alert(severity=Severity.CRITICAL, entity="a"))
    store.upsert(make_alert(severity=Severity.HIGH, entity="b"))

    stats = store.stats()

    assert stats["total"] == 2
    assert stats["by_severity"]["critical"] == 1
    assert stats["entities"] == 2
    assert stats["latest_update"] is not None


def test_clear(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    store.upsert(make_alert())

    assert store.clear() == 1
    assert store.count() == 0


def test_evidence_roundtrip(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    store.upsert(make_alert(evidence={"event_ids": ["a", "b"], "count": 2}))

    stored = store.fetch_alerts()[0]

    assert stored.evidence["event_ids"] == ["a", "b"]
    assert stored.evidence["count"] == 2
