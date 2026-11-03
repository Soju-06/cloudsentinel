"""Near-real-time streaming ingestion tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from cloudsentinel.config import Config
from cloudsentinel.db import AlertStore
from cloudsentinel.stream import (
    DirectoryWatcher,
    StreamProcessor,
    iter_directory_records,
    watch_directory,
)

BASE = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


def _failure(offset_seconds=0, *, user="carol", ip="203.0.113.50", event_id=None):
    record = {
        "timestamp": (BASE + timedelta(seconds=offset_seconds)).isoformat(),
        "event_source": "aws.signin",
        "event_name": "ConsoleLogin",
        "user": user,
        "source_ip": ip,
        "status": "failure",
        "error_code": "Failed authentication",
    }
    if event_id is not None:
        record["event_id"] = event_id
    return record


def _processor(tmp_path, **overrides):
    settings = {
        "brute_force": {"threshold": 5, "window_minutes": 10},
        "suppression_minutes": 0,
    }
    settings.update(overrides)
    store = AlertStore(tmp_path / "stream.db")
    return StreamProcessor(store, Config.from_dict(settings))


def test_burst_is_detected_when_it_spans_two_batches(tmp_path):
    processor = _processor(tmp_path)

    assert processor.feed([_failure(i) for i in range(3)]) == []

    alerts = processor.feed([_failure(i) for i in range(3, 6)])

    assert len(alerts) == 1
    assert alerts[0].detector == "brute_force"
    assert alerts[0].event_count == 6
    assert alerts[0].severity.value == "high"
    assert processor.store.count() == 1
    assert processor.stats.accepted == 6
    assert processor.stats.batches == 2


def test_duplicate_event_ids_are_discarded_across_batches(tmp_path):
    processor = _processor(tmp_path)
    records = [_failure(i, event_id=f"evt-{i}") for i in range(5)]

    assert len(processor.feed(records)) == 1
    assert processor.feed(records) == []

    assert processor.stats.received == 10
    assert processor.stats.accepted == 5
    assert processor.stats.duplicates == 5
    assert processor.store.count() == 1


def test_records_without_ids_are_deduped_by_content(tmp_path):
    processor = _processor(tmp_path)
    records = [_failure(0), _failure(60, ip="198.51.100.9")]

    processor.feed(records)
    processor.feed([dict(record) for record in records])

    assert processor.stats.accepted == 2
    assert processor.stats.duplicates == 2
    assert processor.buffered == 2


def test_rolling_window_drops_stale_events(tmp_path):
    processor = _processor(tmp_path, stream={"window_minutes": 1})

    assert len(processor.feed([_failure(i) for i in range(5)])) == 1
    assert processor.buffered == 5

    # One hour later the old burst is outside the window, so three failures do
    # not inherit the earlier context (and the stored alert is untouched).
    later = [_failure(3600 + i, user="dave") for i in range(3)]
    assert processor.feed(later) == []
    assert processor.buffered == 3


def test_buffer_size_is_capped(tmp_path):
    processor = _processor(tmp_path, stream={"max_events": 100})
    processor.feed([_failure(i, user=f"user-{i}") for i in range(150)])

    assert processor.buffered == 100


def test_disabled_detector_produces_no_alerts(tmp_path):
    processor = _processor(
        tmp_path, brute_force={"enabled": False, "threshold": 5}
    )

    assert processor.feed([_failure(i) for i in range(6)]) == []
    assert processor.stats.accepted == 6


def test_feed_files_reads_jsonl_and_skips_broken_files(tmp_path):
    processor = _processor(tmp_path)
    good = tmp_path / "events.jsonl"
    good.write_text(
        "\n".join(json.dumps(_failure(i)) for i in range(5)), encoding="utf-8"
    )
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    alerts = processor.feed_files([broken, good])

    assert len(alerts) == 1
    assert processor.stats.accepted == 5


def test_directory_watcher_detects_new_and_changed_files(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    first = raw / "a.json"
    first.write_text("[]", encoding="utf-8")

    watcher = DirectoryWatcher(raw)
    assert watcher.poll() == [first]
    assert watcher.poll() == []

    first.write_text(json.dumps([_failure(0)]), encoding="utf-8")
    assert watcher.poll() == [first]

    second = raw / "b.jsonl"
    second.write_text("", encoding="utf-8")
    assert watcher.poll() == [second]


def test_directory_watcher_ignores_unsupported_files(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "notes.txt").write_text("ignore me", encoding="utf-8")

    assert DirectoryWatcher(raw).poll() == []


def test_watch_directory_feeds_changed_files_only(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "batch.json").write_text(
        json.dumps([_failure(i) for i in range(5)]), encoding="utf-8"
    )

    processor = _processor(tmp_path)
    seen = []

    stats = watch_directory(
        processor,
        DirectoryWatcher(raw),
        interval=0,
        max_polls=3,
        sleep=lambda seconds: None,
        on_batch=lambda paths, alerts: seen.append((len(paths), len(alerts))),
    )

    assert stats.accepted == 5
    assert processor.store.count() == 1
    assert seen == [(1, 1), (0, 0), (0, 0)]


def test_iter_directory_records_yields_raw_payloads(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "batch.json").write_text(
        json.dumps([_failure(0), _failure(1)]), encoding="utf-8"
    )

    records = list(iter_directory_records(raw))

    assert len(records) == 2
    assert records[0]["user"] == "carol"


def test_invalid_stream_settings_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        StreamProcessor(
            AlertStore(tmp_path / "bad.db"),
            Config(),
            window_minutes=0,
        )
    with pytest.raises(ValueError):
        StreamProcessor(
            AlertStore(tmp_path / "bad.db"),
            Config(),
            max_events=10,
        )
