"""Near-real-time ingestion.

CloudSentinel is batch-first, but audit pipelines deliver records continuously:
an EventBridge rule posts CloudTrail records to an HTTPS endpoint, or a log
shipper drops files into a directory. :class:`StreamProcessor` accepts those
records in small batches, keeps a short rolling window of recent events so
window-based detectors (brute force, impossible travel) still have context,
de-duplicates by event ID across batches, and persists only the alerts that the
new batch touched.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

import pandas as pd

from .config import Config
from .db import AlertStore
from .detectors import run_all
from .ingest import EVENT_COLUMNS, load_events, read_records, records_to_dataframe
from .models import Alert
from .paths import SUPPORTED_SUFFIXES
from .utils import to_iso, utcnow

logger = logging.getLogger(__name__)

# Event IDs created by ``records_to_dataframe`` for records without one.
_SYNTHETIC_ID = r"^evt-\d+$"


@dataclass
class StreamStats:
    """Counters for one :class:`StreamProcessor` lifetime."""

    batches: int = 0
    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    dropped: int = 0
    alerts: int = 0
    inserted: int = 0
    updated: int = 0
    merged: int = 0
    buffered: int = 0
    last_batch: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "batches": self.batches,
            "received": self.received,
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "dropped": self.dropped,
            "alerts": self.alerts,
            "inserted": self.inserted,
            "updated": self.updated,
            "merged": self.merged,
            "buffered": self.buffered,
            "last_batch": self.last_batch,
        }


class StreamProcessor:
    """Rolling-window event buffer that detects and persists alerts."""

    def __init__(
        self,
        store: AlertStore,
        config: Config | None = None,
        *,
        window_minutes: int | None = None,
        max_events: int | None = None,
        max_seen_ids: int | None = None,
    ) -> None:
        self.store = store
        self.config = config or Config()
        window = (
            self.config.stream.window_minutes
            if window_minutes is None
            else window_minutes
        )
        if window < 1:
            raise ValueError("stream window must be at least 1 minute")
        self.window = timedelta(minutes=window)

        limit = self.config.stream.max_events if max_events is None else max_events
        if limit < 100:
            raise ValueError("stream buffer must keep at least 100 events")
        self.max_events = limit
        self.max_seen_ids = max(1000, max_seen_ids or self.max_events * 2)
        self.stats = StreamStats()
        self._buffer = pd.DataFrame(columns=EVENT_COLUMNS)
        self._seen: set[str] = set()
        self._seen_order: deque[str] = deque()
        self.store.init()

    # ------------------------------------------------------------------ ingest

    def feed(self, records: Iterable[Any]) -> list[Alert]:
        """Normalise and detect one batch, returning the alerts it touched."""

        records = list(records)
        self.stats.batches += 1
        self.stats.received += len(records)
        self.stats.last_batch = to_iso(utcnow())

        frame = records_to_dataframe(records)
        self.stats.dropped += int(frame.attrs.get("dropped", 0))
        if frame.empty:
            self._remember_buffer_size()
            return []

        frame = self._unique_ids(frame)

        ids = frame["event_id"].astype(str)
        fresh = frame[~ids.isin(self._seen)].copy()
        self.stats.duplicates += int(len(frame) - len(fresh))
        if fresh.empty:
            self._remember_buffer_size()
            return []

        for event_id in fresh["event_id"].astype(str):
            self._remember(str(event_id))
        self.stats.accepted += len(fresh)

        horizon = fresh["timestamp"].min().to_pydatetime()
        self._append(fresh)

        alerts = run_all(self._buffer, self.config)
        touched = [alert for alert in alerts if alert.last_seen >= horizon]
        touched.sort(key=lambda alert: (-alert.severity.score, alert.first_seen))

        result = self.store.upsert_many(
            touched, suppression_minutes=self.config.suppression_minutes
        )
        self.stats.alerts += len(touched)
        self.stats.inserted += result["inserted"]
        self.stats.updated += result["updated"]
        self.stats.merged += result["merged"]
        self._remember_buffer_size()
        return touched

    def feed_files(self, paths: Sequence[str | Path]) -> list[Alert]:
        """Read every supported file in *paths* and feed its records."""

        records: list[Any] = []
        for path in paths:
            try:
                records.extend(read_records(path))
            except (OSError, ValueError) as exc:
                logger.warning("Skipping %s (%s)", path, exc)
        if not records:
            return []
        return self.feed(records)

    @property
    def buffered(self) -> int:
        return int(len(self._buffer))

    # ------------------------------------------------------------------ window

    def _append(self, frame: pd.DataFrame) -> None:
        if self._buffer.empty:
            self._buffer = frame.reset_index(drop=True)
        else:
            self._buffer = pd.concat(
                [self._buffer, frame], ignore_index=True
            )
        self._prune()

    def _prune(self) -> None:
        """Keep only the newest window of events."""

        if self._buffer.empty:
            return
        newest = self._buffer["timestamp"].max()
        frame = self._buffer[self._buffer["timestamp"] >= newest - self.window]
        if len(frame) > self.max_events:
            frame = frame.tail(self.max_events)
        self._buffer = frame.sort_values("timestamp").reset_index(drop=True)

    def _unique_ids(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Derive stable IDs for records that arrived without one.

        A content hash means a retried webhook batch (or a re-read file) maps to
        the same IDs and is discarded by the de-duplication step.
        """

        frame = frame.copy()
        ids = frame["event_id"].astype(str)
        synthetic = ids.str.match(_SYNTHETIC_ID)
        for position in frame.index[synthetic]:
            raw = frame.at[position, "raw"]
            payload = json.dumps(raw, sort_keys=True, default=str)
            digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
            frame.at[position, "event_id"] = f"evt-{digest}"
        return frame

    def _remember(self, event_id: str) -> None:
        if not event_id or event_id in self._seen:
            return
        self._seen.add(event_id)
        self._seen_order.append(event_id)
        while len(self._seen_order) > self.max_seen_ids:
            self._seen.discard(self._seen_order.popleft())

    def _remember_buffer_size(self) -> None:
        self.stats.buffered = self.buffered


class DirectoryWatcher:
    """Detect new or modified supported log files under one directory."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._signatures: dict[Path, tuple[int, int]] = {}

    def poll(self) -> list[Path]:
        """Return files that changed since the previous poll.

        The first poll returns every existing file so a restart replays the
        backlog (record-level de-duplication makes the replay cheap).
        """

        if not self.path.is_dir():
            return []

        current: dict[Path, tuple[int, int]] = {}
        for candidate in sorted(self.path.rglob("*")):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            try:
                stat = candidate.stat()
            except OSError:
                continue
            current[candidate] = (stat.st_mtime_ns, stat.st_size)

        changed = [
            path
            for path, signature in current.items()
            if self._signatures.get(path) != signature
        ]
        self._signatures = current
        return changed


def watch_directory(
    processor: StreamProcessor,
    watcher: DirectoryWatcher,
    *,
    interval: float = 5.0,
    max_polls: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    on_batch: Callable[[list[Path], list[Alert]], None] | None = None,
) -> StreamStats:
    """Poll *watcher*, feed changed files and optionally call *on_batch*.

    Runs until *max_polls* polls have completed (``None`` means forever, which
    is what the ``watch`` CLI command uses until Ctrl+C).
    """

    polls = 0
    try:
        while max_polls is None or polls < max_polls:
            polls += 1
            paths = watcher.poll()
            alerts: list[Alert] = []
            if paths:
                alerts = processor.feed_files(paths)
            if on_batch is not None:
                on_batch(paths, alerts)
            if max_polls is None or polls < max_polls:
                sleep(interval)
    except KeyboardInterrupt:  # pragma: no cover - interactive path
        logger.info("Watch stopped by user")
    return processor.stats


def iter_directory_records(path: str | Path) -> Iterator[Any]:
    """Yield raw records from every supported file under *path* once."""

    frame = load_events(path)
    for record in frame["raw"].tolist():
        yield record
