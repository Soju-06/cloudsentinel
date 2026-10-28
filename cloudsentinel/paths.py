"""Canonical project paths, overridable via environment variables."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = Path(os.environ.get("CLOUDSENTINEL_DATA", PROJECT_ROOT / "data"))
RAW_DIR = Path(os.environ.get("CLOUDSENTINEL_RAW", DATA_DIR / "raw"))
DEFAULT_DB_PATH = Path(os.environ.get("CLOUDSENTINEL_DB", DATA_DIR / "sentinel.db"))
REPORTS_DIR = Path(os.environ.get("CLOUDSENTINEL_REPORTS", PROJECT_ROOT / "reports"))

CONFIG_CANDIDATES = (
    PROJECT_ROOT / "cloudsentinel.toml",
    PROJECT_ROOT / "config.json",
)

SUPPORTED_SUFFIXES = (".json", ".jsonl", ".ndjson", ".csv", ".gz")
