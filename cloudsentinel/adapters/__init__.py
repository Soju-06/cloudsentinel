"""Adapters converting vendor audit-log formats to CloudSentinel's schema."""

from __future__ import annotations

from .cloudtrail import extract_records, looks_like_cloudtrail, map_record

__all__ = ["extract_records", "looks_like_cloudtrail", "map_record"]
