"""Read-only REST API plus an optional scan trigger.

The mobile app (and any SIEM/web client) talks to this service instead of
embedding Python on the device::

    python -m cloudsentinel serve --host 0.0.0.0 --port 8080 --token secret

Endpoints
---------
``GET  /health``          liveness probe (public)
``GET  /api/summary``     severity/detector totals
``GET  /api/alerts``      filtered, paginated alert list
``GET  /api/alerts/{id}`` one alert with evidence
``GET  /api/detectors``   detector metadata for client filters
``POST /api/scan``        re-scan the raw directory (opt-in)

Authentication uses a shared token in the ``X-API-Token`` header. When no
token is configured the API is open, which is only acceptable on a trusted
localhost/LAN.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .config import Config
from .db import AlertStore
from .paths import DEFAULT_DB_PATH, RAW_DIR
from .pipeline import scan_files
from .report import summary
from .severity import Severity
from .utils import parse_timestamp, to_iso, utcnow

DETECTORS = [
    {
        "name": "brute_force",
        "label": "Brute force",
        "description": "Repeated failed logins, including cross-IP bursts.",
    },
    {
        "name": "impossible_travel",
        "label": "Impossible travel",
        "description": "Consecutive logins faster than physical travel allows.",
    },
    {
        "name": "public_storage",
        "label": "Public storage",
        "description": "Buckets or objects exposed through policies or ACLs.",
    },
    {
        "name": "iam_permissions",
        "label": "IAM permissions",
        "description": "Wildcard or administrative permission grants.",
    },
]

_TRUTHY = {"1", "true", "yes", "on"}


def create_app(
    db_path: str | Path | None = None,
    raw_dir: str | Path | None = None,
    config: Config | None = None,
    token: str | None = None,
    allow_scan: bool = False,
    cors_origins: tuple[str, ...] = ("*",),
) -> FastAPI:
    """Build the FastAPI application (a factory keeps tests isolated)."""

    settings = config or Config.load()
    database = Path(
        db_path or os.environ.get("CLOUDSENTINEL_DB") or DEFAULT_DB_PATH
    )
    raw_directory = Path(
        raw_dir or os.environ.get("CLOUDSENTINEL_RAW") or RAW_DIR
    )
    expected_token = token if token is not None else os.environ.get(
        "CLOUDSENTINEL_API_TOKEN", ""
    )
    scan_enabled = allow_scan or os.environ.get(
        "CLOUDSENTINEL_API_ALLOW_SCAN", ""
    ).strip().lower() in _TRUTHY

    store = AlertStore(database)
    store.init()

    app = FastAPI(
        title="CloudSentinel API",
        version=__version__,
        description="Alert feed and summary for the CloudSentinel mobile client.",
    )
    app.state.store = store
    app.state.config = settings
    app.state.raw_dir = raw_directory
    app.state.scan_enabled = scan_enabled

    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["*"],
        )

    def require_token(
        x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
    ) -> None:
        if expected_token and not secrets.compare_digest(
            x_api_token or "", expected_token
        ):
            raise HTTPException(status_code=401, detail="invalid or missing API token")

    guarded = [Depends(require_token)]

    @app.get("/health", tags=["system"])
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "time": to_iso(utcnow()),
            "alerts": store.count(),
            "auth_required": bool(expected_token),
            "scan_enabled": scan_enabled,
        }

    @app.get("/api/summary", dependencies=guarded, tags=["alerts"])
    def api_summary() -> dict[str, Any]:
        alerts = store.fetch_alerts()
        payload = summary(alerts)
        payload.update(
            {
                "version": __version__,
                "server_time": to_iso(utcnow()),
                "database": store.stats(),
                "scan_enabled": scan_enabled,
            }
        )
        return payload

    @app.get("/api/alerts", dependencies=guarded, tags=["alerts"])
    def api_alerts(
        severity: Annotated[list[str] | None, Query()] = None,
        detector: Annotated[list[str] | None, Query()] = None,
        search: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        since_iso = _iso_or_400(since, "since")
        until_iso = _iso_or_400(until, "until")
        try:
            alerts = store.fetch_alerts(
                severity=severity or None,
                detector=detector or None,
                search=search or None,
                since=since_iso,
                until=until_iso,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        total = len(alerts)
        page = alerts[offset : offset + limit]
        return {
            "total": total,
            "count": len(page),
            "limit": limit,
            "offset": offset,
            "alerts": [alert.to_dict() for alert in page],
        }

    @app.get("/api/alerts/{alert_id}", dependencies=guarded, tags=["alerts"])
    def api_alert(alert_id: int) -> dict[str, Any]:
        alert = store.get(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert.to_dict()

    @app.get("/api/detectors", dependencies=guarded, tags=["meta"])
    def api_detectors() -> dict[str, Any]:
        return {
            "detectors": DETECTORS,
            "severities": [severity.value for severity in Severity],
        }

    @app.post("/api/scan", dependencies=guarded, tags=["scan"])
    def api_scan(reset: bool = False) -> dict[str, Any]:
        if not scan_enabled:
            raise HTTPException(
                status_code=403,
                detail="scan endpoint disabled; start the server with --allow-scan",
            )
        if not raw_directory.is_dir():
            raise HTTPException(
                status_code=400, detail=f"raw directory not found: {raw_directory}"
            )

        result = scan_files(raw_directory, database, settings, reset=reset)
        return {
            "status": "ok",
            "events_scanned": result.events_scanned,
            "alerts": len(result.alerts),
            "by_severity": result.by_severity,
            "inserted": result.inserted,
            "merged": result.merged,
            "updated": result.updated,
            "dropped_events": result.dropped_events,
            "duplicate_events": result.duplicate_events,
            "files": result.files,
        }

    return app


def _iso_or_400(value: str | None, field: str) -> str | None:
    if not value:
        return None
    parsed = parse_timestamp(value)
    if parsed is None:
        raise HTTPException(status_code=400, detail=f"invalid {field} timestamp")
    return to_iso(parsed)


app = create_app()
