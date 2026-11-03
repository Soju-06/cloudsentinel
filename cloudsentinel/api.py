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
``PATCH /api/alerts/{id}`` acknowledge / assign / close one alert
``GET  /api/detectors``   detector metadata for client filters
``GET  /api/auth/me``     who is this token and what may it do
``POST /api/scan``        re-scan the raw directory (opt-in, admin role)
``POST /api/ingest``      accept pushed records near-real-time (opt-in, admin)

Authentication accepts a token in ``X-API-Token`` (legacy) or
``Authorization: Bearer``. Tokens come from two places: the bootstrap
``--token`` value (always ``admin``) and the rotating token store
(``python -m cloudsentinel tokens``), whose tokens each carry a role:

* ``viewer``  — read alerts, summary, detectors, exports via clients;
* ``analyst`` — everything above plus triage updates (default);
* ``admin``   — everything above plus ``POST /api/scan`` and ``/api/ingest``.

When neither is configured the API is open, which is only acceptable
on a trusted localhost (the anonymous caller stays full-access).

Every ``/api/*`` request is rate limited per client/token and the API returns
uniform JSON errors that never echo secrets or stack traces.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .adapters.cloudtrail import extract_records
from .auth import ADMIN, TRIAGE, VIEW, Principal, open_principal
from .config import Config
from .db import AlertStore
from .paths import DEFAULT_DB_PATH, RAW_DIR
from .pipeline import scan_files
from .ratelimit import SlidingWindowLimiter
from .report import summary
from .severity import Severity
from .stream import StreamProcessor
from .tokens import TokenStore
from .triage import (
    STATUSES,
    InvalidStatusError,
    InvalidTransitionError,
    TriageError,
)
from .utils import parse_timestamp, to_iso, utcnow

logger = logging.getLogger(__name__)

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
    {
        "name": "mfa_changes",
        "label": "MFA changes",
        "description": "MFA devices disabled or deleted.",
    },
    {
        "name": "root_usage",
        "label": "Root account",
        "description": "Activity performed by the account root user.",
    },
    {
        "name": "access_key_creation",
        "label": "Access keys",
        "description": "Long-lived IAM access keys created.",
    },
    {
        "name": "security_group_open",
        "label": "Open security group",
        "description": "Ingress rules exposed to 0.0.0.0/0 or ::/0.",
    },
    {
        "name": "cloudtrail_tampering",
        "label": "CloudTrail tampering",
        "description": "Audit logging stopped, deleted or re-scoped.",
    },
]

_TRUTHY = {"1", "true", "yes", "on"}

# Local browser clients are the only ones that need CORS: the Windows shell and
# the Flutter web build are served from a loopback port, then call the API from
# a different loopback port.
_LOOPBACK_ORIGIN = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$"

_OPEN_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

MAX_ASSIGNEE_LENGTH = 120
MAX_INGEST_RECORDS = 5000
_WRITE_PATHS = {"/api/scan", "/api/ingest"}


class TriageUpdate(BaseModel):
    """Partial triage update; omitted fields are left untouched."""

    status: str | None = Field(
        default=None,
        description="open, acknowledged or closed",
    )
    assignee: str | None = Field(
        default=None,
        description="Analyst name; send null to clear the current assignee",
    )


def create_app(
    db_path: str | Path | None = None,
    raw_dir: str | Path | None = None,
    config: Config | None = None,
    token: str | None = None,
    allow_scan: bool = False,
    allow_ingest: bool = False,
    cors_origins: tuple[str, ...] | None = None,
    token_store: TokenStore | None = None,
    rate_limit: int | None = None,
    rate_limit_window: float = 60.0,
    scan_rate_limit: int | None = None,
) -> FastAPI:
    """Build the FastAPI application (a factory keeps tests isolated)."""

    settings = config or Config.load()
    database = Path(
        db_path or os.environ.get("CLOUDSENTINEL_DB") or DEFAULT_DB_PATH
    )
    raw_directory = Path(
        raw_dir or os.environ.get("CLOUDSENTINEL_RAW") or RAW_DIR
    )
    bootstrap_token = token if token is not None else os.environ.get(
        "CLOUDSENTINEL_API_TOKEN", ""
    )
    store_tokens = token_store
    # An explicitly configured store means "authentication is configured", even
    # when it is empty or every token inside has been revoked: a missing
    # credential must lock the API, never silently open it.
    auth_required = bool(bootstrap_token) or store_tokens is not None
    scan_enabled = allow_scan or os.environ.get(
        "CLOUDSENTINEL_API_ALLOW_SCAN", ""
    ).strip().lower() in _TRUTHY
    ingest_enabled = allow_ingest or os.environ.get(
        "CLOUDSENTINEL_API_ALLOW_INGEST", ""
    ).strip().lower() in _TRUTHY

    if rate_limit is None:
        raw_limit = os.environ.get("CLOUDSENTINEL_RATE_LIMIT", "").strip()
        rate_limit = int(raw_limit) if raw_limit.isdigit() else 120
    limiter = SlidingWindowLimiter(rate_limit, rate_limit_window)
    scan_limiter = SlidingWindowLimiter(
        scan_rate_limit if scan_rate_limit is not None else max(1, rate_limit // 10),
        rate_limit_window,
    )

    alerts_store = AlertStore(database)
    alerts_store.init()

    app = FastAPI(
        title="CloudSentinel API",
        version=__version__,
        description="Alert feed and summary for the CloudSentinel mobile client.",
    )
    app.state.store = alerts_store
    app.state.config = settings
    app.state.raw_dir = raw_directory
    app.state.scan_enabled = scan_enabled
    app.state.ingest_enabled = ingest_enabled
    app.state.stream_processor = None
    app.state.token_store = store_tokens
    app.state.rate_limiter = limiter
    app.state.scan_rate_limiter = scan_limiter
    app.state.auth_required = auth_required
    app.state.auth_mode = (
        "token-store"
        if store_tokens is not None and not bootstrap_token
        else "bootstrap+store"
        if store_tokens is not None
        else "bootstrap"
        if bootstrap_token
        else "open"
    )

    if cors_origins is None:
        app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=_LOOPBACK_ORIGIN,
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["*"],
        )
    elif cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(cors_origins),
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["*"],
        )

    def resolve_principal(presented: str) -> Principal | None:
        """Map a presented token onto an identity, or ``None`` when unknown.

        A deployment that configured neither a bootstrap token nor a token
        store is a trusted local lab: the anonymous caller gets the ``open``
        principal (full capabilities) so existing behaviour is preserved.
        """

        if bootstrap_token and secrets_compare(presented, bootstrap_token):
            return Principal("bootstrap", "admin", source="bootstrap")
        record = store_tokens.verify_record(presented) if store_tokens else None
        if record is not None:
            return Principal(record.label, record.role, source="token")
        if not auth_required:
            return open_principal()
        return None

    def require(capability: str):
        """Build a dependency enforcing one capability on an endpoint."""

        def guard(
            x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
            authorization: Annotated[str | None, Header()] = None,
        ) -> Principal:
            presented = extract_token(x_api_token, authorization)
            principal = resolve_principal(presented)
            if principal is None:
                raise HTTPException(
                    status_code=401,
                    detail="invalid or missing API token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if not principal.can(capability):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"token role '{principal.role}' does not allow "
                        f"'{capability}'; issue a token with --role admin"
                        if capability == ADMIN
                        else f"token role '{principal.role}' does not allow '{capability}'"
                    ),
                )
            return principal

        return guard

    guarded = [Depends(require(VIEW))]  # read-only endpoints (any role)
    triager_guards = [Depends(require(TRIAGE))]
    admin_guards = [Depends(require(ADMIN))]

    @app.middleware("http")
    async def security_guard(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and (limiter.enabled or scan_limiter.enabled):
            key = _client_key(request)
            active = scan_limiter if path in _WRITE_PATHS else limiter
            allowed, retry_after = active.check(key)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "rate limit exceeded",
                        "retry_after": retry_after,
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        response = await call_next(request)
        for name, value in _OPEN_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # One error shape everywhere: a human `detail` plus machine `errors`.
        return JSONResponse(
            status_code=422,
            content={
                "detail": "invalid request parameters",
                "errors": jsonable_encoder(exc.errors()),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        # Log locally, tell the client nothing that helps an attacker.
        logger.exception("unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "internal server error"},
        )

    @app.get("/health", tags=["system"])
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "time": to_iso(utcnow()),
            "alerts": alerts_store.count(),
            "auth_required": auth_required,
            "auth_mode": app.state.auth_mode,
            "scan_enabled": scan_enabled,
            "ingest_enabled": ingest_enabled,
            "rate_limit_per_minute": limiter.limit,
            "scan_rate_limit_per_minute": scan_limiter.limit,
        }

    @app.get("/api/summary", dependencies=guarded, tags=["alerts"])
    def api_summary() -> dict[str, Any]:
        alerts = alerts_store.fetch_alerts()
        payload = summary(alerts)
        database = alerts_store.stats()
        by_status = {
            status: database["by_status"].get(status, 0) for status in STATUSES
        }
        payload.update(
            {
                "version": __version__,
                "server_time": to_iso(utcnow()),
                "database": database,
                "by_status": by_status,
                "scan_enabled": scan_enabled,
            }
        )
        return payload

    @app.get("/api/alerts", dependencies=guarded, tags=["alerts"])
    def api_alerts(
        severity: Annotated[list[str] | None, Query()] = None,
        detector: Annotated[list[str] | None, Query()] = None,
        status: Annotated[list[str] | None, Query()] = None,
        search: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        since_iso = _iso_or_400(since, "since")
        until_iso = _iso_or_400(until, "until")
        try:
            alerts = alerts_store.fetch_alerts(
                severity=severity or None,
                detector=detector or None,
                status=status or None,
                search=search or None,
                since=since_iso,
                until=until_iso,
            )
        except TriageError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        alert = alerts_store.get(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert.to_dict()

    @app.patch("/api/alerts/{alert_id}", dependencies=triager_guards, tags=["alerts"])
    def api_triage(alert_id: int, payload: TriageUpdate) -> dict[str, Any]:
        if not payload.model_fields_set:
            raise HTTPException(
                status_code=400,
                detail="provide a status and/or assignee to update",
            )
        if payload.assignee is not None and len(payload.assignee) > MAX_ASSIGNEE_LENGTH:
            raise HTTPException(
                status_code=400,
                detail=f"assignee must be at most {MAX_ASSIGNEE_LENGTH} characters",
            )

        try:
            alert = alerts_store.set_triage(
                alert_id,
                status=payload.status,
                assignee=payload.assignee,
                update_assignee="assignee" in payload.model_fields_set,
            )
        except InvalidStatusError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except InvalidTransitionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert.to_dict()

    @app.get("/api/detectors", dependencies=guarded, tags=["meta"])
    def api_detectors() -> dict[str, Any]:
        return {
            "detectors": DETECTORS,
            "severities": [severity.value for severity in Severity],
            "statuses": list(STATUSES),
        }

    @app.get("/api/auth/me", dependencies=guarded, tags=["meta"])
    def api_me(principal: Principal = Depends(require(VIEW))) -> dict[str, Any]:
        """Who is this token, and what may it do?"""
        return principal.to_dict()

    @app.post("/api/scan", dependencies=admin_guards, tags=["scan"])
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

    @app.post("/api/ingest", dependencies=admin_guards, tags=["scan"])
    def api_ingest(body: Any = Body(...)) -> dict[str, Any]:
        """Accept pushed audit records and run detections immediately.

        The body can be a single record, a JSON array, a CloudTrail
        ``{"Records": [...]}`` dump or a CloudWatch Logs subscription payload.
        Records are de-duplicated by event ID across requests, so a webhook that
        retries the same batch does not create duplicate alerts.
        """

        if not ingest_enabled:
            raise HTTPException(
                status_code=403,
                detail="ingest endpoint disabled; start the server with --allow-ingest",
            )

        records = extract_records(body)
        if not records:
            raise HTTPException(
                status_code=400, detail="no event records found in request body"
            )
        if len(records) > MAX_INGEST_RECORDS:
            raise HTTPException(
                status_code=413,
                detail=f"batch too large; send at most {MAX_INGEST_RECORDS} records",
            )

        processor = app.state.stream_processor
        if processor is None:
            processor = StreamProcessor(alerts_store, settings)
            app.state.stream_processor = processor

        alerts = processor.feed(records)
        return {
            "status": "ok",
            "received": len(records),
            "alerts": len(alerts),
            "findings": [
                {
                    "detector": alert.detector,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "entity": alert.entity,
                    "event_count": alert.event_count,
                    "last_seen": to_iso(alert.last_seen),
                }
                for alert in alerts
            ],
            "stats": processor.stats.to_dict(),
        }

    return app


def secrets_compare(presented: str, expected: str) -> bool:
    """Constant-time comparison for the bootstrap token."""
    import hmac

    return hmac.compare_digest(presented.encode(), expected.encode())


def extract_token(
    header_token: str | None, authorization: str | None
) -> str:
    """Prefer ``X-API-Token`` and fall back to a Bearer header."""
    if header_token:
        return header_token.strip()
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
    return ""


def _client_key(request: Request) -> str:
    """Rate-limit key: client address plus a token fingerprint when present."""
    host = request.client.host if request.client else "unknown"
    presented = extract_token(
        request.headers.get("x-api-token"),
        request.headers.get("authorization"),
    )
    if not presented:
        return host
    digest = hashlib.sha256(presented.encode()).hexdigest()[:12]
    return f"{host}:{digest}"


def _iso_or_400(value: str | None, field: str) -> str | None:
    if not value:
        return None
    parsed = parse_timestamp(value)
    if parsed is None:
        raise HTTPException(status_code=400, detail=f"invalid {field} timestamp")
    return to_iso(parsed)


app = create_app()
