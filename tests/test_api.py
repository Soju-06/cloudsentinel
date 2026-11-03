"""REST API tests for the mobile/remote client."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from cloudsentinel.api import create_app
from cloudsentinel.db import AlertStore
from cloudsentinel.severity import Severity
from cloudsentinel.tokens import TokenStore

TOKEN = "test-token"


@pytest.fixture
def client(tmp_path, make_alert):
    db_path = tmp_path / "api.db"
    store = AlertStore(db_path).init()
    store.upsert_many(
        [
            make_alert(
                severity=Severity.CRITICAL,
                entity="carol",
                title="Repeated failed logins",
            ),
            make_alert(
                severity=Severity.HIGH,
                entity="public-bucket",
                detector="public_storage",
                title="Publicly accessible storage",
            ),
            make_alert(
                severity=Severity.MEDIUM,
                entity="dave",
                detector="iam_permissions",
                title="Excessive IAM permissions",
            ),
        ],
        suppression_minutes=0,
    )
    app = create_app(
        db_path=db_path,
        raw_dir=tmp_path / "raw",
        token=TOKEN,
    )
    with TestClient(app) as test_client:
        yield test_client


def _auth() -> dict[str, str]:
    return {"X-API-Token": TOKEN}


def test_health_is_public(client):
    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["alerts"] == 3
    assert payload["auth_required"] is True


def test_api_requires_token(client):
    assert client.get("/api/summary").status_code == 401
    assert client.get("/api/summary", headers={"X-API-Token": "wrong"}).status_code == 401
    assert client.get("/api/summary", headers=_auth()).status_code == 200


def test_summary_shape(client):
    payload = client.get("/api/summary", headers=_auth()).json()

    assert payload["total_alerts"] == 3
    assert payload["by_severity"]["critical"] == 1
    assert payload["by_severity"]["high"] == 1
    assert payload["database"]["total"] == 3
    assert "version" in payload


def test_alert_list_and_pagination(client):
    response = client.get("/api/alerts", headers=_auth(), params={"limit": 2})
    payload = response.json()

    assert response.status_code == 200
    assert payload["total"] == 3
    assert payload["count"] == 2
    assert len(payload["alerts"]) == 2
    # Critical sorts before high.
    assert payload["alerts"][0]["severity"] == "critical"

    second = client.get(
        "/api/alerts", headers=_auth(), params={"limit": 2, "offset": 2}
    ).json()
    assert second["count"] == 1
    assert second["offset"] == 2


def test_alert_filters(client):
    by_severity = client.get(
        "/api/alerts", headers=_auth(), params={"severity": "critical"}
    ).json()
    assert by_severity["total"] == 1

    by_detector = client.get(
        "/api/alerts", headers=_auth(), params={"detector": "public_storage"}
    ).json()
    assert by_detector["total"] == 1
    assert by_detector["alerts"][0]["entity"] == "public-bucket"

    by_search = client.get(
        "/api/alerts", headers=_auth(), params={"search": "carol"}
    ).json()
    assert by_search["total"] == 1


def test_alert_detail_and_404(client):
    listing = client.get("/api/alerts", headers=_auth()).json()
    alert_id = listing["alerts"][0]["id"]

    detail = client.get(f"/api/alerts/{alert_id}", headers=_auth())
    assert detail.status_code == 200
    assert detail.json()["id"] == alert_id
    assert isinstance(detail.json()["evidence"], dict)

    assert client.get("/api/alerts/999999", headers=_auth()).status_code == 404


def test_detector_metadata(client):
    payload = client.get("/api/detectors", headers=_auth()).json()

    names = {item["name"] for item in payload["detectors"]}
    assert names == {
        "brute_force",
        "impossible_travel",
        "public_storage",
        "iam_permissions",
        "mfa_changes",
        "root_usage",
        "access_key_creation",
        "security_group_open",
        "cloudtrail_tampering",
    }
    assert "critical" in payload["severities"]


def test_invalid_timestamp_is_rejected(client):
    response = client.get(
        "/api/alerts", headers=_auth(), params={"since": "not-a-date"}
    )
    assert response.status_code == 400


def test_scan_is_disabled_by_default(client):
    response = client.post("/api/scan", headers=_auth())
    assert response.status_code == 403


def test_scan_endpoint_runs_pipeline(tmp_path, make_alert):
    raw = tmp_path / "raw"
    raw.mkdir()
    events = [
        {
            "timestamp": f"2026-04-01T10:0{index}:00Z",
            "event_source": "aws.signin",
            "event_name": "ConsoleLogin",
            "user": "mallory",
            "source_ip": "203.0.113.99",
            "status": "failure",
            "error_code": "Failed authentication",
        }
        for index in range(6)
    ]
    (raw / "events.json").write_text(json.dumps(events), encoding="utf-8")

    app = create_app(
        db_path=tmp_path / "scan.db",
        raw_dir=raw,
        token=TOKEN,
        allow_scan=True,
    )
    with TestClient(app) as scan_client:
        response = scan_client.post("/api/scan", headers=_auth())

    assert response.status_code == 200
    payload = response.json()
    assert payload["events_scanned"] == 6
    assert payload["alerts"] >= 1
    assert payload["inserted"] >= 1
    assert payload["status"] == "ok"


def test_open_api_when_no_token_configured(client):
    app = create_app(db_path=client.app.state.store.path, token="")
    with TestClient(app) as open_client:
        assert open_client.get("/api/summary").status_code == 200


def test_docs_are_served(client):
    assert client.get("/docs").status_code == 200
    assert "CloudSentinel API" in client.get("/openapi.json").json()["info"]["title"]


def _cloudtrail_failure(index: int) -> dict:
    return {
        "eventVersion": "1.09",
        "eventID": f"ct-ingest-{index}",
        "eventTime": f"2026-06-01T10:0{index}:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/carol",
            "userName": "carol",
        },
        "errorCode": "Failed authentication",
    }


@pytest.fixture
def ingest_client(tmp_path):
    app = create_app(
        db_path=tmp_path / "ingest.db",
        raw_dir=tmp_path / "raw",
        token=TOKEN,
        allow_ingest=True,
    )
    with TestClient(app) as test_client:
        yield test_client


def test_ingest_is_disabled_by_default(client):
    response = client.post("/api/ingest", headers=_auth(), json=[])

    assert response.status_code == 403
    assert "allow-ingest" in response.json()["detail"]


def test_ingest_detects_and_dedupes(ingest_client):
    payload = {"Records": [_cloudtrail_failure(index) for index in range(5)]}

    first = ingest_client.post("/api/ingest", headers=_auth(), json=payload)

    assert first.status_code == 200
    body = first.json()
    assert body["received"] == 5
    assert body["alerts"] == 1
    assert body["findings"][0]["detector"] == "brute_force"
    assert body["stats"]["accepted"] == 5
    assert body["stats"]["inserted"] == 1

    second = ingest_client.post("/api/ingest", headers=_auth(), json=payload)

    assert second.status_code == 200
    assert second.json()["alerts"] == 0
    assert second.json()["stats"]["duplicates"] == 5
    assert second.json()["stats"]["inserted"] == 1

    listing = ingest_client.get("/api/alerts", headers=_auth()).json()
    assert listing["total"] == 1


def test_ingest_accepts_a_single_record(ingest_client):
    response = ingest_client.post(
        "/api/ingest", headers=_auth(), json=_cloudtrail_failure(0)
    )

    assert response.status_code == 200
    assert response.json()["received"] == 1


def test_ingest_rejects_a_body_without_records(ingest_client):
    response = ingest_client.post("/api/ingest", headers=_auth(), json="hello")

    assert response.status_code == 400


def test_ingest_enforces_batch_limit(ingest_client, monkeypatch):
    import cloudsentinel.api as api_module

    monkeypatch.setattr(api_module, "MAX_INGEST_RECORDS", 2)
    payload = [_cloudtrail_failure(index) for index in range(3)]

    response = ingest_client.post("/api/ingest", headers=_auth(), json=payload)

    assert response.status_code == 413


def test_health_reports_ingest_flag(client, ingest_client):
    assert client.get("/health").json()["ingest_enabled"] is False
    assert ingest_client.get("/health").json()["ingest_enabled"] is True


def _role_app(tmp_path, alerts):
    store = AlertStore(tmp_path / "auth.db").init()
    store.upsert_many(alerts, suppression_minutes=0)

    tokens = TokenStore(tmp_path / "tokens.json")
    plaintexts = {}
    for role in ("admin", "analyst", "viewer"):
        plaintexts[role], _ = tokens.add(label=f"{role}-token", role=role)

    app = create_app(
        db_path=tmp_path / "auth.db",
        raw_dir=tmp_path / "raw",
        token_store=tokens,
        allow_scan=True,
        allow_ingest=True,
    )
    return app, plaintexts


@pytest.fixture
def role_client(tmp_path, make_alert):
    app, plaintexts = _role_app(
        tmp_path,
        [make_alert(severity=Severity.CRITICAL, entity="carol")],
    )
    with TestClient(app) as test_client:
        yield test_client, plaintexts


def test_every_role_can_read(role_client):
    client, plaintexts = role_client

    for token in plaintexts.values():
        response = client.get("/api/summary", headers=_token_header(token))
        assert response.status_code == 200


def test_viewer_token_cannot_triage(role_client):
    client, plaintexts = role_client
    alert_id = client.get(
        "/api/alerts", headers=_token_header(plaintexts["admin"])
    ).json()["alerts"][0]["id"]

    headers = _token_header(plaintexts["viewer"])
    denied = client.patch(
        f"/api/alerts/{alert_id}",
        headers=headers,
        json={"status": "acknowledged"},
    )
    assert denied.status_code == 403
    assert "viewer" in denied.json()["detail"]

    allowed = client.patch(
        f"/api/alerts/{alert_id}",
        headers=_token_header(plaintexts["analyst"]),
        json={"status": "acknowledged"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "acknowledged"


def test_scan_and_ingest_require_admin(role_client, tmp_path):
    client, plaintexts = role_client
    (tmp_path / "raw").mkdir(exist_ok=True)

    scan = client.post("/api/scan", headers=_token_header(plaintexts["analyst"]))
    assert scan.status_code == 403

    ingest = client.post(
        "/api/ingest",
        headers=_token_header(plaintexts["viewer"]),
        json={"Records": []},
    )
    assert ingest.status_code == 403

    records = [
        {
            "eventVersion": "1.09",
            "eventID": f"role-{index}",
            "eventTime": f"2026-06-01T10:0{index}:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBucket",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.0.0.5",
            "userIdentity": {"type": "IAMUser", "userName": "carol"},
        }
        for index in range(3)
    ]
    ingest = client.post(
        "/api/ingest",
        headers=_token_header(plaintexts["admin"]),
        json={"Records": records},
    )
    assert ingest.status_code == 200
    assert ingest.json()["received"] == 3


def test_auth_me_returns_token_identity(role_client):
    client, plaintexts = role_client

    response = client.get(
        "/api/auth/me", headers=_token_header(plaintexts["analyst"])
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "analyst-token"
    assert payload["role"] == "analyst"
    assert payload["source"] == "token"
    assert "triage" in payload["capabilities"]
    assert "admin" not in payload["capabilities"]

    denied = client.get("/api/auth/me", headers=_token_header("wrong"))
    assert denied.status_code == 401


def test_token_store_configures_auth(role_client):
    client, _ = role_client

    health = client.get("/health").json()
    assert health["auth_required"] is True
    assert health["auth_mode"] == "token-store"

    missing = client.get("/api/summary")
    assert missing.status_code == 401


def _token_header(token: str) -> dict[str, str]:
    return {"X-API-Token": token}
