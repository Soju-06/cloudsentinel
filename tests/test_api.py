"""REST API tests for the mobile/remote client."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from cloudsentinel.api import create_app
from cloudsentinel.db import AlertStore
from cloudsentinel.severity import Severity

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
