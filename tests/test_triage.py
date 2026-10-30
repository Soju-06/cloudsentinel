"""Alert triage: state machine, persistence, migration and API."""

from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from cloudsentinel.api import create_app
from cloudsentinel.db import AlertStore
from cloudsentinel.report import alerts_dataframe, summary
from cloudsentinel.severity import Severity
from cloudsentinel.triage import (
    InvalidStatusError,
    InvalidTransitionError,
    normalize_status,
    validate_transition,
)

TOKEN = "triage-token"

OLD_SCHEMA = """
CREATE TABLE alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL UNIQUE,
    detector      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    entity        TEXT NOT NULL,
    entity_type   TEXT NOT NULL,
    event_count   INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
"""


# --------------------------------------------------------------------- workflow


def test_normalize_status_is_case_insensitive():
    assert normalize_status(None) == "open"
    assert normalize_status(" Closed ") == "closed"
    with pytest.raises(InvalidStatusError):
        normalize_status("resolved")


def test_allowed_transitions():
    assert validate_transition("open", "acknowledged") == "acknowledged"
    assert validate_transition("open", "closed") == "closed"
    assert validate_transition("acknowledged", "open") == "open"
    assert validate_transition("acknowledged", "closed") == "closed"
    assert validate_transition("closed", "open") == "open"
    # Idempotent moves are accepted.
    assert validate_transition("closed", "closed") == "closed"


def test_closed_alert_cannot_be_acknowledged_directly():
    with pytest.raises(InvalidTransitionError):
        validate_transition("closed", "acknowledged")


# --------------------------------------------------------------------- storage


def test_new_alerts_start_open(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    store.upsert(make_alert())

    stored = store.fetch_alerts()[0]

    assert stored.status == "open"
    assert stored.assignee is None
    assert stored.triaged_at is None


def test_acknowledge_assign_and_close(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    alert_id = store.upsert(make_alert())[1]

    acknowledged = store.set_triage(alert_id, status="acknowledged")
    assert acknowledged is not None
    assert acknowledged.status == "acknowledged"
    assert acknowledged.triaged_at is not None

    assigned = store.set_triage(alert_id, assignee="analyst@example.com", update_assignee=True)
    assert assigned is not None
    assert assigned.assignee == "analyst@example.com"
    # Assigning an acknowledged alert leaves the state alone.
    assert assigned.status == "acknowledged"

    closed = store.set_triage(alert_id, status="closed")
    assert closed is not None
    assert closed.status == "closed"

    reopened = store.set_triage(alert_id, status="open")
    assert reopened is not None
    assert reopened.status == "open"


def test_assigning_an_open_alert_acknowledges_it(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    alert_id = store.upsert(make_alert())[1]

    alert = store.set_triage(
        alert_id, assignee="alice", update_assignee=True
    )

    assert alert is not None
    assert alert.status == "acknowledged"
    assert alert.assignee == "alice"


def test_assignee_can_be_cleared(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    alert_id = store.upsert(make_alert())[1]
    store.set_triage(alert_id, assignee="alice", update_assignee=True)

    alert = store.set_triage(alert_id, assignee=None, update_assignee=True)

    assert alert is not None
    assert alert.assignee is None
    assert alert.status == "acknowledged"


def test_unknown_alert_returns_none(tmp_path):
    store = AlertStore(tmp_path / "alerts.db").init()

    assert store.set_triage(999, status="closed") is None


def test_triage_survives_rescans(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    alert = make_alert()
    alert_id = store.upsert(alert)[1]
    store.set_triage(
        alert_id, status="closed", assignee="alice", update_assignee=True
    )

    # Same fingerprint -> update; a nearby finding -> merge. Neither resets
    # the analyst's decision.
    store.upsert(alert)
    store.upsert(
        make_alert(
            first_seen=alert.first_seen + timedelta(minutes=10),
            last_seen=alert.last_seen + timedelta(minutes=10),
        ),
        suppression_minutes=60,
    )

    stored = store.get(alert_id)
    assert stored is not None
    assert stored.status == "closed"
    assert stored.assignee == "alice"


def test_status_filter_and_stats(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    first = store.upsert(make_alert(entity="a"))[1]
    store.upsert(make_alert(entity="b"))
    store.set_triage(first, status="closed")

    assert {alert.entity for alert in store.fetch_alerts(status="closed")} == {"a"}
    assert len(store.fetch_alerts(status=["open", "acknowledged"])) == 1
    with pytest.raises(InvalidStatusError):
        store.fetch_alerts(status="bogus")

    stats = store.stats()
    assert stats["by_status"]["closed"] == 1
    assert stats["by_status"]["open"] == 1


def test_old_database_is_migrated_in_place(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    conn.execute(
        """
        INSERT INTO alerts (
            fingerprint, detector, severity, title, description, entity,
            entity_type, event_count, first_seen, last_seen, evidence,
            created_at, updated_at
        ) VALUES ('fp', 'brute_force', 'high', 'Legacy', 'Old row', 'alice',
                  'user', 3, '2026-01-01T00:00:00+00:00',
                  '2026-01-01T00:05:00+00:00', '{}',
                  '2026-01-01T00:05:00+00:00', '2026-01-01T00:05:00+00:00')
        """
    )
    conn.commit()
    conn.close()

    store = AlertStore(path).init()
    legacy = store.get(1)
    assert legacy is not None
    assert legacy.status == "open"
    assert legacy.assignee is None

    updated = store.set_triage(1, status="acknowledged")
    assert updated is not None
    assert updated.status == "acknowledged"


# ------------------------------------------------------------------------ API


@pytest.fixture
def client(tmp_path, make_alert):
    db_path = tmp_path / "triage.db"
    store = AlertStore(db_path).init()
    store.upsert_many(
        [
            make_alert(severity=Severity.CRITICAL, entity="carol"),
            make_alert(
                severity=Severity.HIGH,
                entity="bucket",
                detector="public_storage",
            ),
        ],
        suppression_minutes=0,
    )
    app = create_app(db_path=db_path, raw_dir=tmp_path / "raw", token=TOKEN)
    with TestClient(app) as test_client:
        yield test_client


def _auth() -> dict[str, str]:
    return {"X-API-Token": TOKEN}


def _ids(client) -> list[int]:
    return [item["id"] for item in client.get("/api/alerts", headers=_auth()).json()["alerts"]]


def test_patch_requires_token(client):
    alert_id = _ids(client)[0]

    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "closed"}).status_code == 401


def test_patch_status_and_assignee(client):
    alert_id = _ids(client)[0]

    response = client.patch(
        f"/api/alerts/{alert_id}",
        headers=_auth(),
        json={"status": "acknowledged", "assignee": "alice"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "acknowledged"
    assert payload["assignee"] == "alice"
    assert payload["triaged_at"] is not None


def test_patch_clears_assignee_with_null(client):
    alert_id = _ids(client)[0]
    client.patch(
        f"/api/alerts/{alert_id}",
        headers=_auth(),
        json={"assignee": "alice"},
    )

    payload = client.patch(
        f"/api/alerts/{alert_id}",
        headers=_auth(),
        json={"assignee": None},
    ).json()

    assert payload["assignee"] is None


def test_patch_rejects_unknown_status(client):
    alert_id = _ids(client)[0]

    response = client.patch(
        f"/api/alerts/{alert_id}",
        headers=_auth(),
        json={"status": "resolved"},
    )

    assert response.status_code == 400
    assert "unknown status" in response.json()["detail"]


def test_patch_rejects_illegal_transition(client):
    alert_id = _ids(client)[0]
    client.patch(
        f"/api/alerts/{alert_id}", headers=_auth(), json={"status": "closed"}
    )

    response = client.patch(
        f"/api/alerts/{alert_id}",
        headers=_auth(),
        json={"status": "acknowledged"},
    )

    assert response.status_code == 409


def test_patch_empty_body_and_missing_alert(client):
    alert_id = _ids(client)[0]

    assert (
        client.patch(f"/api/alerts/{alert_id}", headers=_auth(), json={}).status_code
        == 400
    )
    assert (
        client.patch(
            "/api/alerts/999999", headers=_auth(), json={"status": "closed"}
        ).status_code
        == 404
    )


def test_patch_rejects_long_assignee(client):
    alert_id = _ids(client)[0]

    response = client.patch(
        f"/api/alerts/{alert_id}",
        headers=_auth(),
        json={"assignee": "x" * 200},
    )

    assert response.status_code == 400


def test_status_filter_and_summary(client):
    alert_id = _ids(client)[0]
    client.patch(
        f"/api/alerts/{alert_id}", headers=_auth(), json={"status": "closed"}
    )

    closed = client.get(
        "/api/alerts", headers=_auth(), params={"status": "closed"}
    ).json()
    assert closed["total"] == 1
    assert closed["alerts"][0]["id"] == alert_id

    summary_payload = client.get("/api/summary", headers=_auth()).json()
    assert summary_payload["by_status"] == {
        "open": 1,
        "acknowledged": 0,
        "closed": 1,
    }
    assert summary_payload["database"]["by_status"]["closed"] == 1

    invalid = client.get(
        "/api/alerts", headers=_auth(), params={"status": "bogus"}
    )
    assert invalid.status_code == 400


def test_detector_metadata_lists_statuses(client):
    payload = client.get("/api/detectors", headers=_auth()).json()

    assert payload["statuses"] == ["open", "acknowledged", "closed"]


# --------------------------------------------------------------------- reports


def test_report_columns_and_summary_include_triage(tmp_path, make_alert):
    store = AlertStore(tmp_path / "alerts.db").init()
    alert_id = store.upsert(make_alert())[1]
    store.set_triage(alert_id, status="closed")

    frame = alerts_dataframe(store.fetch_alerts())
    assert "status" in frame.columns
    assert "assignee" in frame.columns

    info = summary(store.fetch_alerts())
    assert info["by_status"] == {"open": 0, "acknowledged": 0, "closed": 1}
