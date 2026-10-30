"""CLI smoke tests."""

from __future__ import annotations

import pandas as pd

from cloudsentinel.cli import main
from cloudsentinel.db import AlertStore


def test_cli_demo_and_report(tmp_path, capsys):
    raw = tmp_path / "raw"
    db_path = tmp_path / "alerts.db"

    assert main(["demo", "-d", str(db_path), "-o", str(raw)]) == 0
    output = capsys.readouterr().out
    assert "Generated" in output
    assert db_path.exists()

    report_path = tmp_path / "report.csv"
    assert (
        main(
            ["report", "-d", str(db_path), "-f", "csv", "-o", str(report_path)]
        )
        == 0
    )

    frame = pd.read_csv(report_path)
    assert not frame.empty
    assert {"severity", "detector", "entity"}.issubset(frame.columns)


def test_cli_scan_and_json_report(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "events.json").write_text(
        """
        [
          {"timestamp": "2026-01-01T00:00:00Z", "event_source": "aws.signin",
           "event_name": "ConsoleLogin", "user": "alice",
           "source_ip": "203.0.113.1", "status": "failure",
           "error_code": "Failed authentication"},
          {"timestamp": "2026-01-01T00:00:30Z", "event_source": "aws.signin",
           "event_name": "ConsoleLogin", "user": "alice",
           "source_ip": "203.0.113.1", "status": "failure",
           "error_code": "Failed authentication"},
          {"timestamp": "2026-01-01T00:01:00Z", "event_source": "aws.signin",
           "event_name": "ConsoleLogin", "user": "alice",
           "source_ip": "203.0.113.1", "status": "failure",
           "error_code": "Failed authentication"},
          {"timestamp": "2026-01-01T00:01:30Z", "event_source": "aws.signin",
           "event_name": "ConsoleLogin", "user": "alice",
           "source_ip": "203.0.113.1", "status": "failure",
           "error_code": "Failed authentication"},
          {"timestamp": "2026-01-01T00:02:00Z", "event_source": "aws.signin",
           "event_name": "ConsoleLogin", "user": "alice",
           "source_ip": "203.0.113.1", "status": "failure",
           "error_code": "Failed authentication"}
        ]
        """,
        encoding="utf-8",
    )
    db_path = tmp_path / "alerts.db"

    assert main(["scan", "-i", str(raw), "-d", str(db_path)]) == 0

    report_path = tmp_path / "report.json"
    assert (
        main(
            ["report", "-d", str(db_path), "-f", "json", "-o", str(report_path)]
        )
        == 0
    )
    assert report_path.exists()


def test_cli_init(tmp_path):
    db_path = tmp_path / "alerts.db"
    assert main(["init", "-d", str(db_path)]) == 0
    assert db_path.exists()


def test_cli_triage(tmp_path, make_alert, capsys):
    db_path = tmp_path / "alerts.db"
    store = AlertStore(db_path).init()
    alert_id = store.upsert(make_alert())[1]

    assert (
        main(
            [
                "triage",
                str(alert_id),
                "-d",
                str(db_path),
                "--status",
                "acknowledged",
                "--assignee",
                "alice",
            ]
        )
        == 0
    )
    alert = store.get(alert_id)
    assert alert is not None
    assert alert.status == "acknowledged"
    assert alert.assignee == "alice"
    assert "acknowledged" in capsys.readouterr().out

    assert (
        main(["triage", str(alert_id), "-d", str(db_path), "--clear-assignee"])
        == 0
    )
    assert store.get(alert_id).assignee is None

    # No change requested, unknown alert, and an illegal transition.
    assert main(["triage", str(alert_id), "-d", str(db_path)]) == 2
    assert main(["triage", "999", "-d", str(db_path), "--status", "closed"]) == 1

    store.set_triage(alert_id, status="closed")
    assert main(["triage", str(alert_id), "-d", str(db_path), "--status", "acknowledged"]) == 2
