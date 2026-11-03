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


def test_cli_watch_once(tmp_path, capsys):
    import json

    raw = tmp_path / "raw"
    raw.mkdir()
    records = [
        {
            "timestamp": f"2026-07-01T09:0{index}:00Z",
            "event_source": "aws.signin",
            "event_name": "ConsoleLogin",
            "user": "carol",
            "source_ip": "203.0.113.50",
            "status": "failure",
        }
        for index in range(5)
    ]
    (raw / "batch.json").write_text(json.dumps(records), encoding="utf-8")
    db_path = tmp_path / "watch.db"

    assert main(["watch", "-i", str(raw), "-d", str(db_path), "--once"]) == 0

    output = capsys.readouterr().out
    assert "CloudSentinel watch" in output
    assert "Alerts 1" in output
    assert AlertStore(db_path).count() == 1


def test_cli_watch_rejects_missing_directory(tmp_path, capsys):
    assert main(["watch", "-i", str(tmp_path / "missing"), "-d", str(tmp_path / "a.db")]) == 2
    assert "input directory not found" in capsys.readouterr().out


def test_cli_users_lifecycle(tmp_path, monkeypatch, capsys):
    import getpass

    users_file = tmp_path / "users.json"
    monkeypatch.setenv("CLOUDSENTINEL_USERS_FILE", str(users_file))
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: "sup3rsafe1")

    assert main(["users", "add", "alice", "--role", "admin"]) == 0
    output = capsys.readouterr().out
    assert "Created console account 'alice' (role: admin)." in output
    assert users_file.exists()
    assert "sup3rsafe1" not in users_file.read_text(encoding="utf-8")

    assert main(["users", "list"]) == 0
    output = capsys.readouterr().out
    assert "alice" in output
    assert "admin" in output

    assert main(["users", "setrole", "alice", "viewer"]) == 0
    assert "to role: viewer." in capsys.readouterr().out

    assert main(["users", "remove", "alice"]) == 0
    assert "Removed console account 'alice'" in capsys.readouterr().out

    # Unknown account twice: remove and setrole both fail cleanly.
    assert main(["users", "remove", "alice"]) == 2
    assert main(["users", "setrole", "ghost", "admin"]) == 2


def test_cli_users_rejects_password_mismatch(tmp_path, monkeypatch, capsys):
    import getpass

    monkeypatch.setenv("CLOUDSENTINEL_USERS_FILE", str(tmp_path / "users.json"))
    answers = iter(["sup3rsafe1", "sup3rsafe2"])
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: next(answers))

    assert main(["users", "add", "bob"]) == 2
    assert "passwords do not match" in capsys.readouterr().out


def test_cli_tokens_add_accepts_role(tmp_path, capsys):
    from cloudsentinel.tokens import TokenStore

    token_file = tmp_path / "tokens.json"

    assert (
        main(
            [
                "tokens",
                "add",
                "--label",
                "phone",
                "--role",
                "viewer",
                "--token-file",
                str(token_file),
            ]
        )
        == 0
    )
    assert "role       : viewer" in capsys.readouterr().out
    assert TokenStore(token_file).listing()[0]["role"] == "viewer"

    # Without --role the token defaults to analyst (triage-capable).
    assert (
        main(["tokens", "add", "--label", "ci", "--token-file", str(token_file)])
        == 0
    )
    assert "role       : analyst" in capsys.readouterr().out
