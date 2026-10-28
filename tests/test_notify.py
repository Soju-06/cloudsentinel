"""Notification channel tests (no real network access)."""

from __future__ import annotations

import json

import cloudsentinel.notify as notify
from cloudsentinel.config import NotificationConfig
from cloudsentinel.notify import (
    alerts_at_or_above,
    build_message,
    build_slack_payload,
    notify_alerts,
)
from cloudsentinel.severity import Severity


def test_filter_by_severity(make_alert):
    alerts = [
        make_alert(severity=Severity.CRITICAL, entity="crit"),
        make_alert(severity=Severity.LOW, entity="low"),
    ]

    selected = alerts_at_or_above(alerts, Severity.HIGH)

    assert [alert.entity for alert in selected] == ["crit"]


def test_build_message(make_alert):
    message = build_message([make_alert(severity=Severity.CRITICAL, entity="carol")])
    assert "CloudSentinel" in message
    assert "CRITICAL" in message
    assert "carol" in message


def test_slack_payload(make_alert):
    payload = build_slack_payload([make_alert()])
    assert "text" in payload
    assert "Repeated failed logins" in payload["text"]


def test_disabled_notifications(make_alert):
    assert notify_alerts([make_alert()], NotificationConfig(enabled=False)) == []


def test_slack_delivery(monkeypatch, make_alert):
    captured = {}

    def fake_post(url, payload, timeout=5.0):
        captured["url"] = url
        captured["payload"] = payload

    monkeypatch.setattr(notify, "_post_json", fake_post)
    config = NotificationConfig(
        enabled=True,
        slack_webhook_url="https://hooks.slack.test/services/T000/B000/secret",
        min_severity="high",
    )

    results = notify_alerts([make_alert(severity=Severity.CRITICAL)], config)

    assert len(results) == 1
    assert results[0].channel == "slack"
    assert results[0].sent is True
    assert captured["payload"]["text"]
    # Secrets are redacted in the detail string.
    assert "secret" not in results[0].detail


def test_webhook_delivery(monkeypatch, make_alert):
    captured = {}

    def fake_post(url, payload, timeout=5.0):
        captured["payload"] = payload

    monkeypatch.setattr(notify, "_post_json", fake_post)
    config = NotificationConfig(enabled=True, webhook_url="https://example.test/hook")

    results = notify_alerts([make_alert()], config)

    assert results[0].channel == "webhook"
    assert captured["payload"]["source"] == "cloudsentinel"
    assert captured["payload"]["alerts"][0]["entity"] == "alice"


def test_transport_failure_is_reported(monkeypatch, make_alert):
    def failing_post(url, payload, timeout=5.0):
        raise OSError("network unreachable")

    monkeypatch.setattr(notify, "_post_json", failing_post)
    config = NotificationConfig(enabled=True, slack_webhook_url="https://example.test/x")

    results = notify_alerts([make_alert()], config)

    assert results[0].sent is False
    assert "unreachable" in results[0].detail


def test_environment_override(monkeypatch, make_alert):
    captured = {}

    def fake_post(url, payload, timeout=5.0):
        captured["url"] = url

    monkeypatch.setattr(notify, "_post_json", fake_post)
    config = NotificationConfig(enabled=True)

    results = notify_alerts(
        [make_alert()],
        config,
        environment={"CLOUDSENTINEL_SLACK_WEBHOOK": "https://env.test/hook"},
    )

    assert results[0].sent is True
    assert captured["url"] == "https://env.test/hook"


def test_no_channel_configured(make_alert):
    results = notify_alerts([make_alert()], NotificationConfig(enabled=True))
    assert results[0].channel == "none"
    assert results[0].sent is False


def test_email_delivery(monkeypatch, make_alert):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=5):
            sent["host"] = host

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, username, password):
            sent["login"] = username

        def send_message(self, message):
            sent["subject"] = message["Subject"]
            sent["to"] = message["To"]

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    config = NotificationConfig(
        enabled=True,
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_username="user",
        smtp_password="pass",
        email_from="alerts@example.test",
        email_to=["sec@example.test"],
    )

    results = notify_alerts([make_alert()], config)

    assert results[0].channel == "email"
    assert results[0].sent is True
    assert sent["host"] == "smtp.example.test"
    assert sent["to"] == "sec@example.test"


def test_payload_is_json_serialisable(make_alert):
    payload = notify.build_webhook_payload([make_alert()])
    assert "alice" in json.dumps(payload)
