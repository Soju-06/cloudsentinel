"""Alert notifications over Slack, generic webhooks and SMTP email.

Transport functions use only the standard library and never raise: a failed
notification must not break a detection scan. Secrets can live in the config
file or in environment variables (recommended for CI/containers).
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Iterable, Mapping

from .config import NotificationConfig
from .models import Alert
from .severity import Severity
from .utils import truncate

logger = logging.getLogger(__name__)

_SLACK_ENV = "CLOUDSENTINEL_SLACK_WEBHOOK"
_WEBHOOK_ENV = "CLOUDSENTINEL_WEBHOOK_URL"
_SMTP_PASSWORD_ENV = "CLOUDSENTINEL_SMTP_PASSWORD"


@dataclass
class NotificationResult:
    channel: str
    sent: bool
    detail: str = ""

    def to_dict(self) -> dict[str, str | bool]:
        return {"channel": self.channel, "sent": self.sent, "detail": self.detail}


@dataclass
class _Settings:
    slack_webhook_url: str | None = None
    webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    email_from: str | None = None
    email_to: list[str] = field(default_factory=list)
    timeout_seconds: float = 5.0
    max_alerts: int = 20


def alerts_at_or_above(
    alerts: Iterable[Alert], min_severity: Severity | str
) -> list[Alert]:
    threshold = Severity.parse(min_severity)
    selected = [alert for alert in alerts if alert.severity.score >= threshold.score]
    return sorted(selected, key=lambda alert: (-alert.severity.score, alert.last_seen))


def build_message(alerts: Iterable[Alert], max_alerts: int = 20) -> str:
    alerts = list(alerts)
    counts: dict[str, int] = {}
    for alert in alerts:
        counts[alert.severity.value] = counts.get(alert.severity.value, 0) + 1

    mix = ", ".join(
        f"{count} {severity}"
        for severity, count in sorted(
            counts.items(), key=lambda item: -Severity.parse(item[0]).score
        )
    )
    lines = [f"CloudSentinel — {len(alerts)} alert(s)" + (f" ({mix})" if mix else "")]

    for alert in alerts[:max_alerts]:
        lines.append(
            f"[{alert.severity.label}] {alert.title} — {alert.entity}"
            f" ({alert.event_count} events)"
        )
        lines.append(f"  {truncate(alert.description, 200)}")

    if len(alerts) > max_alerts:
        lines.append(f"… {len(alerts) - max_alerts} more alert(s) in the dashboard")
    return "\n".join(lines)


def build_slack_payload(alerts: Iterable[Alert], max_alerts: int = 20) -> dict:
    return {"text": build_message(alerts, max_alerts=max_alerts)}


def build_webhook_payload(alerts: Iterable[Alert], max_alerts: int = 20) -> dict:
    alerts = list(alerts)
    counts = {severity.value: 0 for severity in Severity}
    for alert in alerts:
        counts[alert.severity.value] += 1
    return {
        "source": "cloudsentinel",
        "total_alerts": len(alerts),
        "by_severity": counts,
        "alerts": [alert.to_dict() for alert in alerts[:max_alerts]],
    }


def notify_alerts(
    alerts: Iterable[Alert],
    config: NotificationConfig | None = None,
    environment: Mapping[str, str] | None = None,
) -> list[NotificationResult]:
    """Send alerts through every configured channel."""

    config = config or NotificationConfig()
    if not config.enabled:
        logger.debug("Notifications disabled; skipping")
        return []

    settings = _settings(config, environment or os.environ)
    selected = alerts_at_or_above(alerts, config.min_severity)
    if not selected:
        return [NotificationResult("all", True, "no alerts at or above threshold")]

    body = build_message(selected, max_alerts=settings.max_alerts)
    results: list[NotificationResult] = []

    if settings.slack_webhook_url:
        results.append(
            _send_json(
                "slack",
                settings.slack_webhook_url,
                build_slack_payload(selected, max_alerts=settings.max_alerts),
                settings.timeout_seconds,
            )
        )

    if settings.webhook_url:
        results.append(
            _send_json(
                "webhook",
                settings.webhook_url,
                build_webhook_payload(selected, max_alerts=settings.max_alerts),
                settings.timeout_seconds,
            )
        )

    if settings.smtp_host and settings.email_to:
        results.append(_send_email(settings, selected, body))

    if not results:
        results.append(
            NotificationResult(
                "none",
                False,
                "notifications enabled but no channel is configured",
            )
        )
    return results


def _settings(
    config: NotificationConfig, environment: Mapping[str, str]
) -> _Settings:
    return _Settings(
        slack_webhook_url=config.slack_webhook_url
        or environment.get(_SLACK_ENV)
        or None,
        webhook_url=config.webhook_url or environment.get(_WEBHOOK_ENV) or None,
        smtp_host=config.smtp_host or environment.get("CLOUDSENTINEL_SMTP_HOST"),
        smtp_port=int(environment.get("CLOUDSENTINEL_SMTP_PORT", config.smtp_port)),
        smtp_username=config.smtp_username
        or environment.get("CLOUDSENTINEL_SMTP_USERNAME"),
        smtp_password=config.smtp_password or environment.get(_SMTP_PASSWORD_ENV),
        smtp_use_tls=config.smtp_use_tls,
        email_from=config.email_from
        or environment.get("CLOUDSENTINEL_EMAIL_FROM"),
        email_to=list(config.email_to)
        or [
            item
            for item in environment.get("CLOUDSENTINEL_EMAIL_TO", "").split(",")
            if item.strip()
        ],
        timeout_seconds=config.timeout_seconds,
        max_alerts=config.max_alerts,
    )


def _send_json(
    channel: str, url: str, payload: dict, timeout: float
) -> NotificationResult:
    try:
        _post_json(url, payload, timeout)
    except Exception as exc:  # noqa: BLE001 - transport must never raise
        logger.warning("%s notification failed: %s", channel, exc)
        return NotificationResult(channel, False, str(exc))
    return NotificationResult(channel, True, f"delivered to {_redact(url)}")


def _post_json(url: str, payload: dict, timeout: float = 5.0) -> None:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "CloudSentinel/0.2",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response.read()


def _send_email(
    settings: _Settings, alerts: list[Alert], body: str
) -> NotificationResult:
    sender = settings.email_from or settings.smtp_username or "cloudsentinel@localhost"
    message = EmailMessage()
    message["Subject"] = f"CloudSentinel — {len(alerts)} new security alert(s)"
    message["From"] = sender
    message["To"] = ", ".join(settings.email_to)
    message.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.timeout_seconds) as smtp:
            if settings.smtp_use_tls:
                smtp.starttls()
            if settings.smtp_username and settings.smtp_password:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(message)
    except Exception as exc:  # noqa: BLE001 - transport must never raise
        logger.warning("email notification failed: %s", exc)
        return NotificationResult("email", False, str(exc))

    return NotificationResult(
        "email", True, f"sent to {len(settings.email_to)} recipient(s)"
    )


def _redact(url: str) -> str:
    """Hide webhook secrets when logging: keep only scheme + host."""

    parts = urllib.parse.urlsplit(url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}/…"
    return "…"
