"""Report export tests."""

from __future__ import annotations

import json

import pandas as pd

from cloudsentinel.report import (
    EXPORT_COLUMNS,
    alerts_dataframe,
    export_csv,
    export_html,
    export_json,
    export_pdf,
    render_html,
    render_pdf_bytes,
    report_payload,
    summary,
)
from cloudsentinel.severity import Severity


def test_dataframe_sorted_by_severity(make_alert):
    alerts = [
        make_alert(severity=Severity.LOW, entity="low"),
        make_alert(severity=Severity.CRITICAL, entity="critical"),
        make_alert(severity=Severity.HIGH, entity="high"),
    ]

    frame = alerts_dataframe(alerts)

    assert list(frame["entity"]) == ["critical", "high", "low"]
    assert list(frame.columns) == EXPORT_COLUMNS


def test_empty_dataframe_has_columns():
    frame = alerts_dataframe([])
    assert frame.empty
    assert list(frame.columns) == EXPORT_COLUMNS


def test_export_csv(make_alert, tmp_path):
    alerts = [
        make_alert(severity=Severity.CRITICAL, entity="carol"),
        make_alert(severity=Severity.HIGH, entity="bob"),
    ]
    destination = export_csv(alerts, tmp_path / "report.csv")

    frame = pd.read_csv(destination)

    assert destination.exists()
    assert len(frame) == 2
    assert "severity" in frame.columns
    assert frame.iloc[0]["severity"] == "critical"


def test_export_json(make_alert, tmp_path):
    alerts = [make_alert(evidence={"event_ids": ["evt-1"]})]
    destination = export_json(alerts, tmp_path / "report.json")

    payload = json.loads(destination.read_text(encoding="utf-8"))

    assert payload["summary"]["total_alerts"] == 1
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["evidence"]["event_ids"] == ["evt-1"]
    assert payload["summary"]["by_severity"]["high"] == 1


def test_summary_counts(make_alert):
    alerts = [
        make_alert(severity=Severity.CRITICAL, entity="a"),
        make_alert(severity=Severity.CRITICAL, entity="a"),
        make_alert(severity=Severity.MEDIUM, entity="b"),
    ]

    info = summary(alerts)

    assert info["total_alerts"] == 3
    assert info["by_severity"]["critical"] == 2
    assert info["by_severity"]["medium"] == 1
    assert info["affected_entities"] == 2


def test_report_payload_is_json_serialisable(make_alert):
    payload = report_payload([make_alert()])
    encoded = json.dumps(payload)
    assert "Repeated failed logins" in encoded


def test_html_report(make_alert):
    document = render_html([make_alert(severity=Severity.CRITICAL, entity="carol")])

    assert "<!DOCTYPE html>" in document
    assert "CLOUD SECURITY REPORT" in document
    assert "carol" in document
    assert "CRITICAL" in document


def test_html_report_escapes_content(make_alert):
    document = render_html([make_alert(entity="<script>alert(1)</script>")])
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;" in document


def test_export_html(make_alert, tmp_path):
    destination = export_html([make_alert()], tmp_path / "report.html")
    assert destination.exists()
    assert "CloudSentinel" in destination.read_text(encoding="utf-8")


def test_pdf_report(make_alert, tmp_path):
    data = render_pdf_bytes([make_alert(severity=Severity.CRITICAL, entity="carol")])
    assert data.startswith(b"%PDF")
    assert len(data) > 500

    destination = export_pdf([make_alert()], tmp_path / "report.pdf")
    assert destination.exists()
    assert destination.read_bytes().startswith(b"%PDF")


def test_empty_html_report():
    document = render_html([])
    assert "No alerts matched" in document
