"""Alert reporting: CSV/JSON/HTML/PDF exports and summary aggregation."""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

import pandas as pd

from .models import Alert
from .paths import REPORTS_DIR
from .severity import Severity, sort_key
from .utils import utcnow

EXPORT_COLUMNS = [
    "id",
    "severity",
    "detector",
    "title",
    "entity",
    "entity_type",
    "event_count",
    "first_seen",
    "last_seen",
    "description",
    "evidence",
]

AlertLike = Alert | dict[str, Any] | pd.DataFrame | Iterable[Alert | dict[str, Any]]


def alerts_dataframe(alerts: AlertLike) -> pd.DataFrame:
    """Build a consistently ordered DataFrame from alerts."""

    if isinstance(alerts, pd.DataFrame):
        frame = alerts.copy()
    else:
        records = []
        for alert in alerts:
            records.append(alert.to_dict() if isinstance(alert, Alert) else dict(alert))
        frame = pd.DataFrame(records)

    if frame.empty:
        return pd.DataFrame(columns=EXPORT_COLUMNS)

    for column in EXPORT_COLUMNS:
        if column not in frame.columns:
            frame[column] = None

    frame = frame[EXPORT_COLUMNS].copy()
    frame["severity"] = frame["severity"].map(lambda value: Severity.parse(value).value)
    frame["_rank"] = frame["severity"].map(sort_key)
    frame["last_seen"] = pd.to_datetime(frame["last_seen"], utc=True, errors="coerce")
    frame["first_seen"] = pd.to_datetime(frame["first_seen"], utc=True, errors="coerce")
    frame = frame.sort_values(["_rank", "last_seen"], ascending=[True, False])
    return frame.drop(columns=["_rank"]).reset_index(drop=True)


def summary(alerts: AlertLike) -> dict[str, Any]:
    frame = alerts_dataframe(alerts)
    by_severity = {severity.value: 0 for severity in Severity}
    if not frame.empty:
        for value, count in frame["severity"].value_counts().items():
            by_severity[str(value)] = int(count)

    by_detector: dict[str, int] = {}
    entities: list[str] = []
    if not frame.empty:
        by_detector = {
            str(key): int(value)
            for key, value in frame["detector"].value_counts().items()
        }
        entities = sorted({str(value) for value in frame["entity"].dropna()})

    return {
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "total_alerts": int(len(frame)),
        "by_severity": by_severity,
        "by_detector": by_detector,
        "affected_entities": len(entities),
        "entities": entities,
        "earliest_event": (
            frame["first_seen"].min().isoformat() if not frame.empty else None
        ),
        "latest_event": (
            frame["last_seen"].max().isoformat() if not frame.empty else None
        ),
    }


def report_payload(alerts: AlertLike) -> dict[str, Any]:
    frame = alerts_dataframe(alerts)
    records = []
    for record in frame.to_dict(orient="records"):
        for key in ("first_seen", "last_seen"):
            value = record.get(key)
            record[key] = value.isoformat() if pd.notna(value) else None
        evidence = record.get("evidence")
        if isinstance(evidence, str):
            try:
                record["evidence"] = json.loads(evidence)
            except ValueError:
                pass
        records.append(record)
    return {"summary": summary(frame), "alerts": records}


def export_csv(alerts: AlertLike, path: str | Path | None = None) -> Path:
    """Write alerts to CSV and return the destination path."""

    frame = alerts_dataframe(alerts).copy()
    frame["evidence"] = frame["evidence"].map(
        lambda value: json.dumps(value, default=str, sort_keys=True)
        if isinstance(value, (dict, list))
        else value
    )
    destination = _destination(path, ".csv")
    frame.to_csv(destination, index=False, encoding="utf-8")
    return destination


def export_json(alerts: AlertLike, path: str | Path | None = None) -> Path:
    """Write a full JSON report (summary + alerts)."""

    destination = _destination(path, ".json")
    destination.write_text(
        json.dumps(report_payload(alerts), indent=2, default=str),
        encoding="utf-8",
    )
    return destination


def render_html(alerts: AlertLike, title: str = "CloudSentinel Security Report") -> str:
    """Render a self-contained HTML report (safe for sharing or printing)."""

    frame = alerts_dataframe(alerts)
    info = summary(frame)
    generated = html.escape(str(info["generated_at"]))
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = []
    for record in frame.itertuples(index=False):
        severity = Severity.parse(record.severity)
        last_seen = record.last_seen
        timestamp = last_seen.strftime("%d %b %Y %H:%M UTC") if pd.notna(last_seen) else "—"
        rows.append(
            f"""
            <tr>
              <td><span class="badge {severity.value}">{severity.label}</span></td>
              <td>
                <div class="title">{html.escape(str(record.title))}</div>
                <div class="desc">{html.escape(str(record.description))}</div>
              </td>
              <td>{html.escape(str(record.detector))}</td>
              <td class="mono">{html.escape(str(record.entity))}</td>
              <td class="mono">{int(record.event_count)}</td>
              <td class="mono nowrap">{html.escape(timestamp)}</td>
            </tr>"""
        )

    if not rows:
        rows.append(
            '<tr><td colspan="6" class="empty">No alerts matched the report filters.</td></tr>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ --bg:#050810; --panel:#0b1424; --text:#e6f1ff; --muted:#7d93ad; --line:rgba(0,229,255,.16); }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:40px; background:radial-gradient(900px 420px at 85% -10%, rgba(124,77,255,.18), transparent 60%), var(--bg); color:var(--text); font-family:'Segoe UI', system-ui, sans-serif; }}
  .wrap {{ max-width:1180px; margin:0 auto; }}
  header {{ display:flex; justify-content:space-between; align-items:flex-end; gap:20px; border-bottom:1px solid var(--line); padding-bottom:18px; margin-bottom:26px; }}
  h1 {{ font-size:22px; letter-spacing:.18em; margin:0; color:#00e5ff; }}
  .sub {{ color:var(--muted); font-size:12px; letter-spacing:.14em; margin-top:6px; }}
  .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:26px; }}
  .card {{ border:1px solid var(--line); background:var(--panel); border-radius:14px; padding:16px 18px; }}
  .label {{ color:var(--muted); font-size:10px; letter-spacing:.2em; }}
  .value {{ font-size:28px; font-weight:700; margin-top:8px; }}
  .critical {{ color:#ff2d55; }} .high {{ color:#ff9f0a; }} .medium {{ color:#ffd60a; }} .low {{ color:#30d158; }} .info {{ color:#64d2ff; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:14px; overflow:hidden; font-size:13px; }}
  th {{ text-align:left; padding:12px 14px; color:var(--muted); font-size:10px; letter-spacing:.18em; background:rgba(0,229,255,.04); border-bottom:1px solid var(--line); }}
  td {{ padding:12px 14px; border-bottom:1px solid rgba(255,255,255,.05); vertical-align:top; }}
  tr:last-child td {{ border-bottom:0; }}
  .title {{ font-weight:600; margin-bottom:3px; }}
  .desc {{ color:var(--muted); font-size:12px; line-height:1.5; }}
  .mono {{ font-family:Consolas, monospace; font-size:12px; }}
  .nowrap {{ white-space:nowrap; }}
  .badge {{ display:inline-block; padding:3px 9px; border-radius:999px; font-size:10px; font-weight:700; letter-spacing:.1em; border:1px solid currentColor; }}
  .badge.critical {{ box-shadow:0 0 12px rgba(255,45,85,.25); }}
  .empty {{ text-align:center; color:var(--muted); padding:30px; }}
  footer {{ margin-top:24px; color:var(--muted); font-size:11px; display:flex; justify-content:space-between; }}
  @media print {{ body {{ background:#fff; color:#111; padding:16px; }} .card, table {{ background:#fff; }} .desc, .sub, footer {{ color:#555; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>CLOUDSENTINEL</h1>
      <div class="sub">CLOUD SECURITY REPORT · GENERATED {generated}</div>
    </div>
    <div class="sub">REPORT {stamp}</div>
  </header>
  <div class="cards">
    <div class="card"><div class="label">TOTAL ALERTS</div><div class="value">{info['total_alerts']}</div></div>
    <div class="card"><div class="label">CRITICAL</div><div class="value critical">{info['by_severity']['critical']}</div></div>
    <div class="card"><div class="label">HIGH</div><div class="value high">{info['by_severity']['high']}</div></div>
    <div class="card"><div class="label">AFFECTED ENTITIES</div><div class="value">{info['affected_entities']}</div></div>
  </div>
  <table>
    <thead><tr><th>SEVERITY</th><th>FINDING</th><th>DETECTOR</th><th>ENTITY</th><th>EVENTS</th><th>LAST SEEN</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
  <footer><span>CloudSentinel v0.2.0</span><span>SQLite · Pandas engine · Streamlit console</span></footer>
</div>
</body>
</html>
"""


def export_html(alerts: AlertLike, path: str | Path | None = None) -> Path:
    """Write a standalone HTML report."""

    destination = _destination(path, ".html")
    destination.write_text(render_html(alerts), encoding="utf-8")
    return destination


def render_pdf_bytes(alerts: AlertLike) -> bytes:
    """Render a compact PDF report (requires the optional ``fpdf2`` package)."""

    try:
        from fpdf import FPDF
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise RuntimeError(
            "PDF export requires fpdf2. Install it with: pip install fpdf2"
        ) from exc

    frame = alerts_dataframe(alerts)
    info = summary(frame)

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(0, 160, 190)
    pdf.cell(0, 9, _pdf_text("CLOUDSENTINEL SECURITY REPORT"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(110, 125, 145)
    pdf.cell(
        0,
        5,
        _pdf_text(f"Generated {info['generated_at']}  |  {info['total_alerts']} alerts  |  "
                  f"{info['by_severity']['critical']} critical  |  {info['by_severity']['high']} high"),
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(5)

    rank_colors = {
        Severity.CRITICAL: (214, 32, 64),
        Severity.HIGH: (214, 126, 8),
        Severity.MEDIUM: (176, 146, 0),
        Severity.LOW: (32, 140, 64),
    }

    for record in frame.itertuples(index=False):
        severity = Severity.parse(record.severity)
        if pdf.get_y() > 255:
            pdf.add_page()

        pdf.set_font("Helvetica", "B", 9)
        red, green, blue = rank_colors.get(severity, (60, 130, 160))
        pdf.set_text_color(red, green, blue)
        pdf.cell(24, 5, severity.label, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(20, 20, 20)
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(
            0, 5, _pdf_text(f"{record.title} — {record.entity} ({int(record.event_count)} events)"),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(90, 100, 115)
        pdf.multi_cell(
            0, 4.5, _pdf_text(str(record.description)), new_x="LMARGIN", new_y="NEXT"
        )
        pdf.ln(2.5)

    if frame.empty:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(90, 100, 115)
        pdf.cell(0, 6, _pdf_text("No alerts matched the report filters."))

    return bytes(pdf.output())


def export_pdf(alerts: AlertLike, path: str | Path | None = None) -> Path:
    """Write a PDF report."""

    destination = _destination(path, ".pdf")
    destination.write_bytes(render_pdf_bytes(alerts))
    return destination


def _pdf_text(value: Any) -> str:
    return str(value).encode("latin-1", "replace").decode("latin-1")


def _destination(path: str | Path | None, suffix: str) -> Path:
    if path is None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return REPORTS_DIR / f"cloudsentinel_alerts_{stamp}{suffix}"
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def severity_counts(alerts: Sequence[Alert]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for alert in alerts:
        counts[Severity.parse(alert.severity).value] += 1
    return counts
