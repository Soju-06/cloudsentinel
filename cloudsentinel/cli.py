"""Command-line interface.

Examples
--------
    python -m cloudsentinel scan
    python -m cloudsentinel scan -i data/raw --reset
    python -m cloudsentinel report -f json -o reports/alerts.json
    python -m cloudsentinel demo
    python -m cloudsentinel init
"""

from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .db import AlertStore
from .notify import notify_alerts
from .paths import DEFAULT_DB_PATH, RAW_DIR
from .pipeline import scan_files
from .report import export_csv, export_html, export_json, export_pdf, summary
from .severity import Severity, sort_key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudsentinel",
        description="Cloud security monitoring & threat detection",
    )
    parser.add_argument("--version", action="version", version=f"cloudsentinel {__version__}")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable debug logging"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="ingest raw logs and run detectors")
    scan.add_argument(
        "-i", "--input", default=str(RAW_DIR), help="raw log file or directory"
    )
    scan.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH), help="alerts database")
    scan.add_argument("-c", "--config", default=None, help="TOML/JSON config file")
    scan.add_argument(
        "--reset", action="store_true", help="delete existing alerts before scanning"
    )
    scan.add_argument(
        "--notify",
        action="store_true",
        help="send alerts through configured notification channels",
    )

    report = subparsers.add_parser("report", help="export stored alerts")
    report.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH), help="alerts database")
    report.add_argument(
        "-f",
        "--format",
        choices=["csv", "json", "html", "pdf"],
        default="csv",
        help="export format",
    )
    report.add_argument("-o", "--output", default=None, help="output file path")
    report.add_argument(
        "--severity",
        nargs="*",
        choices=[severity.value for severity in Severity],
        help="only export the given severities",
    )

    init = subparsers.add_parser("init", help="initialise the alerts database")
    init.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH), help="alerts database")

    notify = subparsers.add_parser(
        "notify", help="send stored alerts through configured channels"
    )
    notify.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH), help="alerts database")
    notify.add_argument("-c", "--config", default=None, help="TOML/JSON config file")
    notify.add_argument(
        "--min-severity",
        choices=[severity.value for severity in Severity],
        default=None,
        help="override the configured minimum severity",
    )

    demo = subparsers.add_parser("demo", help="generate sample logs and scan them")
    demo.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH), help="alerts database")
    demo.add_argument("-o", "--out-dir", default=str(RAW_DIR), help="sample data directory")
    demo.add_argument("--seed", type=int, default=1337, help="sample data seed")

    serve = subparsers.add_parser(
        "serve", help="run the REST API used by the mobile app"
    )
    serve.add_argument("--host", default="127.0.0.1", help="bind address (0.0.0.0 for LAN)")
    serve.add_argument("--port", type=int, default=8080, help="TCP port")
    serve.add_argument("-d", "--db", default=str(DEFAULT_DB_PATH), help="alerts database")
    serve.add_argument("-i", "--input", default=str(RAW_DIR), help="raw log directory")
    serve.add_argument("-c", "--config", default=None, help="TOML/JSON config file")
    serve.add_argument(
        "--token",
        default=None,
        help="shared API token (defaults to CLOUDSENTINEL_API_TOKEN)",
    )
    serve.add_argument(
        "--allow-scan",
        action="store_true",
        help="expose POST /api/scan to trigger detection scans remotely",
    )
    serve.add_argument(
        "--cors",
        default=None,
        help="comma-separated allowed origins for browser clients (default: *)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command == "scan":
        return _scan(args)
    if args.command == "report":
        return _report(args)
    if args.command == "init":
        return _init(args)
    if args.command == "demo":
        return _demo(args)
    if args.command == "notify":
        return _notify(args)
    if args.command == "serve":
        return _serve(args)
    return 1


def _scan(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    result = scan_files(args.input, args.db, config, reset=args.reset)

    if result.events_scanned == 0:
        print(f"No events found in {Path(args.input)}")
        return 1

    print("CloudSentinel scan")
    print(f"  events scanned : {result.events_scanned}")
    print(f"  source files   : {len(result.files)}")
    print(f"  alerts found   : {len(result.alerts)}")
    print(
        "  severity mix   : "
        + ", ".join(
            f"{severity.label} {count}"
            for severity, count in (
                (severity, result.by_severity[severity.value])
                for severity in sorted(Severity, key=sort_key)
                if result.by_severity[severity.value]
            )
        )
    )
    print(
        f"  database       : {result.inserted} new,"
        f" {result.merged} merged, {result.updated} updated"
    )
    if result.dropped_events:
        print(f"  skipped events : {result.dropped_events} (invalid timestamps)")
    if result.duplicate_events:
        print(f"  duplicates     : {result.duplicate_events} (skipped by event ID)")

    for alert in sorted(
        result.alerts, key=lambda item: (-item.severity.score, item.first_seen)
    )[:20]:
        print(
            f"  [{alert.severity.label:8}] {alert.title}"
            f" -> {alert.entity} ({alert.event_count} events)"
        )

    if getattr(args, "notify", False):
        _print_notifications(notify_alerts(result.alerts, config.notifications))
    return 0


def _report(args: argparse.Namespace) -> int:
    store = AlertStore(args.db)
    alerts = store.fetch_alerts(severity=args.severity or None)
    if not alerts:
        print("No alerts stored yet. Run `cloudsentinel scan` first.")
        return 1

    exporters = {
        "csv": export_csv,
        "json": export_json,
        "html": export_html,
        "pdf": export_pdf,
    }
    exporter = exporters[args.format]
    try:
        destination = exporter(alerts, args.output)
    except RuntimeError as exc:
        print(f"Export failed: {exc}")
        return 1

    info = summary(alerts)
    print(
        f"Exported {info['total_alerts']} alerts"
        f" ({info['by_severity']['critical']} critical,"
        f" {info['by_severity']['high']} high) -> {destination}"
    )
    return 0


def _notify(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    if args.min_severity:
        config.notifications.min_severity = args.min_severity

    alerts = AlertStore(args.db).fetch_alerts()
    if not alerts:
        print("No alerts stored yet. Run `cloudsentinel scan` first.")
        return 1

    results = notify_alerts(alerts, config.notifications)
    if not results:
        print("Notifications are disabled. Enable them in cloudsentinel.toml.")
        return 1

    _print_notifications(results)
    return 0


def _print_notifications(results) -> None:
    if not results:
        print("  notifications  : disabled")
        return
    for result in results:
        status = "sent" if result.sent else "failed"
        print(f"  notification   : {result.channel} {status} — {result.detail}")


def _serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The API server requires uvicorn. Install dependencies with:")
        print("  python -m pip install -r requirements.txt")
        return 1

    from .api import create_app

    config = Config.load(args.config)
    token = (
        args.token
        if args.token is not None
        else os.environ.get("CLOUDSENTINEL_API_TOKEN", "")
    )
    origins = tuple(
        item.strip() for item in (args.cors or "*").split(",") if item.strip()
    )
    application = create_app(
        db_path=args.db,
        raw_dir=args.input,
        config=config,
        token=token,
        allow_scan=args.allow_scan,
        cors_origins=origins,
    )

    host = args.host
    print(f"CloudSentinel API  -> http://{host}:{args.port}/docs")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        if not token:
            print(
                "WARNING: the API is reachable on your network without a token. "
                "Use --token or CLOUDSENTINEL_API_TOKEN."
            )
        try:
            lan_ip = socket.gethostbyname(socket.gethostname())
            print(f"Phone server URL   -> http://{lan_ip}:{args.port}")
        except OSError:
            pass
    print("Press Ctrl+C to stop.")
    uvicorn.run(application, host=host, port=args.port, log_level="info")
    return 0


def _init(args: argparse.Namespace) -> int:
    store = AlertStore(args.db).init()
    print(f"Initialised alerts database at {store.path}")
    return 0


def _demo(args: argparse.Namespace) -> int:
    from .sampledata import write_sample_data

    paths = write_sample_data(args.out_dir, seed=args.seed)
    for path in paths:
        print(f"Generated {path}")

    result = scan_files(args.out_dir, args.db, Config(), reset=True)
    print(
        f"Scanned {result.events_scanned} events ->"
        f" {len(result.alerts)} alerts inserted"
    )
    for severity in sorted(Severity, key=sort_key):
        count = result.by_severity[severity.value]
        if count:
            print(f"  {severity.label:8} {count}")
    print(f"Dashboard: streamlit run cloudsentinel/dashboard.py")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
