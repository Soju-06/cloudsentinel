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
        help="bootstrap API token (defaults to CLOUDSENTINEL_API_TOKEN)",
    )
    serve.add_argument(
        "--token-file",
        default=None,
        help="rotating token store (default: data/api_tokens.json when it exists)",
    )
    serve.add_argument(
        "--tls-cert",
        default=None,
        help="PEM certificate chain; enables HTTPS (needs --tls-key)",
    )
    serve.add_argument(
        "--tls-key",
        default=None,
        help="PEM private key for --tls-cert",
    )
    serve.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        help="API requests per minute per client (0 disables; default 120)",
    )
    serve.add_argument(
        "--allow-scan",
        action="store_true",
        help="expose POST /api/scan to trigger detection scans remotely",
    )
    serve.add_argument(
        "--cors",
        default=None,
        help=(
            "comma-separated browser origins; default allows loopback only, "
            "use '*' to allow every origin"
        ),
    )

    tokens = subparsers.add_parser(
        "tokens", help="manage rotating API tokens (add, list, revoke)"
    )
    token_actions = tokens.add_subparsers(dest="token_action", required=True)

    token_add = token_actions.add_parser("add", help="create a token")
    token_add.add_argument("--label", default=None, help="human label, e.g. phone")
    token_add.add_argument("--token-file", default=None, help="token store path")

    token_list = token_actions.add_parser("list", help="show stored tokens")
    token_list.add_argument("--token-file", default=None, help="token store path")

    token_revoke = token_actions.add_parser(
        "revoke", help="revoke a token by label or fingerprint prefix"
    )
    token_revoke.add_argument("label", help="exact label, label prefix or digest prefix")
    token_revoke.add_argument("--token-file", default=None, help="token store path")

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
    if args.command == "tokens":
        return _tokens(args)
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
        print(f"  notification   : {result.channel} {status} - {result.detail}")


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _security_banner(
    host: str,
    *,
    tls: bool,
    bootstrap_token: bool,
    token_store=None,
    rate_limit: int | None,
) -> list[str]:
    """Human-readable security summary printed before the server starts."""
    active_tokens = token_store.active_count() if token_store is not None else 0

    if bootstrap_token and active_tokens:
        auth = f"bootstrap token + {active_tokens} rotating token(s)"
    elif active_tokens:
        auth = f"{active_tokens} rotating token(s)"
    elif bootstrap_token:
        auth = "single shared token (bootstrap)"
    elif token_store is not None:
        auth = "LOCKED - token store has no active tokens (use `tokens add`)"
    else:
        auth = "OPEN - no token configured"

    limit = rate_limit if rate_limit is not None else 120
    lines = [
        f"TLS            : {'on' if tls else 'off - plain HTTP'}",
        f"Authentication : {auth}",
        f"Rate limit     : {'off' if limit == 0 else f'{limit} req/min per client'}",
    ]

    if host not in _LOOPBACK_HOSTS:
        if not tls:
            lines.append(
                "WARNING: --host binds the API to your network. Without --tls-cert/"
                "--tls-key the token travels in plain text and can be captured by "
                "anyone on the same Wi-Fi."
            )
        if not bootstrap_token and not active_tokens and token_store is None:
            lines.append(
                "WARNING: the API is reachable on your network without a token. "
                "Add --token or create one with `python -m cloudsentinel tokens add`."
            )
    return lines


def _serve(args: argparse.Namespace) -> int:
    tls_cert = getattr(args, "tls_cert", None)
    tls_key = getattr(args, "tls_key", None)

    if args.rate_limit is not None and args.rate_limit < 0:
        print("error: --rate-limit must be 0 (disabled) or a positive number")
        return 2
    if bool(tls_cert) != bool(tls_key):
        print("error: --tls-cert and --tls-key must be given together")
        return 2
    for path, flag in ((tls_cert, "--tls-cert"), (tls_key, "--tls-key")):
        if path and not Path(path).is_file():
            print(f"error: {flag} file not found: {path}")
            return 2

    try:
        import uvicorn
    except ImportError:
        print("The API server requires uvicorn. Install dependencies with:")
        print("  python -m pip install -r requirements.txt")
        return 1

    from .api import create_app
    from .tokens import DEFAULT_TOKEN_PATH, TokenError, TokenStore

    config = Config.load(args.config)
    token = (
        args.token
        if args.token is not None
        else os.environ.get("CLOUDSENTINEL_API_TOKEN", "")
    )

    token_store = None
    token_file = Path(args.token_file) if args.token_file else DEFAULT_TOKEN_PATH
    if Path(token_file).exists() or args.token_file:
        try:
            token_store = TokenStore(token_file)
        except TokenError as exc:
            print(f"error: {exc}")
            return 2

    origins = (
        None
        if args.cors is None
        else tuple(item.strip() for item in args.cors.split(",") if item.strip())
    )
    application = create_app(
        db_path=args.db,
        raw_dir=args.input,
        config=config,
        token=token,
        allow_scan=args.allow_scan,
        cors_origins=origins,
        token_store=token_store,
        rate_limit=args.rate_limit,
    )

    host = args.host
    scheme = "https" if tls_cert else "http"
    print(f"CloudSentinel API  -> {scheme}://{host}:{args.port}/docs")
    for line in _security_banner(
        host,
        tls=bool(tls_cert),
        bootstrap_token=bool(token),
        token_store=token_store,
        rate_limit=args.rate_limit,
    ):
        print(f"  {line}")

    if host not in _LOOPBACK_HOSTS:
        try:
            lan_ip = socket.gethostbyname(socket.gethostname())
            print(f"Phone server URL   -> {scheme}://{lan_ip}:{args.port}")
        except OSError:
            pass
        if tls_cert:
            print(
                "  Tip: install the certificate as trusted on each device, "
                "or the client will reject the HTTPS connection."
            )

    print("Press Ctrl+C to stop.")
    uvicorn.run(
        application,
        host=host,
        port=args.port,
        log_level="info",
        ssl_certfile=tls_cert,
        ssl_keyfile=tls_key,
    )
    return 0


def _tokens(args: argparse.Namespace) -> int:
    from .tokens import TokenError, TokenStore

    try:
        store = TokenStore(args.token_file)
    except TokenError as exc:
        print(f"error: {exc}")
        return 2

    if args.token_action == "add":
        try:
            plaintext, record = store.add(label=args.label)
        except TokenError as exc:
            print(f"error: {exc}")
            return 2
        print("New API token - shown once, store it now:")
        print(f"  {plaintext}")
        print(f"  label      : {record.label}")
        print(f"  fingerprint: {record.digest[:8]}")
        print(f"  store      : {store.path}")
        print()
        print("Clients send it as X-API-Token (or Authorization: Bearer <token>).")
        print("Revoke later with: python -m cloudsentinel tokens revoke <label>")
        return 0

    if args.token_action == "list":
        items = store.listing()
        if not items:
            print("No tokens stored.")
            return 0
        state_width = 8
        print(f"{'LABEL':<18} {'FINGERPRINT':<12} {'CREATED':<22} STATE")
        for item in items:
            state = "active" if item["active"] else "revoked"
            print(
                f"{item['label']:<18} {item['fingerprint']:<12} "
                f"{item['created']:<22} {state:<{state_width}}"
            )
        print(f"\nStore: {store.path}")
        return 0

    if args.token_action == "revoke":
        revoked = store.revoke(args.label)
        if revoked:
            print(f"Revoked {revoked} token(s) matching '{args.label}'.")
            print("Active connections continue until their next request.")
            return 0
        print(f"No active token matched '{args.label}'.")
        return 1

    return 2


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
