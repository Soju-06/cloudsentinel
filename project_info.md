# CloudSentinel — Project Information

## Overview
CloudSentinel is a Python cloud-security monitoring and threat-detection lab.
It ingests cloud audit logs, normalises them into a vendor-neutral schema, runs
four detection engines, persists de-duplicated alerts in SQLite, and presents
them in a futuristic Streamlit console with CSV/JSON/HTML/PDF reporting and
Slack/webhook/email notifications. A FastAPI service exposes the same alert
store to native Flutter clients: a sideloadable Android APK and a portable
Windows desktop app.

## Goal
Build a tool that analyses cloud audit logs and flags suspicious activity, with
automated tests and first-class AWS CloudTrail support.

## Key features
- Detect repeated failed logins (sliding window, compromise escalation,
  cross-IP distributed bursts).
- Detect impossible travel between consecutive successful logins.
- Flag potentially public cloud storage (bucket policies and canned ACLs).
- Detect potentially excessive IAM permissions (wildcards, admin policies).
- Display alerts with severity levels in a Streamlit dashboard.
- Export security reports as CSV/JSON/HTML/PDF.
- Notify Slack, generic webhooks and SMTP recipients.
- Automated pytest suite, CloudTrail/CloudWatch adapters, gzip ingestion.
- REST API (FastAPI) with bearer/X-API-Token auth, rotating token store,
  native HTTPS, rate limiting, filters and opt-in remote scanning.
- Native Flutter Android console compiled to a release APK.
- Portable Windows app: the same Flutter UI in a .NET/WebView2 shell.
- Docker + docker-compose packaging for the console.

## Tech stack
- Python 3.11+ (developed on 3.14)
- Streamlit 1.66 for the dashboard
- FastAPI + uvicorn for the mobile-facing REST API
- SQLite for alert persistence
- Pandas for ingestion, normalisation and export
- Pytest for the Python test suite
- Plotly for the console charts
- fpdf2 for PDF reports
- Flutter 3.47 / Dart 3.13 for the Android client
- Flutter web + .NET Framework 4.8 / WebView2 for the Windows client
- AWS CloudTrail concepts for the AWS adapter

## Architecture
```
data/raw/*.json|jsonl|csv|gz
        │
        ▼
   ingest.py (format detection, gzip, CloudTrail/CloudWatch adapter,
              duplicate-ID suppression)
        │  canonical event DataFrame
        ▼
 detectors/ (brute_force · impossible_travel · public_storage · iam_permissions)
        │  Alert objects
        ▼
   db.py (SQLite: fingerprint upsert, suppression merge)
        │
        ├──► dashboard.py (Streamlit console)
        ├──► report.py (CSV / JSON / HTML / PDF)
        ├──► notify.py (Slack / webhook / SMTP)
        └──► api.py (FastAPI) ──► mobile/ Flutter APK + Windows app
```

### Hybrid storage decision
- Raw events → JSON/JSONL/CSV/gzip files in `data/raw/` (source of truth).
- Alerts → `data/sentinel.db` (history, filtering, de-duplication).
- Re-scanning is idempotent thanks to deterministic fingerprints plus a
  configurable suppression window.

## Alert model
| Field | Meaning |
|---|---|
| detector | `brute_force`, `impossible_travel`, `public_storage`, `iam_permissions` |
| severity | CRITICAL · HIGH · MEDIUM · LOW · INFO |
| title / description | human-readable finding |
| entity / entity_type | impacted user, IP, bucket or IAM principal |
| event_count | events contributing to the finding |
| first_seen / last_seen | detection window |
| evidence | JSON indicators, coordinates, source IPs and event IDs |
| fingerprint | stable identity for idempotent rescans |

## Detection rules
1. **Repeated failed logins** — ≥5 failures in 10 minutes per user+IP.
   Escalates to CRITICAL at ≥15 failures or a successful login within
   30 minutes of the burst (possible compromise). With
   `correlate_across_ips`, ≥5 failures for one user across multiple IPs produce
   a single "Distributed failed logins" alert instead of zero per-IP alerts.
2. **Impossible travel** — consecutive successful logins ≥500 km apart within
   3 hours (HIGH), or ≥5,000 km within 1 hour (CRITICAL). Geolocation comes
   from event coordinates (default), a local MaxMind database, or an optional
   HTTP lookup.
3. **Public storage** — public `Principal: "*"` bucket policies, wildcard
   policy actions, `public-read` / `public-read-write` ACLs,
   `authenticated-read` grants and explicit public flags. `Principal` may be a
   string, list or `{"AWS": ...}` object.
4. **Excessive IAM** — wildcard `Action`/`Resource`, and
   `AdministratorAccess` / `PowerUserAccess` attachments. Scoped to IAM events
   to avoid cross-service false positives.

## Configuration
`cloudsentinel.toml` or `config.json` at the project root; thresholds, windows,
grouping mode, enabled detectors, travel/geolocation settings, notification
channels and suppression window are configurable. Secrets can be supplied via
environment variables.

## Usage
```powershell
python -m pip install -r requirements.txt
python -m cloudsentinel demo              # sample logs + scan
python -m cloudsentinel scan              # scan data/raw
python -m cloudsentinel scan --notify     # scan + send notifications
python -m cloudsentinel report -f html    # export alerts
python -m cloudsentinel notify            # re-send stored alerts
python -m cloudsentinel serve             # REST API for the Android app
python -m cloudsentinel serve --host 0.0.0.0 --token SECRET \
  --tls-cert certs/cloudsentinel-dev.pem --tls-key certs/cloudsentinel-dev-key.pem
python -m cloudsentinel tokens add --label phone   # rotating token
python -m cloudsentinel tokens list
python -m cloudsentinel tokens revoke phone
streamlit run cloudsentinel/dashboard.py  # console
python -m pytest                          # 192 tests (1 skipped)
python scripts/benchmark.py --events 100000
```

## Dashboard
- OVERVIEW: severity donut, alert timeline, detections by engine, top-risk
  entities.
- ALERT FEED: severity badges, entity, event counts, timestamps.
- EXPORTS: CSV/JSON/HTML/PDF downloads and JSON summary.
- Sidebar: filters, on-demand scan, demo loader, send-alerts action, status.

## Test suite
192 pytest tests (1 skipped on Windows) covering ingestion (JSON/JSONL/CSV/gzip/
CloudTrail/CloudWatch Logs), duplicate IDs, corrupt records, timezone handling,
detector boundaries and severity matrices, cross-IP correlation, impossible
travel, SQLite merge/suppression behaviour, report shapes (including PDF magic
bytes), notification transports, configuration, CLI round trips, REST API
auth/filters/pagination/scan gating, API hardening (token rotation, rate limits,
CORS, security headers, TLS flags, certificate SANs) and end-to-end sample data.
A genuine AWS CloudWatch Logs subscription fixture lives in `tests/fixtures/`.

The Flutter client adds 25 Dart tests (`flutter test`): URL normalisation,
tolerant model parsing, token headers, 401/403 error paths, filter query
encoding, network failure handling, timestamp formatting, connect-screen
widget behaviour, the connection-recovery flow (serve-command builder,
copy-to-clipboard, change-server prefill and preference clearing) and the golf
animation (one-shot play, replay on retry, reduced-motion fallback).
`flutter analyze` reports no issues.

## Hardening & scale (Phase 12)
- CloudWatch Logs subscription payloads (`logEvents[].message`) unwrapped.
- gzip (`.gz`) ingestion, including compressed JSON Lines.
- Duplicate CloudTrail event IDs skipped; duplicates reported in scan stats.
- Corrupt/non-object/invalid-timestamp records dropped without aborting.
- Mixed timezone offsets normalised to UTC; naive timestamps treated as UTC.
- Split-IP brute-force correlation; single-IP bursts not double-reported.
- Vectorised detector pre-filters and single-pass policy/flag scanning.
- 100k-event benchmark harness with median-of-N timing.

## API & Android client (Phase 13)
- `cloudsentinel/api.py` — FastAPI factory with `/health`, `/api/summary`,
  `/api/alerts` (severity/detector/search/since/until + limit/offset),
  `/api/alerts/{id}`, `/api/detectors` and opt-in `POST /api/scan`.
- Shared-token auth via `X-API-Token` (`secrets.compare_digest`); the API is
  open only when no token is configured.
- `python -m cloudsentinel serve --host 0.0.0.0 --port 8080 --token …`
  prints the LAN URL for the phone; `--allow-scan` gates remote scans.
- Flutter client in `mobile/cloudsentinel_mobile`: neon theme, connection gate
  with health check, metric cards, severity/detector chips, search, alert feed,
  detail view with evidence and copy-to-clipboard, settings with diagnostics.
- Connection-recovery screen: when the saved server is unreachable, the client
  shows the attempted address, the exact `serve` command (with `--host 0.0.0.0`
  on Android) plus a copy button, RETRY, and CHANGE SERVER — which forgets the
  saved connection but pre-fills the form with it.
- Release APK built with Flutter/Gradle; copy at
  `dist/CloudSentinel-1.0.0.apk` (debug signing, sideload only).
- Android manifest: `INTERNET`, `ACCESS_NETWORK_STATE`, cleartext enabled for
  LAN HTTP, custom adaptive launcher icon and dark launch screen.

## Windows desktop app (Phase 14)
- The Flutter client gained a web target; the Dart API layer no longer depends
  on `dart:io`, so one codebase serves Android and the desktop shell.
- `windows/Program.cs` — WinForms + WebView2 host with an embedded loopback
  static server (avoids HttpListener URL ACLs, so no admin rights), dark title
  bar, DPI-aware layout, F5 reload, optional DevTools and `--server/--token`
  auto-connect for shortcuts.
- `windows/build_windows.ps1` builds the web bundle, caches the WebView2 SDK in
  `.build-cache`, prunes unreachable WebAssembly payloads and compiles
  `app/CloudSentinel.exe` (~21 MB) with the .NET Framework compiler.
- Verified live against the running API: 10 alerts / 5 critical rendered; the
  browser viewport matches the window at 125 % display scaling
  (`devicePixelRatio` 1.25) after disabling WinForms autoscaling.
- `INSTALL.md` documents server setup, Windows launch, Android sideload and
  troubleshooting.

## Connection recovery & motion (Phase 15)
- `lib/serve_command.dart` derives the exact `serve` invocation from the URL the
  client tried, adding `--host 0.0.0.0` on Android and reusing the saved port.
- `ConnectionLostView` states that the client is only a viewer, shows the
  command with a copy button, and offers RETRY plus CHANGE SERVER. Changing the
  server clears the stored URL/token but pre-fills the connect form with them.
- `lib/widgets/golf_attempt.dart` draws a one-shot golf scene with a custom
  painter: backswing, arcing flight, two bounces, a roll that stops beside the
  hole, flag flutter and a fading "SO CLOSE" caption. RETRY replays it; reduced
  motion jumps to the final frame. No assets, no packages, no infinite ticker.
- The Windows shell gained `--screenshot FILE` and `--screenshot-delay MS`, so
  either state can be captured off-screen even when another window covers it.

## Secure API & network (Phase 16)
- `cloudsentinel/tokens.py` — rotating token store at `data/api_tokens.json`:
  256-bit `secrets.token_urlsafe` tokens, salted SHA-256 fingerprints only,
  constant-time verification against every active token, atomic owner-only
  writes. `add`, `list`, `revoke` (label, label prefix or fingerprint prefix).
  Revoking the last token **locks** the API instead of opening it.
- `cloudsentinel/ratelimit.py` — dependency-free sliding-window limiter keyed by
  client IP plus a truncated token hash; bounded client map; `429` with
  `Retry-After`. `/health` is exempt, `/api/scan` gets one tenth of the budget.
- `api.py` accepts `X-API-Token` and `Authorization: Bearer`, combines the
  bootstrap token with the store, adds security headers (`nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`), loopback-only CORS by
  default, and uniform `422`/`500` JSON bodies that never echo internals.
  `/health` now reports `auth_required`, `auth_mode` and both rate limits.
- `cli.py` serve flags: `--tls-cert`/`--tls-key` (uvicorn-native TLS),
  `--rate-limit`, `--token-file`; a startup banner states TLS/auth/rate posture
  and warns on plain-HTTP or tokenless LAN binds. New `tokens` subcommand.
- `scripts/make_dev_cert.py` — self-signed RSA-2048/SHA-256 certificate with SANs
  for localhost, machine name, loopback and detected LAN IP; prints Windows and
  Android trust steps. `cryptography` added to requirements.
- `tests/test_security.py` — 36 tests; full suite 191 passed, 1 skipped.
- Verified live: HTTPS 8443 with `curl --cacert` (health 200, missing token 401,
  header and bearer 200, sixth request 429 + `retry-after: 60`), and the plain
  HTTP banner/429 path on `0.0.0.0`.
- Documentation: `SECURITY.md` (threat model, rotation runbook, TLS/Android
  caveat, deployment checklist) plus refreshed `INSTALL.md` and `README.md`.

## Design decisions
- Generic-first schema keeps the detectors vendor-neutral.
- CloudTrail adapter maps `eventName`, `errorCode`, `sourceIPAddress`,
  `userIdentity` and `requestParameters` into the canonical schema.
- Alert fingerprints + suppression produce one evolving incident per entity.
- Dashboard styling deliberately comes after functional verification.
- Detector pre-filters are conservative: they narrow candidates, while the
  full analysis remains the source of truth.

## Severity levels
- **CRITICAL** — immediate response (public read/write bucket, full wildcard IAM, impossible travel, likely compromise).
- **HIGH** — triage within 24h (public-read bucket, failed-login burst, admin policy, slow impossible travel).
- **MEDIUM** — review (authenticated-read ACL, wildcard resource only).
- **LOW / INFO** — reserved for future rules.

## Known limitations
- The Streamlit dashboard is unauthenticated; the API uses shared tokens, not
  per-user accounts. Neither is ready for public internet exposure.
- Native TLS works for Windows/browsers, but Flutter's HTTP stack ignores the
  Android user CA store, so a self-signed certificate cannot secure the APK;
  phones need a publicly trusted certificate or a VPN.
- Token store and rate limiter are file-backed and per-process; multi-worker
  deployments would need a shared store and secret manager.
- CloudTrail ingestion is file/export based, not a live event stream.
- Detections are batch-only; there is no streaming, baselining or threat intel.
- Alerts have no triage workflow (acknowledge/assign/close).
- The Docker image was not built in this environment (no Docker CLI).
- The APK is debug-signed, Android-only, has no push notifications and no
  offline cache.
- The Windows app is a WebView2 shell around the Flutter web build; a native
  Flutter Windows runner would require the MSVC toolchain.
- The HTTP geolocation backend shares IPs with a third party.
- Alerts are stored locally in SQLite; there is no multi-user backend.

## Roadmap
1. ✅ MVP: ingestion, three detectors, SQLite alerts, dashboard, exports, tests.
2. ✅ AWS CloudTrail adapter and de-duplication.
3. ✅ IP geolocation / impossible-travel detection.
4. ✅ Slack/webhook/email notifications.
5. ✅ HTML/PDF report export and Docker packaging.
6. ✅ Hardening: CloudWatch wrappers, gzip, duplicates, mixed timezones,
   corrupt records, cross-IP bursts, 100k benchmark.
7. ✅ REST API + native Flutter Android APK (Phase 13).
8. ✅ Windows desktop app + release packaging (Phase 14).
9. ✅ Connection-recovery UX with start-command hint and golf animation
   (Phase 15).
10. ✅ Secure API & network: rotation, TLS, rate limits, CORS, security docs
    (Phase 16).
11. ⬜ Alert triage state, streaming ingestion, per-user auth.
12. ⬜ Additional detections (MFA/root/key/security-group/CloudTrail tampering).

## Project status
Phases 0–16 complete and verified:
- 191 Python tests passing (1 skipped on Windows); 25/25 Flutter tests passing;
  `flutter analyze` reports no issues.
- Demo dataset: 210 events → 10 alerts (5 critical, 5 high), all four engines.
- Dashboard headless run: 0 exceptions, 3 tabs, 3 actions, 4 export formats.
- API verified live: `/health` returns version 0.3.0 and 10 alerts, tokenless
  `/api/summary` is rejected with 401, token requests return the summary.
- Security verified live: HTTPS on 8443 with a generated certificate (health
  200, no token 401, `X-API-Token` 200, bearer 200, 6th request 429 with
  `retry-after: 60`); plain-HTTP LAN banner warns about unencrypted tokens.
- Android release APK rebuilt from final source and copied to
  `dist/CloudSentinel-1.0.0.apk` (49.8 MB, debug signing; sideload).
  SHA-256 `9AC7D8128AD48974DB289A01F408AD067562A1E12D2F82E8ABD4FCD2EE08F24D`.
- Windows app built at `app/CloudSentinel.exe` (20.7 MB) and verified live
  against the API; viewport/DPI probe matches the window at 125 % scaling.
- Connection-recovery screen verified by off-screen render in both states:
  server offline (error screen with command, golf scene at rest) and server
  online (dashboard).
- Benchmark: ~5.6 s median for 100k events (~18k events/s end-to-end) on a
  quiet machine; slower when antivirus is active.
- Docker CLI unavailable on the development machine, so image build untested.
