# 🛡️ CloudSentinel

**Cloud Security Monitoring & Threat Detection Lab**

Ingest cloud audit logs, detect suspicious activity with four purpose-built
detectors, and investigate findings in a futuristic Streamlit security console
or the native Android and Windows apps.

```
raw logs ──► ingest/normalise ──► detectors ──► SQLite alerts ──► Streamlit console
(JSON/JSONL/CSV/gz)  (Pandas)      (4 engines)   (deduplicated)     + CSV/JSON/HTML/PDF
                                                                   + Slack/webhook/email
                                                                   + REST API ──► Android APK
                                                                                └► Windows app
```

---

## Highlights

- **Repeated failed logins** — sliding-window detection with automatic
  compromise escalation when a successful login follows a burst. Bursts split
  across multiple source IPs are correlated into one distributed attack.
- **Impossible travel** — compares consecutive successful logins per user and
  flags physically impossible movement using great-circle distance.
- **Public cloud storage** — flags public bucket policies (`Principal: "*"`),
  public-read / public-read-write ACLs and explicit public exposure flags.
- **Excessive IAM permissions** — detects wildcard actions/resources and
  administrative managed-policy attachments, including CloudTrail's
  URL-encoded policy documents.
- **Hybrid storage** — raw events stay in files (`data/raw/`); only alerts are
  persisted in SQLite for history, filtering and de-duplication.
- **Zero-duplicate rescans** — fingerprints + a suppression window merge repeat
  findings instead of flooding the dashboard. Duplicate CloudTrail deliveries
  are skipped by event ID during ingestion.
- **Real-world ingestion** — CloudTrail `Records` dumps, CloudWatch Logs
  subscription payloads (`logEvents[].message`), gzip objects, JSON Lines and
  CSV, with corrupt records skipped instead of crashing the scan.
- **Notifications** — Slack webhooks, generic JSON webhooks and SMTP email,
  with environment-variable secrets and redacted logs.
- **Reporting** — CSV, JSON, standalone HTML and PDF exports.
- **REST API** — FastAPI service (`serve` command) exposing summary, alerts,
  filters, pagination, detector metadata and an opt-in remote scan trigger,
  protected by a shared `X-API-Token`.
- **Native Android app** — a real Flutter APK (not a WebView wrapper) with the
  same neon design: metrics, severity/detector filters, search, alert detail,
  evidence viewer, connection diagnostics and an optional one-tap scan.
- **Windows desktop app** — the same Flutter UI packaged as a portable
  `.exe` (`app\`) with an embedded WebView2 shell, dark title bar, DPI-correct
  rendering and `--server/--token` auto-connect. No installer or admin rights.
- **Futuristic console** — dark glassmorphism theme, neon severity badges,
  Plotly charts, top-risk entities and one-click exports.
- **Docker** — `Dockerfile` + `docker-compose.yml` for a reproducible console.
- **156 automated Python tests** plus **23 Flutter tests** covering ingestion,
  every detector, storage, reporting, notifications, configuration, CLI, API
  auth/filters, hardening scenarios, the Dart API client and app boot flow.

---

## Quick start

```powershell
# 1. Install dependencies
python -m pip install -r requirements.txt

# 2. Generate demo telemetry and run a detection scan
python -m cloudsentinel demo

# 3. Launch the console
streamlit run cloudsentinel/dashboard.py
```

Open http://localhost:8501.

The demo dataset contains **210 events** across two sources (generic JSON + a
CloudTrail dump) and produces **10 alerts — 5 critical, 5 high** — covering all
four detectors, including an Ashburn → Moscow impossible-travel login.

### Docker (optional)

```powershell
docker compose up --build
# console at http://localhost:8501; data/ and reports/ are mounted
```

The Docker files are provided but were not built in this environment (no
Docker CLI available on the development machine).

---

## Using your own logs

Drop files into `data/raw/` and run:

```powershell
python -m cloudsentinel scan
```

Supported formats:

| Format | Example |
|---|---|
| JSON array | `[{ "timestamp": "...", "event_name": "..." }]` |
| JSON Lines | one JSON object per line (`*.jsonl`, `*.ndjson`) |
| CSV | columns such as `timestamp,event_name,user,source_ip,status` |
| AWS CloudTrail (S3) | `{ "Records": [ { "eventName": "...", ... } ] }` |
| AWS CloudWatch Logs | `{ "logEvents": [ { "message": "{...CloudTrail...}" } ] }` |
| gzip | any of the above as `*.gz`, including native CloudTrail objects |

### Generic event schema

Only `timestamp` is mandatory; everything else degrades gracefully.

| Field | Description |
|---|---|
| `timestamp` | ISO-8601 string or epoch seconds/milliseconds (UTC) |
| `event_source` | Service name, e.g. `aws.s3`, `aws.iam`, `aws.signin` |
| `event_name` | Action, e.g. `ConsoleLogin`, `PutBucketPolicy` |
| `user` | Actor / principal |
| `source_ip` | Originating IP address |
| `resource` | Bucket, role, object or other target |
| `status` | `success` / `failure` (aliases like `failed`, `denied` normalised) |
| `error_code` | Optional failure reason |
| `raw` | Full original record (kept for evidence) |

Common aliases are accepted automatically (`time`, `@timestamp`, `username`,
`action`, `src_ip`, `result`, …). Timezone offsets are normalised to UTC;
naive timestamps are treated as UTC.

### Geolocation for impossible travel

`impossible_travel` supports three enrichment backends:

| Backend | Behaviour |
|---|---|
| `event` (default) | Reads `latitude`/`longitude`/`country`/`city` from the log — fully offline |
| `maxmind` | Looks up IPs in a local GeoLite2/GeoIP2 database (`pip install geoip2`) |
| `http` | Calls the free `ipapi.co` service (sends IPs to a third party) |

---

## Detection rules

### 1. Repeated failed logins — `brute_force`

| Setting | Default |
|---|---|
| Threshold | 5 failures |
| Window | 10 minutes |
| Grouping | user + source IP |
| Escalation | CRITICAL at 15 failures or a successful login within 30 minutes of the burst |
| Cross-IP correlation | 5+ failures for one user across multiple IPs → one distributed alert |

Detection uses a sliding window, so a burst is found even when surrounding
noise is present. Login events are matched by name (`ConsoleLogin`, `SignIn`,
`Login`, …) and only failures count.

### 2. Impossible travel — `impossible_travel`

| Condition | Severity |
|---|---|
| ≥ 5,000 km within 1 hour | **CRITICAL** |
| ≥ 500 km within 3 hours | **HIGH** |

Only successful logins with resolvable coordinates are compared. The alert
evidence records both endpoints, distance, elapsed time and implied speed.

### 3. Public cloud storage — `public_storage`

- Policy documents with `"Principal": "*"` → **HIGH**
- Wildcard principal **and** wildcard action → **CRITICAL**
- `public-read` ACL / `AllUsers` grant → **HIGH**
- `public-read-write` ACL → **CRITICAL**
- `authenticated-read` ACL → **MEDIUM**
- Explicit `"public": true` style flags → **HIGH**

`Principal` is understood in every shape AWS emits: `"*"`, `["*"]`,
`{"AWS": "*"}`, `{"AWS": ["*"]}` and mixed account lists.

### 4. Excessive IAM permissions — `iam_permissions`

- `Action: "*"` + `Resource: "*"` → **CRITICAL**
- `Action: "*"` only → **HIGH**
- `Resource: "*"` only → **MEDIUM**
- `AdministratorAccess` / `PowerUserAccess` attachment → **HIGH**

Only IAM-related events are evaluated, so an S3 bucket policy that uses
`Principal: "*"` is not misreported as an IAM over-grant.

---

## CLI reference

```text
python -m cloudsentinel scan [-i PATH] [-d DB] [-c CONFIG] [--reset] [--notify]
python -m cloudsentinel report [-f csv|json|html|pdf] [-o FILE] [--severity ...]
python -m cloudsentinel notify [-d DB] [-c CONFIG] [--min-severity ...]
python -m cloudsentinel init [-d DB]
python -m cloudsentinel demo [-o RAW_DIR] [--seed N]
python -m cloudsentinel serve [--host H] [--port P] [--token T] [--allow-scan]
```

Examples:

```powershell
# Scan and clear previous alerts
python -m cloudsentinel scan --reset

# Scan and push new findings to Slack/email
python -m cloudsentinel scan --notify

# Export only critical + high findings
python -m cloudsentinel report -f json --severity critical high -o reports/triage.json

# Printable HTML / PDF reports
python -m cloudsentinel report -f html -o reports/latest.html
python -m cloudsentinel report -f pdf  -o reports/latest.pdf

# Re-send stored alerts through configured channels
python -m cloudsentinel notify --min-severity critical
```

The scan summary reports dropped records (invalid timestamps) and duplicate
records skipped by event ID, so data-quality problems are visible.

---

## REST API

The mobile app and any other client read from a small FastAPI service:

```powershell
# Local development (open, no token)
python -m cloudsentinel serve

# Phone on the same Wi-Fi (token required, LAN-visible)
python -m cloudsentinel serve --host 0.0.0.0 --port 8080 --token YOUR_TOKEN --allow-scan
```

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | public | version, stored alert count, auth/scan flags |
| `GET /api/summary` | token | totals by severity/detector, entities, DB stats |
| `GET /api/alerts` | token | filtered/paginated alerts (`severity`, `detector`, `search`, `since`, `until`, `limit`, `offset`) |
| `GET /api/alerts/{id}` | token | one alert including evidence |
| `GET /api/detectors` | token | detector labels for client filter chips |
| `POST /api/scan` | token | re-scan `data/raw` (only with `--allow-scan`) |

Authentication uses the `X-API-Token` header. When no token is configured the
API is open — acceptable only on localhost or a trusted LAN. CORS defaults to
`*` for browser clients and can be narrowed with `--cors`.

Interactive docs: http://localhost:8080/docs

Environment equivalents: `CLOUDSENTINEL_API_TOKEN`,
`CLOUDSENTINEL_API_ALLOW_SCAN=true`.

---

## Android app

A genuine signed-with-debug-key release APK is produced by Flutter:

```powershell
cd mobile/cloudsentinel_mobile
flutter pub get
flutter build apk --release
# artifact: build/app/outputs/flutter-apk/app-release.apk
```

The ready-to-sideload build is also copied to **`dist/CloudSentinel-1.0.0.apk`**.

### Install and connect

1. Start the API on your computer with `--host 0.0.0.0 --token YOUR_TOKEN`.
2. Put the phone on the same Wi-Fi network.
3. Copy the APK to the phone (USB, `adb install`, or a file share) and allow
   installation from unknown sources.
4. Open **CloudSentinel**, enter `http://<computer-LAN-IP>:8080` and the token.
5. The app verifies `/health` and `/api/summary` before saving the connection.

The server prints the correct LAN URL at startup. Android 9+ blocks plain HTTP
by default; the manifest enables cleartext traffic so LAN testing works. For
anything beyond a lab, terminate TLS in front of the API (Caddy/nginx) and use
an `https://` URL.

The APK uses Flutter's generated debug signing config, which is fine for
sideloading and demos but **not** suitable for Google Play. Replace it with your
own keystore before publishing.

---

## Windows desktop app

The same Flutter UI runs as a portable Windows application in **`app/`**:

```
app/
├── CloudSentinel.exe                 # native WebView2 shell (C#)
├── Microsoft.Web.WebView2.*.dll      # WebView2 SDK
├── WebView2Loader.dll
└── web/                              # compiled Flutter UI
```

Double-click `CloudSentinel.exe`, enter `http://127.0.0.1:8080` and your token.
The connection is remembered. There is no installer and no administrator
requirement — the folder can be copied anywhere.

If the remembered server is no longer running, the app shows **CONNECTION LOST**
with the exact `serve` command and a copy button, plus **RETRY** and
**CHANGE SERVER** (which pre-fills the address so you only fix what changed).

A shortcut can skip the connect screen:

```powershell
"C:\Users\SOJUS\Desktop\CYBER\app\CloudSentinel.exe" --server http://127.0.0.1:8080 --token YOUR_TOKEN
```

`--devtools` enables F12/right-click developer tools. Windows SmartScreen may
warn about an unsigned executable on first launch: **More info → Run anyway**.
The WebView2 runtime ships with Microsoft Edge on Windows 10/11.

Rebuild with:

```powershell
powershell -ExecutionPolicy Bypass -File windows\build_windows.ps1
```

The script builds the Flutter web bundle, caches the WebView2 SDK in
`.build-cache`, prunes unreachable WebAssembly payloads and compiles the shell
with the .NET Framework compiler bundled with Windows. A native Flutter Windows
target would need the MSVC/Visual Studio C++ toolchain; this shell reproduces the
same UI without that dependency.

Step-by-step instructions, including the Android sideload flow and
troubleshooting, are in **[INSTALL.md](INSTALL.md)**.

---

## Configuration

Copy `cloudsentinel.example.toml` to `cloudsentinel.toml` (or use
`config.json`) and adjust thresholds. The file is auto-discovered at the
project root.

```toml
[brute_force]
threshold = 5
window_minutes = 10
critical_multiplier = 3
correlate_across_ips = true
group_by = "user_ip"          # user_ip | user | ip

[public_storage]
enabled = true

[iam]
enabled = true

[impossible_travel]
enabled = true
min_distance_km = 500
max_travel_hours = 3
critical_distance_km = 5000
critical_travel_hours = 1

[impossible_travel.geoip]
backend = "event"             # event | maxmind | http

[notifications]
enabled = false
min_severity = "high"
# slack_webhook_url = "https://hooks.slack.com/services/..."
# webhook_url = "https://your-siem.example/ingest/cloudsentinel"
# smtp_host = "smtp.example.com"
# email_to = ["security@example.com"]

suppression_minutes = 60      # merge repeat findings inside this window
```

Per-run override:

```powershell
python -m cloudsentinel scan -c my-config.toml
```

Environment overrides: `CLOUDSENTINEL_DATA`, `CLOUDSENTINEL_RAW`,
`CLOUDSENTINEL_DB`, `CLOUDSENTINEL_REPORTS`, `CLOUDSENTINEL_API_TOKEN`,
`CLOUDSENTINEL_API_ALLOW_SCAN`, plus secret-friendly
`CLOUDSENTINEL_SLACK_WEBHOOK`, `CLOUDSENTINEL_WEBHOOK_URL`,
`CLOUDSENTINEL_SMTP_PASSWORD`, `CLOUDSENTINEL_SMTP_HOST`,
`CLOUDSENTINEL_SMTP_USERNAME`, `CLOUDSENTINEL_EMAIL_FROM`,
`CLOUDSENTINEL_EMAIL_TO`.

---

## Dashboard

`streamlit run cloudsentinel/dashboard.py`

- **OVERVIEW** — severity donut, stacked alert timeline, detections by engine,
  top-risk entities ranked by aggregated severity.
- **ALERT FEED** — filterable table with severity badges, evidence descriptions
  and affected entities.
- **EXPORTS** — one-click CSV, JSON, HTML and PDF downloads plus a JSON summary.
- Sidebar: severity/detector filters, time window, free-text search, on-demand
  detection scan, demo loader, "send alerts" action and system status.

---

## Benchmark

`scripts/benchmark.py` generates synthetic telemetry, then measures ingestion,
detection and SQLite persistence separately:

```powershell
python scripts/benchmark.py --events 100000 --repeats 3
```

Reference run (100,019 events, 22 MB, Windows / Python 3.14, median of 3):

| Phase | Time |
|---|---|
| Ingest + normalise | ~2.7 s (~37k events/s) |
| Run four detectors | ~2.9 s |
| Persist to SQLite | ~0.01 s |
| **Total** | **~5.6 s (~18k events/s end-to-end)** |

Timings depend heavily on disk/antivirus activity; the script reports both the
median and the best run. Large-scan optimisations include vectorised detector
pre-filters, a single policy/flag tree walk per event, and pre-built record
dicts instead of `iterrows`.

---

## Project structure

```
cloudsentinel/
├── cloudsentinel/
│   ├── adapters/cloudtrail.py   # CloudTrail + CloudWatch Logs → generic schema
│   ├── api.py                   # FastAPI service for the mobile client
│   ├── detectors/               # brute force, travel, storage, IAM, policies
│   ├── cli.py                   # scan / report / notify / init / demo / serve
│   ├── config.py                # dataclass config + TOML/JSON loading
│   ├── dashboard.py             # Streamlit console
│   ├── db.py                    # SQLite alert repository
│   ├── geoip.py                 # event / MaxMind / HTTP geolocation
│   ├── ingest.py                # JSON / JSONL / CSV / gzip normalisation
│   ├── models.py                # Alert dataclass + fingerprints
│   ├── notify.py                # Slack / webhook / SMTP notifications
│   ├── pipeline.py              # orchestration and persistence
│   ├── report.py                # CSV / JSON / HTML / PDF exports
│   ├── sampledata.py            # deterministic incident dataset
│   ├── severity.py              # CRITICAL/HIGH/MEDIUM/LOW/INFO
│   └── utils.py                 # timestamp + JSON helpers
├── mobile/cloudsentinel_mobile/ # native Flutter client (Android + web)
│   ├── lib/api.dart             # typed API client + models
│   ├── lib/screens/             # connect, dashboard, detail, settings
│   ├── test/                    # 23 Dart unit/widget tests
│   ├── web/                     # boot splash, manifest, icons
│   └── android/                 # manifest, icons, launch screen
├── windows/                     # WebView2 desktop shell + build script
│   ├── Program.cs               # WinForms host, loopback server, auto-connect
│   ├── build_windows.ps1        # one-command build → app/
│   └── app.ico / app.manifest
├── app/CloudSentinel.exe        # portable Windows app (ready to run)
├── dist/CloudSentinel-1.0.0.apk # sideloadable release build
├── INSTALL.md                   # server + Windows + Android install guide
├── data/raw/                    # source-of-truth audit logs
├── reports/                     # generated exports
├── scripts/benchmark.py         # 100k-event performance harness
├── scripts/generate_sample_data.py
├── tests/                       # 156 pytest tests + real AWS fixture
├── Dockerfile
├── docker-compose.yml
├── cloudsentinel.example.toml
└── requirements.txt
```

---

## Testing

```powershell
python -m pytest
```

156 Python tests covering:

- generic JSON / JSONL / CSV, gzip, CloudTrail `Records` and CloudWatch Logs
  wrappers (including a genuine AWS subscription fixture)
- duplicate event IDs across files, corrupt records, empty/null payloads
- timestamp parsing, timezone-offset normalisation and alias mapping
- threshold boundaries, sliding windows, compromise escalation and
  cross-IP distributed bursts
- impossible-travel distances, slow-travel tolerance and geolocation shapes
- public policy/ACL severity matrix, `Principal` variants and non-storage
  false-positive guards
- wildcard permissions, admin attachments and URL-encoded policies
- SQLite insert / update / merge / suppression / filters
- CSV/JSON/HTML/PDF report shapes, HTML escaping and PDF magic bytes
- Slack/webhook SMTP delivery with mocked transports and secret redaction
- configuration loading, CLI round trips and end-to-end sample data
- REST API token auth, summary/list/detail shapes, filtering, pagination,
  invalid timestamps, scan gating and OpenAPI docs

Flutter client:

```powershell
cd mobile/cloudsentinel_mobile
flutter analyze
flutter test
```

23 tests covering URL normalisation, tolerant JSON parsing, token headers,
401/403 handling, filter query encoding, network failures, timestamp
formatting, the connect-screen boot/validation flow and the connection-recovery
screen (serve command, clipboard copy, change-server prefill).

---

## Design notes

**Why hybrid storage?** Raw logs are append-only, re-parseable and naturally
file-shaped; alert state needs queries, history and de-duplication. Keeping
events in files means a changed detector can re-scan history without a
database migration, while SQLite keeps the alert feed stable between runs.

**Why fingerprints + suppression?** Re-running a scan on the same log file must
be idempotent. Alerts are keyed by detector + entity + first-seen timestamp;
nearby findings for the same entity are merged inside the suppression window
so dashboards show one evolving incident, not hundreds of duplicates.

**Why duplicate event IDs?** CloudTrail can deliver the same record more than
once across S3 objects or CloudWatch retries. De-duplicating at ingestion keeps
counts, windows and evidence accurate.

---

## Limitations & roadmap

This is a strong portfolio/lab project, but it is **not** a finished commercial
product. The honest gap list, roughly in value order:

**Security & operations**
- The Streamlit dashboard has no login; the API uses one shared token, not
  users/roles. Add OIDC or per-user API keys before exposing either publicly.
- TLS is not terminated by CloudSentinel itself; put Caddy/nginx in front and
  drop `usesCleartextTraffic` for production builds.
- No rate limiting, audit log or key rotation on the API.

**Detection coverage**
- Four detectors only. High-value next rules: MFA disabled/deleted, root
  account use, access-key creation, security-group opened to `0.0.0.0/0`,
  CloudTrail logging stopped, KMS key deletion, guardrail/SCP changes.
- Detections are batch, not streaming. Add EventBridge/S3/SQS consumers or
  CloudTrail Lake queries for near-real-time coverage.
- No threat-intel enrichment (known-bad IPs, Tor exit nodes) and no
  entity baselining/anomaly scoring.
- No case management: alerts cannot be acknowledged, assigned, commented on or
  closed, so triage state is lost between sessions.

**Clients**
- The Android APK is debug-signed and read-only; there is no Play Store
  pipeline, push notification, offline cache or background sync.
- The Windows app wraps the Flutter web build in WebView2 rather than using
  Flutter's native Windows runner (that requires the MSVC toolchain). It works
  offline for the shell, but the UI still needs the API to show alerts.
- No iOS build (the Flutter code is portable, but it was not compiled here).
- No web frontend beyond Streamlit; the API could power one.

**Engineering**
- Docker files exist but the image was not built in this environment.
- No CI pipeline (GitHub Actions), no coverage gate, no dependency scanning.
- SQLite is single-node; multi-analyst deployments need Postgres and
  migrations.
- No infrastructure-as-code, no schema/versioning policy for stored evidence.

**Suggested next three features** (highest impact for effort):
1. **Alert triage state** — acknowledge/assign/close with notes, surfaced in
   both the dashboard and mobile app.
2. **Streaming ingestion** — S3/SQS poller or EventBridge webhook so findings
   appear without manual scans.
3. **Real auth + TLS** — OIDC for the console, per-user API keys, HTTPS
   deployment recipe; this is the gate for any shared environment.

---

## License

Educational lab project. Use responsibly on logs you are authorised to analyse.
