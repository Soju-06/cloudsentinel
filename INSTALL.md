# CloudSentinel — Installation & Run Guide

CloudSentinel ships as three pieces that all read the same alert database:

| Piece | What it is | Where |
|---|---|---|
| **API server** | FastAPI service the apps talk to | `python -m cloudsentinel serve` |
| **Windows app** | Flutter UI in a native WebView2 shell | `app\CloudSentinel.exe` |
| **Android app** | Native Flutter APK | `dist\CloudSentinel-1.0.0.apk` |
| **Web dashboard** | Streamlit analyst console (optional) | `streamlit run cloudsentinel/dashboard.py` |

The apps are clients. **Start the server first**, then open either app.

---

## 1. Start the server (required for both apps)

Requirements: **Python 3.11+** on the machine that will hold the data.

```powershell
cd C:\Users\SOJUS\Desktop\CYBER

# one-time: install dependencies
python -m pip install -r requirements.txt

# one-time: create the database and a realistic demo dataset
python -m cloudsentinel demo

# start the API (LAN-visible, token protected)
python -m cloudsentinel serve --host 0.0.0.0 --port 8080 --token CHANGE_ME
```

At startup the server prints the URLs you can use, including the LAN address
phones should connect to. Leave this window running.

Useful variants:

```powershell
# localhost only, no token (development)
python -m cloudsentinel serve

# custom port + remote scan button in the apps
python -m cloudsentinel serve --port 8081 --token CHANGE_ME --allow-scan

# HTTPS for the LAN (see section 6)
python scripts/make_dev_cert.py --out certs
python -m cloudsentinel serve --host 0.0.0.0 --port 8443 --token CHANGE_ME `
  --tls-cert certs\cloudsentinel-dev.pem --tls-key certs\cloudsentinel-dev-key.pem
```

Rotating tokens (add a new one, switch clients, then revoke the old one — no
restart needed):

```powershell
python -m cloudsentinel tokens add --label phone
python -m cloudsentinel tokens list
python -m cloudsentinel tokens revoke phone
```

> **Firewall:** the first time you bind `0.0.0.0`, Windows asks whether to allow
> Python on the network. Allow it for **Private** networks, otherwise phones
> cannot connect.

Environment variables work too: `CLOUDSENTINEL_API_TOKEN`,
`CLOUDSENTINEL_API_ALLOW_SCAN=true`, `CLOUDSENTINEL_RATE_LIMIT`, and
`CLOUDSENTINEL_TOKEN_FILE`.

---

## 2. Windows desktop app

**File:** `app\CloudSentinel.exe`

### Run it

1. Keep the whole `app` folder together — the `.exe` needs `web\`, the two
   `Microsoft.Web.WebView2.*.dll` files, and `WebView2Loader.dll` next to it.
2. Double-click `CloudSentinel.exe`.
3. On first launch you get the connect screen:
   - **Server URL:** `http://127.0.0.1:8080`
   - **API token:** the token you passed to `serve`
4. The connection is saved, so later launches go straight to the dashboard.
5. If the saved server is not running, the app shows **CONNECTION LOST** with
   the address it tried, the exact `serve` command, and two buttons:
   **RETRY** and **CHANGE SERVER**. *Change server* forgets the saved address
   but pre-fills the form with it, so you only edit the port or token.
   A one-shot golf animation (ball lands just short of the hole) plays on that
   screen and swings again each time you press RETRY.

No installer and **no administrator rights** are needed. The folder is portable
— copy it anywhere, including a USB stick.

### Requirements

- Windows 10 or 11, 64-bit.
- **WebView2 Runtime.** It ships with Microsoft Edge on current Windows. If the
  app says the runtime is missing, install the free Evergreen runtime:
  https://developer.microsoft.com/microsoft-edge/webview2/

### First-run warnings

Windows SmartScreen may show *"Windows protected your PC"* because the binary is
not code-signed. Click **More info → Run anyway**. Some antivirus products also
flag unsigned, self-built executables; the source is in `windows\Program.cs` if
you want to review or rebuild it.

### Auto-connect shortcut (optional)

The app accepts the server and token on the command line, so a desktop shortcut
can skip the connect screen entirely:

```
"C:\Users\SOJUS\Desktop\CYBER\app\CloudSentinel.exe" --server http://127.0.0.1:8080 --token CHANGE_ME
```

Create it with: right-click desktop → **New → Shortcut** → paste the line above.

Other flags:

| Flag | Effect |
|---|---|
| `--server URL` | pre-fill / auto-connect to this API |
| `--token TOKEN` | token used with `--server` |
| `--devtools` | enables F12 DevTools and the right-click menu |
| `--probe` | writes viewport/DPI diagnostics to `%TEMP%\cloudsentinel-probe.txt` and exits |
| `--screenshot FILE` | renders the page to a PNG off-screen, then exits (build QA) |
| `--screenshot-delay MS` | wait before the capture, e.g. `4000` to catch an animation mid-flight |
| `F5` | reload the UI |

### Keyboard & window behaviour

- Resizable from 880×600 up; the layout adapts down to phone width.
- The window opens at 92 % of the monitor work area and is DPI-correct at
  100 %, 125 %, 150 % and per-monitor mixed scaling.

---

## 3. Android app

**File:** `dist\CloudSentinel-1.0.0.apk` (~50 MB)

- Package: `com.cloudsentinel.cloudsentinel_mobile`
- Version: 1.0.0 (versionCode 1)
- Minimum: Android 7.0 (API 24); targets Android 16 (API 36)
- Signed with Flutter's debug key — **sideload only, not for Google Play**

### Install

**Option A — copy the file (no tools needed)**

1. Connect the phone by USB (or upload the APK to Google Drive / send it to
   yourself).
2. Copy `CloudSentinel-1.0.0.apk` to the phone's Downloads folder.
3. Open it with the phone's file manager.
4. Android asks to allow installs from that app — tap **Settings → Allow from
   this source**, go back, tap **Install**.
5. Play Protect may warn that the app is unknown. Choose **Install anyway** —
   the APK is self-built and not distributed through Play.

**Option B — ADB (USB debugging enabled)**

```powershell
adb install -r "C:\Users\SOJUS\Desktop\CYBER\dist\CloudSentinel-1.0.0.apk"
```

### Connect

1. Phone and computer on the **same Wi-Fi** (guest networks often block
   device-to-device traffic).
2. Start the server with `--host 0.0.0.0 --token CHANGE_ME`.
3. Find the computer's LAN IPv4 address:

   ```powershell
   ipconfig | Select-String "IPv4"
   ```

   e.g. `192.168.1.42`.
4. In the app enter:
   - **Server URL:** `http://192.168.1.42:8080` (not `127.0.0.1` — that is the
     phone itself)
   - **API token:** `CHANGE_ME`
5. Tap **Connect**. The app checks `/health` and `/api/summary` before saving.

The connection is remembered, including the token, in Android's private app
storage. Use **Settings → Disconnect** inside the app to forget it, or tap
**CHANGE SERVER** on the error screen when the saved server is unreachable.
That screen also shows the `serve` command with `--host 0.0.0.0` already in it,
which is what a phone needs.

Android 9+ blocks plain HTTP by default; the manifest enables cleartext traffic
so LAN testing works. See the security notes below before exposing the API
beyond a trusted network.

---

## 4. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `401 invalid or missing API token` | Token in the app does not match `--token`. Re-enter it (Settings → Disconnect). |
| `Cannot reach http://…` | Server not running, wrong IP/port, firewall blocking Python, or phone on another network. Test `http://<ip>:8080/health` in the phone browser. |
| Dashboard shows 0 alerts | Database is empty. Run `python -m cloudsentinel demo` or `python -m cloudsentinel scan -i data/raw`. |
| `The web assets are missing` (Windows) | The `app` folder was partially copied. Keep `CloudSentinel.exe`, the two WebView2 DLLs, `WebView2Loader.dll`, and the `web` folder together. |
| Windows app shows a runtime error at start | Install the WebView2 Evergreen Runtime (link above). |
| `[Errno 10048] address already in use` | Port 8080 is taken. Use `--port 8081`, then update the URL in the app. |
| Phone cannot connect but browser can | Some routers isolate wireless clients (AP isolation). Use a hotspot or disable isolation. |
| App stuck on the boot screen | Start the server first, then press F5 (Windows) or reopen the app. |
| `CONNECTION LOST` on every launch | The app remembered a server that is no longer running. Start the server (the exact command is shown on that screen — use the copy button), or press **CHANGE SERVER** to point the app somewhere else. The address is pre-filled, so you only edit what changed. |

Diagnostics:

```powershell
# is the API up and what does it see?
curl.exe http://127.0.0.1:8080/health
curl.exe -H "X-API-Token: CHANGE_ME" http://127.0.0.1:8080/api/summary

# triage alert 1 (status: open | acknowledged | closed; assignee null clears)
curl.exe -X PATCH -H "X-API-Token: CHANGE_ME" -H "Content-Type: application/json" `
  -d '{"status":"acknowledged","assignee":"me"}' http://127.0.0.1:8080/api/alerts/1

# Windows shell viewport/DPI report
.\app\CloudSentinel.exe --probe
Get-Content "$env:TEMP\cloudsentinel-probe.txt"
```

---

## 5. Rebuilding from source

### Android APK

```powershell
cd mobile\cloudsentinel_mobile
flutter pub get
flutter test                 # 25 tests
flutter build apk --release
# output: build\app\outputs\flutter-apk\app-release.apk
```

### Windows app

```powershell
# from the repository root
powershell -ExecutionPolicy Bypass -File windows\build_windows.ps1
```

The script builds the Flutter web bundle, downloads the WebView2 SDK into
`.build-cache` (once), prunes unused WebAssembly payloads, and compiles
`app\CloudSentinel.exe` with the .NET Framework compiler that ships with
Windows. No Visual Studio or administrator rights required.

### Streamlit analyst console

```powershell
streamlit run cloudsentinel\dashboard.py
# http://localhost:8501
```

---

## 6. Security notes (read before exposing anything)

The short version: **localhost by default, tokens always, TLS before the LAN,
never the public internet.** Full threat model and rationale: `SECURITY.md`.

### What the server does by default

| Control | Default |
|---|---|
| Bind address | `127.0.0.1` — loops back to this machine only |
| Authentication | required as soon as a token exists; open only when none is configured |
| Rate limit | 120 requests/minute per client+token (scans: 1/10th of that) |
| Browser origins | loopback only (`http://127.0.0.1:…`, `http://localhost:…`) |
| Scan endpoint | disabled (`403`) unless `--allow-scan` |
| Error responses | uniform JSON, no tokens, paths or stack traces |

### HTTPS on your network (recommended for `--host 0.0.0.0`)

```powershell
# 1. Create a development certificate (localhost, 127.0.0.1 and your LAN IP)
python scripts\make_dev_cert.py --out certs

# 2. Trust it on this PC (current user store, no admin rights)
certutil -user -addstore Root certs\cloudsentinel-dev.pem

# 3. Serve HTTPS
python -m cloudsentinel serve --host 0.0.0.0 --port 8443 --token CHANGE_ME `
  --tls-cert certs\cloudsentinel-dev.pem --tls-key certs\cloudsentinel-dev-key.pem
```

- The Windows app and browsers use the Windows certificate store, so step 2 is
  enough for them.
- **Android:** because the certificate is self-signed you can install it under
  *Settings → Security → Encryption & credentials → Install a certificate → CA
  certificate*, which makes browsers trust it. Flutter's HTTP stack does **not**
  read the Android user CA store, so for the phone app over HTTPS use a
  publicly trusted certificate (e.g. Caddy/nginx with Let's Encrypt) — or keep
  HTTP on a trusted home Wi-Fi, which is what the LAN default assumes.
- Never commit `certs/` or the private key; both are gitignored.

### Tokens and rotation

- `--token` is the bootstrap token: fine for a quick start, but one value for
  every client.
- `python -m cloudsentinel tokens add --label phone` creates a 256-bit token,
  shown **once** and stored only as a salted SHA-256 fingerprint in
  `data/api_tokens.json` (gitignored, owner-only permissions on POSIX).
- `tokens list` shows labels and 8-character fingerprints — never the secret.
- `tokens revoke <label>` takes effect on the next request, with no restart:
  add the replacement, update the client, revoke the old one.
- Revoking the last token **locks** the API (it does not silently open it).
- The stack is a shared secret, not a user account system: anyone holding a
  valid token has full read access to alerts and evidence.

### Rate limiting

The API returns `429` with a `Retry-After` header when a client exceeds its
budget. Tune it with `--rate-limit N` (requests per minute, `0` disables) or
`CLOUDSENTINEL_RATE_LIMIT`. `/health` is always exempt so monitoring stays up.
The limiter is per process — correct for this single-process deployment.

### What not to do

- Never port-forward the API from the internet. Use a VPN or an authenticated
  reverse proxy with TLS.
- Keep `--allow-scan` off on untrusted networks; it runs a scan on request.
- Don't put the bootstrap token in a shortcut on a shared computer — use
  `tokens add` and a client that stores it privately.

