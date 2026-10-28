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
```

> **Firewall:** the first time you bind `0.0.0.0`, Windows asks whether to allow
> Python on the network. Allow it for **Private** networks, otherwise phones
> cannot connect.

Environment variables work too: `CLOUDSENTINEL_API_TOKEN`,
`CLOUDSENTINEL_API_ALLOW_SCAN=true`.

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
storage. Use **Settings → Disconnect** inside the app to forget it.

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

Diagnostics:

```powershell
# is the API up and what does it see?
curl.exe http://127.0.0.1:8080/health
curl.exe -H "X-API-Token: CHANGE_ME" http://127.0.0.1:8080/api/summary

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
flutter test                 # 15 tests
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

- The token is a **shared secret**, not a user account system. Anyone with it
  has full read access to alerts and evidence.
- Traffic is plain HTTP. That is fine on a trusted lab LAN; for anything else,
  put Caddy/nginx with TLS in front of the API and use an `https://` URL.
- `POST /api/scan` is disabled unless you pass `--allow-scan`. Keep it off on
  untrusted networks.
- Never port-forward 8080 from the internet. Use a VPN or an authenticated
  reverse proxy.
- Rotate the token by restarting the server with a new `--token` and re-entering
  it in each app.
