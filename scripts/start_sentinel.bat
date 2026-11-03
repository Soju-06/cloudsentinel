@echo off
rem ================= CloudSentinel launcher =================
rem Starts the three services in minimized PowerShell windows:
rem   1. sentinel-sync  - pulls new CloudTrail .gz from the S3 bucket
rem   2. sentinel-watch - detects alerts on new files continuously
rem   3. sentinel-api   - the FastAPI server the phone/apps talk to
rem Double-click this after boot, or let the Startup folder do it
rem (see install_autostart step in the README).

cd /d "C:\Users\SOJUS\Desktop\CYBER"

rem --- 1. AWS log sync (every 3 minutes) ---
start "sentinel-sync"  /min powershell -NoProfile -ExecutionPolicy Bypass ^
    -File "scripts\sync_aws_logs.ps1" -Bucket sojus-cloudtrail-logs-42 -IntervalSeconds 180

rem --- 2. Continuous detection ---
start "sentinel-watch" /min cmd /c "python -m cloudsentinel watch"

rem --- 3. API server (skip if something already listens on 8080) ---
netstat -ano | findstr ":8080" | findstr "LISTENING" >nul
if %errorlevel%==0 (
    echo API already listening on 8080 - not starting a second one.
) else (
    start "sentinel-api"  /min cmd /c "python -m cloudsentinel serve --host 0.0.0.0 --port 8080 --allow-scan"
)

echo CloudSentinel started: sync + watch + API in minimized windows.
echo Open the phone app / http://127.0.0.1:8080/health to verify.
pause
