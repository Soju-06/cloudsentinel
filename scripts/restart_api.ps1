<#
.SYNOPSIS
  Restart the CloudSentinel API in its own minimized window and verify /health.

.DESCRIPTION
  Stops any running `cloudsentinel serve` process, starts a fresh one
  (bound to all interfaces, scan enabled) and polls /health until it
  answers. Safe to run repeatedly; keeps the phone-facing server current
  after code or version changes (e.g. after a version bump).

.EXAMPLE
  .\restart_api.ps1            # default port 8080
  .\restart_api.ps1 -Port 8081
#>
param(
    [int]$Port = 8080
)

$old = Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -match 'cloudsentinel\s+serve' }
if ($old) {
    $old | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host ("Stopped running API (pid {0})" -f ($old.ProcessId -join ','))
} else {
    Write-Host "No API process was running."
}

Start-Sleep -Seconds 1

Start-Process -FilePath "python" `
    -ArgumentList "-m", "cloudsentinel", "serve", "--host", "0.0.0.0", "--port", "$Port", "--allow-scan" `
    -WindowStyle Minimized

$ok = $false
$health = $null
foreach ($i in 1..20) {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2
        $ok = $true
        break
    } catch { Start-Sleep -Milliseconds 700 }
}

if (-not $ok) {
    throw "API did not come up on port $Port within 14s - check the minimized console window for errors."
}

Write-Host ("API healthy: version {0}, alerts {1}, auth_mode {2}" -f `
    $health.version, $health.alerts, $health.auth_mode)
