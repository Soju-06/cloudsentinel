<#
.SYNOPSIS
  Capture a live dashboard screenshot through the Windows app's --screenshot mode.

.DESCRIPTION
  Creates a short-lived one-off analyst token, launches app\CloudSentinel.exe
  pointed at the API, waits for it to auto-connect, save the screenshot and
  exit, then revokes the token. The plaintext token never touches a console:
  it is handed over through a temp file that is deleted immediately after.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\capture_dashboard.ps1
#>
param(
    [int]$DelayMs = 9000
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$project   = [IO.Path]::GetFullPath((Join-Path $scriptDir ".."))
$outFile   = Join-Path $project "docs\screenshots\dashboard.png"
$tokFile   = Join-Path $env:TEMP "sentinel_capture_token.txt"

# one-off label, because revoked labels cannot be reused
$label = "capture-{0}" -f (Get-Date -Format "HHmmss")

if (Test-Path $outFile) { Remove-Item $outFile -Force }

python -c "import sys; from cloudsentinel.tokens import TokenStore, DEFAULT_TOKEN_PATH; s = TokenStore(DEFAULT_TOKEN_PATH); plaintext, record = s.add(label=sys.argv[1], role='analyst'); open(sys.argv[2], 'w').write(plaintext)" $label $tokFile
if ($LASTEXITCODE -ne 0) { throw "token creation failed - is the store initialised?" }

$tok = (Get-Content $tokFile -Raw).Trim()

$appArgs = @(
    "--server", "http://127.0.0.1:8080",
    "--token", $tok,
    "--screenshot", $outFile,
    "--screenshot-delay", "$DelayMs"
)

Write-Host ("Launching app to capture {0} ({1}s delay) - a window will flash briefly." -f $outFile, $DelayMs)
$proc = Start-Process -FilePath (Join-Path $project "app\CloudSentinel.exe") -ArgumentList $appArgs -PassThru
$proc | Wait-Process -Timeout 45 -ErrorAction SilentlyContinue
if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force
    Write-Warning "app did not exit within 45s - killed it; screenshot likely missing."
}

# cleanup: revoke the capture token, delete the temp file
python -m cloudsentinel tokens revoke $label | Out-Null
Remove-Item $tokFile -Force

if (Test-Path $outFile) {
    Write-Host ("Screenshot saved: {0} ({1} bytes)" -f $outFile, (Get-Item $outFile).Length)
} else {
    throw "no screenshot was produced - check that the API is running on port 8080."
}
