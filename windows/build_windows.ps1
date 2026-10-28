# CloudSentinel Windows build
#
# Builds the Flutter web UI and compiles the native WebView2 shell into the
# repository's `app` folder. No Visual Studio, Windows SDK, or administrator
# rights are required: it uses the .NET Framework compiler that ships with
# Windows plus the WebView2 runtime that ships with Microsoft Edge.
#
# Usage (from the repository root):
#   powershell -ExecutionPolicy Bypass -File windows\build_windows.ps1
#
# Options:
#   -SkipWeb        reuse the existing Flutter web build
#   -OutputDir DIR  write the app somewhere other than <repo>\app

[CmdletBinding()]
param(
    [string]$OutputDir = '',
    [switch]$SkipWeb
)

$ErrorActionPreference = 'Stop'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if (-not [System.IO.Path]::IsPathRooted($scriptDir)) { $scriptDir = Join-Path (Get-Location).Path $scriptDir }
$scriptDir = [System.IO.Path]::GetFullPath($scriptDir)

$repoRoot = Split-Path -Parent $scriptDir
if (-not $OutputDir) { $OutputDir = Join-Path $repoRoot 'app' }
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)

$flutterProject = Join-Path $repoRoot 'mobile\cloudsentinel_mobile'
$webBuild       = Join-Path $flutterProject 'build\web'
$cacheDir       = Join-Path $repoRoot '.build-cache'
$webViewVersion = '1.0.2903.40'
$webViewZip     = Join-Path $cacheDir "webview2-$webViewVersion.zip"
$webViewPkg     = Join-Path $cacheDir "webview2-$webViewVersion"
$csc            = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'

if (-not (Test-Path $csc)) {
    throw "The .NET Framework compiler was not found at $csc"
}

if (-not $SkipWeb) {
    if (-not (Get-Command flutter -ErrorAction SilentlyContinue)) {
        throw 'flutter was not found on PATH. Install Flutter and reopen the terminal.'
    }

    Write-Host '==> Building Flutter web bundle' -ForegroundColor Cyan
    Push-Location $flutterProject
    try {
        & flutter pub get
        if ($LASTEXITCODE -ne 0) { throw 'flutter pub get failed' }
        & flutter build web --release --no-wasm-dry-run
        if ($LASTEXITCODE -ne 0) { throw 'flutter build web failed' }
    }
    finally {
        Pop-Location
    }
}
else {
    if (-not (Test-Path (Join-Path $webBuild 'index.html'))) {
        throw "No existing web build at $webBuild; run without -SkipWeb"
    }
    Write-Host '==> Building Flutter web bundle (skipped)' -ForegroundColor Cyan
}

Write-Host '==> Preparing WebView2 SDK' -ForegroundColor Cyan
if (-not (Test-Path (Join-Path $webViewPkg 'lib\net462\Microsoft.Web.WebView2.WinForms.dll'))) {
    New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null
    if (-not (Test-Path $webViewZip)) {
        Invoke-WebRequest -UseBasicParsing `
            -Uri "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/$webViewVersion" `
            -OutFile $webViewZip
    }
    Expand-Archive -Path $webViewZip -DestinationPath $webViewPkg -Force
}

Write-Host '==> Assembling application folder' -ForegroundColor Cyan
if (Test-Path $OutputDir) { Remove-Item $OutputDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$webTarget = Join-Path $OutputDir 'web'
New-Item -ItemType Directory -Force -Path $webTarget | Out-Null
Copy-Item (Join-Path $webBuild '*') $webTarget -Recurse -Force

# The shell always runs the JavaScript/CanvasKit build, so the WebAssembly
# renderer payloads and the debug symbol maps are unreachable. Dropping them
# keeps the shipped folder (and the repository) a fraction of the size.
Get-ChildItem $webTarget -Recurse -File |
    Where-Object { $_.Name -like '*.symbols' } |
    Remove-Item -Force
foreach ($unused in @(
    'skwasm.js', 'skwasm.wasm',
    'skwasm_heavy.js', 'skwasm_heavy.wasm',
    'wimp.js', 'wimp.wasm'
)) {
    Remove-Item (Join-Path $webTarget "canvaskit\$unused") -Force -ErrorAction SilentlyContinue
}

$net462 = Join-Path $webViewPkg 'lib\net462'
$native = Join-Path $webViewPkg 'runtimes\win-x64\native'
Copy-Item (Join-Path $net462 'Microsoft.Web.WebView2.Core.dll') $OutputDir -Force
Copy-Item (Join-Path $net462 'Microsoft.Web.WebView2.WinForms.dll') $OutputDir -Force
Copy-Item (Join-Path $native 'WebView2Loader.dll') $OutputDir -Force

Write-Host '==> Compiling CloudSentinel.exe' -ForegroundColor Cyan
$arguments = @(
    '/nologo',
    '/target:winexe',
    '/platform:x64',
    '/optimize+',
    "/out:$(Join-Path $OutputDir 'CloudSentinel.exe')",
    "/win32icon:$(Join-Path $scriptDir 'app.ico')",
    "/win32manifest:$(Join-Path $scriptDir 'app.manifest')",
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Windows.Forms.dll',
    "/reference:$(Join-Path $net462 'Microsoft.Web.WebView2.Core.dll')",
    "/reference:$(Join-Path $net462 'Microsoft.Web.WebView2.WinForms.dll')",
    (Join-Path $scriptDir 'Program.cs')
)

& $csc $arguments
if ($LASTEXITCODE -ne 0) { throw 'C# compilation failed' }

$sizeMb = [math]::Round(((Get-ChildItem $OutputDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Host ''
Write-Host "Windows app ready: $(Join-Path $OutputDir 'CloudSentinel.exe') ($sizeMb MB)" -ForegroundColor Green
