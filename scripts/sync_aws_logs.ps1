<#
.SYNOPSIS
  Keep syncing CloudTrail logs from an S3 bucket into the local scan folder.

.DESCRIPTION
  Run this in one PowerShell window and let it loop. Every
  $IntervalSeconds it pulls newly delivered CloudTrail .json.gz
  files from the trail's S3 bucket into data\raw, where the
  `watch` command (second window) picks them up and runs detection.

  Requires: AWS CLI configured (`aws configure`) with read access
  to the bucket. Ctrl+C stops the loop.

.EXAMPLE
  .\sync_aws_logs.ps1 -Bucket sojus-cloudtrail-logs-42
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Bucket,

    # Where CloudSentinel scans: override if you moved data\raw
    [string]$LocalPath = (Join-Path $PSScriptRoot "..\data\raw"),

    [int]$IntervalSeconds = 300
)

$ErrorActionPreference = "Stop"
Write-Host ("Syncing s3://{0} -> {1} every {2}s (Ctrl+C to stop)." -f $Bucket, $LocalPath, $IntervalSeconds)

while ($true) {
    try {
        aws s3 sync "s3://$Bucket" "$LocalPath"
    } catch {
        Write-Warning "sync failed: $($_.Exception.Message) - retrying next cycle."
    }
    Start-Sleep -Seconds $IntervalSeconds
}
