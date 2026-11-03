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
    [string]$LocalPath,

    [int]$IntervalSeconds = 300
)

# $PSScriptRoot is not available inside param() defaults on Windows
# PowerShell 5.1, so derive the script location ourselves.
if ([string]::IsNullOrWhiteSpace($LocalPath)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $LocalPath = [IO.Path]::GetFullPath((Join-Path $scriptDir "..\data\raw"))
}

Write-Host ("Syncing s3://{0} -> {1} every {2}s (Ctrl+C to stop)." -f $Bucket, $LocalPath, $IntervalSeconds)

while ($true) {
    aws s3 sync "s3://$Bucket" "$LocalPath"
    if ($LASTEXITCODE -ne 0) {
        $message = "aws s3 sync failed (exit {0}) - check the bucket name, " +
            "that the AWS CLI is on PATH (reopen PowerShell if 'aws' is " +
            "unknown) and 'aws configure'. Retrying in {1}s."
        Write-Warning ($message -f $LASTEXITCODE, $IntervalSeconds)
    }
    Start-Sleep -Seconds $IntervalSeconds
}
