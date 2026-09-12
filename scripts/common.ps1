#!/usr/bin/env pwsh
# scripts/common.ps1 — shared helpers for the PowerShell twins. Dot-source only, do not run.
$ErrorActionPreference = 'Stop'

function Write-Log {
  param(
    [Parameter(Mandatory)][string]$Level,
    [Parameter(Mandatory)][string]$Message
  )
  $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  [Console]::Error.WriteLine(('[{0}] {1,-5} {2}' -f $ts, $Level, $Message))
}
function Write-Info { param([string]$Message) Write-Log -Level 'INFO' -Message $Message }
function Write-Warn { param([string]$Message) Write-Log -Level 'WARN' -Message $Message }
function Write-Err { param([string]$Message) Write-Log -Level 'ERROR' -Message $Message }
function Die {
  param([string]$Message)
  Write-Err -Message $Message
  exit 1
}

function Get-RepoRoot {
  if (Get-Command git -ErrorAction SilentlyContinue) {
    $top = & git rev-parse --show-toplevel 2> $null
    if ($LASTEXITCODE -eq 0 -and $top) { return ([string]$top).Trim() }
  }
  return (Split-Path -Parent $PSScriptRoot)
}

function Test-KebabName {
  param([string]$Name)
  if ([string]::IsNullOrEmpty($Name)) { return $false }
  if ($Name -notmatch '^[a-z0-9]+(-[a-z0-9]+)*$') { return $false }
  return ($Name.Length -ge 2 -and $Name.Length -le 48)
}

function Get-MetaValue {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Key
  )
  if (-not (Test-Path -LiteralPath $Path)) { return '' }
  $pattern = '^' + [regex]::Escape($Key) + ':\s?(.*)$'
  foreach ($line in Get-Content -LiteralPath $Path) {
    if ($line -match $pattern) { return ($matches[1] -replace '["'']', '').Trim() }
  }
  return ''
}
