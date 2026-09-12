#!/usr/bin/env pwsh
# Smoke test for a PowerShell tool: <30s, no network, no sudo.
$ErrorActionPreference = 'Stop'

$ToolRoot = Split-Path -Parent $PSScriptRoot
$Entry = Join-Path $ToolRoot 'main.ps1'

function Fail([string]$msg) { [Console]::Error.WriteLine("FAIL: $msg"); exit 1 }

if (-not (Test-Path -LiteralPath $Entry)) { Fail 'no executable entrypoint: main.ps1' }

$out = & $Entry --help 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { Fail '--help exit != 0' }
if ($out -notmatch '(?i)usage:') { Fail "--help missing 'Usage:'" }

& $Entry 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Fail 'no-arg run should fail' }

$a = & $Entry --help 2>&1 | Out-String
$b = & $Entry --help 2>&1 | Out-String
if ($a -ne $b) { Fail 'not idempotent' }

Write-Host ('OK: ' + (Split-Path -Leaf $ToolRoot))
