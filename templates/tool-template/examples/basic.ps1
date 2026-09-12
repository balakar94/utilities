#!/usr/bin/env pwsh
# Minimal copy-paste example. Must run in <5 min.
$ErrorActionPreference = 'Stop'

$Entry = Join-Path (Split-Path -Parent $PSScriptRoot) 'main.ps1'
& $Entry --help
exit $LASTEXITCODE
