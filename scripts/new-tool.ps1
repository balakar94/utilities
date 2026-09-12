#!/usr/bin/env pwsh
# scripts/new-tool.ps1 — scaffold a new tool from template (Windows-native twin of new-tool.sh).
# Usage: pwsh scripts/new-tool.ps1 [-Lang bash|python|powershell|ruby] [-Force] <kebab-name>
[CmdletBinding()]
param(
  [string]$Lang = 'bash',
  [switch]$NoExamples,
  [switch]$Force,
  [switch]$Help,
  [Parameter(Position = 0)][string]$Name
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$usage = @'
Usage: pwsh scripts/new-tool.ps1 [-Lang bash|python|powershell|ruby] [-NoExamples] [-Force] <kebab-name>
  <kebab-name>   e.g. net-scan. Regex: ^[a-z0-9]+(-[a-z0-9]+)*$ (2-48 chars)
  -NoExamples    skip the optional examples/ folder
'@
if ($Help) { [Console]::Error.WriteLine($usage); exit 2 }
if (-not $Name) { [Console]::Error.WriteLine($usage); exit 2 }

if ($Lang -eq 'ps1') { $Lang = 'powershell' }
if ($Lang -notin @('bash', 'python', 'powershell', 'ruby')) {
  Die '-Lang must be bash|python|powershell|ruby'
}
if (-not (Test-KebabName -Name $Name)) { Die "invalid tool name '$Name'" }
if ($Name -in @('common', 'template', 'test', 'scripts', 'tools', 'templates')) {
  Die "reserved name: $Name"
}

$root = Get-RepoRoot
$tpl = Join-Path $root 'templates/tool-template'
$dest = Join-Path $root "tools/$Name"
if (-not (Test-Path -LiteralPath $tpl)) { Die "template missing: $tpl" }
if (Test-Path -LiteralPath $dest) {
  if ($Force) { Remove-Item -Recurse -Force -LiteralPath $dest }
  else { Die "exists: tools/$Name (use -Force)" }
}

New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item -Path (Join-Path $tpl '*') -Destination $dest -Recurse -Force
# Never scaffold junk left in the template dir.
foreach ($junk in @('__pycache__', '.pytest_cache', '.ruff_cache')) {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $dest $junk)
}
Get-ChildItem -LiteralPath $dest -Recurse -Force -Filter '.DS_Store' -ErrorAction SilentlyContinue |
  Remove-Item -Force -ErrorAction SilentlyContinue

$utf8 = New-Object System.Text.UTF8Encoding($false)
Get-ChildItem -LiteralPath $dest -Recurse -File | ForEach-Object {
  $text = Get-Content -LiteralPath $_.FullName -Raw
  if ($text -match '__TOOL_NAME__') {
    [System.IO.File]::WriteAllText($_.FullName, ($text -replace '__TOOL_NAME__', $Name), $utf8)
  }
}

# One language only: keep the chosen entrypoint, its native test and (optional) example.
$keep = @{ bash = 'main.sh'; python = 'main.py'; powershell = 'main.ps1'; ruby = 'main.rb' }[$Lang]
$ext = @{ bash = 'sh'; python = 'py'; powershell = 'ps1'; ruby = 'rb' }[$Lang]
foreach ($m in @('main.sh', 'main.py', 'main.ps1', 'main.rb')) {
  if ($m -ne $keep) { Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $dest $m) }
}
foreach ($t in @('test_basic.sh', 'test_basic.py', 'test_basic.ps1', 'test_basic.rb')) {
  if ($t -ne "test_basic.$ext") { Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $dest "tests/$t") }
}
foreach ($e in @('basic.sh', 'basic.py', 'basic.ps1', 'basic.rb')) {
  if ($e -ne "basic.$ext") { Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $dest "examples/$e") }
}
if ($NoExamples) {
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $dest 'examples')
}
if ($keep -ne 'main.sh') {
  $readme = Join-Path $dest 'README.md'
  $text = Get-Content -LiteralPath $readme -Raw
  [System.IO.File]::WriteAllText($readme, ($text -replace 'main\.sh', $keep), $utf8)
}

$execFiles = @(
  (Join-Path $dest $keep),
  (Join-Path $dest "tests/test_basic.$ext"),
  (Join-Path $dest "examples/basic.$ext")
) | Where-Object { Test-Path -LiteralPath $_ }

if (Get-Command chmod -ErrorAction SilentlyContinue) {
  & chmod +x @execFiles 2> $null
}
# Windows has no exec bit; stage the fresh files with +x so Linux CI sees executable entrypoints.
if ($IsWindows -and (Get-Command git -ErrorAction SilentlyContinue)) {
  & git add --chmod=+x -- @execFiles 2> $null
}

$testCmd = @{
  bash       = "bash tools/$Name/tests/test_basic.sh"
  python     = "python3 tools/$Name/tests/test_basic.py"
  powershell = "pwsh tools/$Name/tests/test_basic.ps1"
  ruby       = "ruby tools/$Name/tests/test_basic.rb"
}[$Lang]

Write-Info "created tools/$Name (lang=$Lang)"
$next = @"
Next:
  1. Edit tools/$Name/metadata.yaml (description, category, owner)
  2. Edit tools/$Name/README.md
  3. $testCmd
  4. pwsh scripts/list-tools.ps1 -Check
"@
[Console]::Error.WriteLine($next)
