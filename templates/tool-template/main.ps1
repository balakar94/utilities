#!/usr/bin/env pwsh
# __TOOL_NAME__ — one-line purpose.
# Usage: main.ps1 [--help] [--version]
$VERSION = "0.1.0"

function Show-Usage {
  "Usage: __TOOL_NAME__ [--help] [--version]",
  "",
  "Small description of what it does."
}

$arg = if ($args.Count -gt 0) { $args[0] } else { "" }
switch ($arg) {
  { $_ -eq "-h" -or $_ -eq "--help" } { Show-Usage; exit 0 }
  "--version" { "__TOOL_NAME__ $VERSION"; exit 0 }
  "" {
    Show-Usage | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 2
  }
  default {
    [Console]::Error.WriteLine("ERROR: unknown arg: $arg")
    Show-Usage | ForEach-Object { [Console]::Error.WriteLine($_) }
    exit 2
  }
}
