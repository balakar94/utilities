#!/usr/bin/env ruby
# frozen_string_literal: true

# __TOOL_NAME__ — one-line purpose.
# Usage: main.rb [--help] [--version]
VERSION = "0.1.0"

def usage
  "Usage: __TOOL_NAME__ [--help] [--version]\n\nSmall description of what it does.\n"
end

case ARGV[0]
when "-h", "--help"
  print usage
when "--version"
  puts "__TOOL_NAME__ #{VERSION}"
when nil
  warn usage
  exit 2
else
  warn "ERROR: unknown arg: #{ARGV[0]}"
  warn usage
  exit 2
end
