#!/usr/bin/env ruby
# frozen_string_literal: true

# Smoke test for a Ruby tool: <30s, no network, no sudo, stdlib only.
require 'open3'

TOOL_ROOT = File.expand_path('..', __dir__)
ENTRY = File.join(TOOL_ROOT, 'main.rb')

def run(*args)
  out, _err, status = Open3.capture3(RbConfig.ruby, ENTRY, *args)
  [out, status.exitstatus]
end

def fail!(msg)
  warn "FAIL: #{msg}"
  exit 1
end

out, code = run('--help')
fail!('--help exit != 0') unless code.zero?
fail!("--help missing 'Usage:'") unless out.downcase.include?('usage:')

_, code = run
fail!('no-arg run should fail') if code.zero?

first, = run('--help')
second, = run('--help')
fail!('not idempotent') unless first == second

puts "OK: #{File.basename(TOOL_ROOT)}"
