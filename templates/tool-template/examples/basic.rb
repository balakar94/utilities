#!/usr/bin/env ruby
# frozen_string_literal: true

# Minimal copy-paste example. Must run in <5 min.
ENTRY = File.join(File.expand_path('..', __dir__), 'main.rb')
exit(system(RbConfig.ruby, ENTRY, '--help') ? 0 : 1)
