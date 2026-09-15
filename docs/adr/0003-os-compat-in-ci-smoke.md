# ADR 0003: Respect OS compatibility in CI smoke tests

- Status: accepted
- Date: 2026-09-16

## Context

`metadata.yaml` requires an OS claim `compat` (`all`, `Linux`, `Windows`, etc.), defined in
`docs/conventions.md` as "an OS claim, not a formality: use `all` when the tool has no OS-specific
code; list only real targets otherwise".

However, the initial CI implementation in ADR 0002 executed smoke tests for every Python and Ruby
tool on both Linux and Windows runners regardless of their declared OS target. For an OS-specific
tool (such as a Linux WireGuard and systemd-networkd manager declaring `compat: Linux`), running
smoke tests on Windows causes false-positive failures on an OS the tool was never designed to
support.

## Decision

Both CI smoke test workflows (`Smoke: Linux` and `Smoke: Windows`) inspect `metadata.yaml`'s `compat`
claim before executing tests:

- Only tools declaring `compat: all` are required and expected to pass smoke tests across all platforms
  (Linux, Windows, macOS).
- `Smoke: Linux` executes tests only if `compat` matches `all` or `linux` (case-insensitive); otherwise skips.
- `Smoke: Windows` executes tests only if `compat` matches `all` or `windows` (case-insensitive); otherwise skips.
- Any future runner (e.g. macOS) follows the same rule: only `all` or its specific OS.

## Consequences

- Platform-specific tools are only exercised on their declared OS targets.
- Universal tools (`compat: all`) continue to be tested across both Linux and Windows runners.
- Eliminates false-positive CI failures for platform-specific utilities.
