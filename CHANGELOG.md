# Changelog

All notable changes to IPMIDeck are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

At release time the release workflow slices the `## [<version>]` section out of this file and uses
it as the GitHub Release body. Before tagging a version, promote the relevant `[Unreleased]` items
into a new dated `## [<version>] - YYYY-MM-DD` section.

## [Unreleased]

### Security

- **Fixed a pre-authentication path traversal in the SPA fallback handler.** An unauthenticated
  request could read files outside the web root — including `data/encryption.key` and
  `data/ipmideck.db`, which together yield plaintext BMC credentials for every managed server.
  The handler now decides containment on the canonical path, so every escape spelling
  (`../`, `%2e%2e%2f`, `..%2f`, `..%5c`, absolute and Windows-style paths, symlinks) falls back to
  the SPA shell. NUL bytes and oversized paths are rejected instead of raising a 500, and the
  `/api/*` 404 guard for disabled modules is unchanged.
- **Added `ipmideck rotate-session-secret`.** Session tokens are stateless HMACs signed with a
  secret stored in the database, so anyone who obtained a copy of the database via the traversal
  above can keep minting valid sessions *after* updating. This command rotates that secret and
  invalidates every issued token. It asks for confirmation (`--yes` skips it for scripts) and
  prints a prominent restart warning: **the rotation only takes effect once IPMIDeck is restarted**,
  because the running process keeps the previous secret in memory.

  If your database may have been exposed, rotating the session secret is only one of three steps —
  also rotate the credential key and re-enter your BMC credentials.

### Fixed

- `ipmideck reset-password` no longer reports success when the username does not exist. The
  underlying update matched zero rows and the command still printed "Password updated", leaving
  the operator locked out believing the password had been changed. It now names the configured
  username and exits non-zero.

## [2.0.1] - 2026-07-25

### Fixed

- Session expiry is now honored. `IPMIDECK_AUTH_SESSION_EXPIRY` (and the `auth.session_expiry`
  config key) now set the session token and cookie lifetime; previously the setting had no effect
  and the lifetime was always 24 hours.
- FanPilot status no longer reports "active" for monitoring-only vendors (HPE, Lenovo, and unknown
  BMCs). Their fans stay under the BMC's own control, and the dashboard now shows that instead of a
  false "FanPilot active" state.

## [2.0.0] - 2026-07-13

Complete rewrite. v1 was a single-page app that pushed fan commands at one Dell PowerEdge; v2 is a
self-hosted IPMI platform — a Python/FastAPI backend serving a React dashboard, talking to any
number of BMCs over ipmitool. Everything runs locally: SQLite on disk, no cloud, no telemetry.

### Added

- Multi-server dashboard with live sensors (temperature, fan RPM, voltage, power) over a WebSocket,
  history charts, and a drag-and-drop widget grid.
- FanPilot: a backend fan-curve engine with hysteresis, a non-negotiable safety override at the
  critical threshold, and fail-safe handling when a BMC becomes unreachable.
- Power control (on, soft off, hard off, reset, cycle) with an audit log and per-server energy-cost
  tracking.
- Hardware event log (SEL) and FRU inventory, both browsable, searchable, and exportable to CSV/JSON.
- 12 languages, dark and light themes, optional local authentication, HTTPS with self-signed
  certificates, and one-click backup/restore.
- Ships as a multi-arch Docker image (`devluigi06/ipmideck`) and the `ipmideck` package on PyPI.

### Notes

- Fan control is vendor-specific: Dell is tested on real hardware; Supermicro and IBM are
  experimental; HPE, Lenovo, and unknown BMCs are monitoring-only (full sensors, power, SEL, and
  FRU, but no fan writes).

[Unreleased]: https://github.com/ipmideck/IPMIDeck/compare/v2.0.1...HEAD
[2.0.1]: https://github.com/ipmideck/IPMIDeck/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/ipmideck/IPMIDeck/compare/84df472...v2.0.0
