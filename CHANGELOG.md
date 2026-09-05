# Changelog

All notable changes to IPMIDeck are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

At release time the release workflow slices the `## [<version>]` section out of this file and uses
it as the GitHub Release body. Before tagging a version, promote the relevant `[Unreleased]` items
into a new dated `## [<version>] - YYYY-MM-DD` section.

## [Unreleased]

> **Upgrading:** this release invalidates every existing session. You will be asked to log in
> again once after updating — that is intentional (see "sessions are now bound to your
> credentials" below).

### Security

This release closes the CRITICAL and HIGH findings from an adversarial security audit of the
authentication and static-file surfaces.

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
- **Sessions are now bound to your credentials.** Changing your password (or username) invalidates
  every session issued before the change — previously only a username change did, so "reset my
  password" did not actually lock anyone out. Tokens issued by earlier versions do not carry this
  binding and are rejected, which is why everyone is signed out once on upgrade.
- **An anonymous caller can no longer disable authentication on a fresh instance.** Before an
  account existed, `POST /api/auth/toggle {"enabled": false}` was accepted with no cookie and no
  password; completing first-run setup then created the user *without* turning authentication back
  on, leaving the whole API open on the LAN with no visible symptom. The pre-setup disable is now
  refused, and completing setup always leaves authentication enabled.
- **Changing credentials now requires the current password.** A valid session cookie alone was
  enough to rewrite the sole account through `/api/auth/configure` — including a cookie the
  operator had just tried to evict — and on an auth-disabled instance no cookie was needed at all.
- **`GET /api/system/app-config/{key}` now honours an allow-list.** It previously returned any
  `app_config` row to any authenticated caller, including `session_secret`. The read surface is now
  exactly the write surface.

If your database may have been exposed, updating is not enough on its own: also rotate the session
secret **and** the credential key, then re-enter your BMC credentials.

### Fixed

- `ipmideck reset-password` no longer reports success when the username does not exist. The
  underlying update matched zero rows and the command still printed "Password updated", leaving
  the operator locked out believing the password had been changed. It now names the configured
  username and exits non-zero.

### Security notes

- **Backup archives contain secrets.** `POST /api/system/backup` bundles `ipmideck.db`,
  `config.yaml` and `encryption.key` — together enough to decrypt every stored BMC credential and
  to forge session cookies. Treat a backup archive exactly like the credentials themselves: store
  it encrypted, do not attach it to issues or support threads, and delete copies you no longer
  need. This is documented in the README's Backups section.

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
