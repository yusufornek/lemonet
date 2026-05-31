# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project scaffolding: module layout, license, governance, and contribution docs.
- LAN device discovery via ARP sweep, with a MAC-keyed device table.
- ARP-based man-in-the-middle engine with mandatory cache restoration on exit.
- Userspace enforcement: per-device block, bandwidth throttle, and pause/resume.
- Loopback web control panel with per-launch token auth, a first-run consent gate, live
  device updates over SSE, and English/Turkish locales.
- `lemonet` command: selects the interface, serves the panel, and opens the browser.
- Content filtering engine: domain matching with allowlist precedence, DNS query inspection
  (NXDOMAIN with Extended DNS Errors, ECH stripping), plaintext TLS SNI parsing, and
  transport-layer toggles for QUIC, encrypted DNS, and common VPN ports.
