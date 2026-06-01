# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-01

First public release.

### Added
- LAN device discovery via active ARP sweep plus passive ARP, mDNS, reverse DNS, and MAC OUI,
  with a best-effort device type and a MAC-keyed device table.
- Man-in-the-middle engine over IPv4 (ARP) and IPv6 (NDP), with a userspace forwarding relay and
  mandatory restoration of ARP/NDP and host state on stop, signal, or panic.
- Userspace enforcement: per-device block, bandwidth throttle (upload and download), and
  pause/resume, applied uniformly to IPv4 and IPv6.
- Content filtering: domain matching with allow-over-block precedence, DNS query inspection
  (NXDOMAIN with Extended DNS Errors, ECH stripping), plaintext TLS-SNI parsing, custom
  per-device allow/block domain rules, and transport toggles for QUIC, encrypted DNS, and common
  VPN ports.
- Loopback web panel with per-launch token auth, Host/Origin checks, a first-run consent gate,
  live updates over SSE, a management view with multi-device selection, and English/Turkish
  locales.
- `lemonet` command: selects the interface, serves the panel, and opens the browser.

### Known limitations
- Defeated by enterprise switch protections (Dynamic ARP Inspection, static ARP, client isolation).
- Obfuscated VPNs and full peer-to-peer game traffic are not reliably blockable.
- IPv6 control requires an IPv6 router on the LAN; otherwise only IPv4 is controlled.
