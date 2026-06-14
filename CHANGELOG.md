# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-14

Second public release. This release turns the first control-panel prototype into a more complete
LAN management tool with stronger mobile-app filtering, safer lifecycle handling, richer policy
management, and a much clearer management UI.

### Added
- Policy profiles for common use cases:
  - Focus blocks social media, streaming video, gaming, gambling, encrypted DNS, VPN defaults,
    QUIC, and ECH.
  - Guest blocks ads, malware, encrypted DNS, VPN defaults, QUIC, and ECH.
  - Child blocks social media, streaming video, gaming, gambling, malware, encrypted DNS, VPN
    defaults, QUIC, and ECH.
- Built-in category packs for streaming video, encrypted DNS, VPN/proxy, gaming, gambling, and
  malware/phishing, alongside expanded social and ads coverage.
- Mobile-app domain coverage for the built-in packs so category filtering reaches common app
  endpoints, not only browser domains.
- Per-category domain transparency in the management panel, with compact expandable domain samples
  and total domain counts.
- Policy import/export for copying a device's filtering setup to other devices.
- Per-device rule explanation so the panel can show why a domain is allowed or blocked.
- Action previews for bulk block/release operations, including protected-device counts, restore
  impact, and session start/stop impact.
- One-step undo for recent policy changes, including block, release, temporary controls, and
  filtering changes.
- Timed block and throttle controls with automatic expiry.
- Diagnostics and preflight endpoints, plus panel cards for relay counters, recent relay events,
  protected devices, capture readiness, pack loading, and IPv6 availability.
- Host and gateway device protection so lemonet refuses to control the machine running the panel
  or the network gateway.
- Per-launch token persistence in session storage so refreshing the panel does not lose API
  access.
- Separate Unix/Windows shutdown signal files and tests for platform-appropriate cleanup handling.

### Changed
- Domain filtering now automatically enables hardening controls for QUIC, encrypted DNS, ECH,
  Firefox DoH canary, VPN ports, and the encrypted-DNS/VPN packs whenever a domain policy is active.
- The userspace relay now treats blocked flows as hard failures by sending TCP resets or UDP
  unreachable replies instead of relying on silent timeout behavior.
- DNS response handling now remembers blocked A and AAAA answers, HTTPS/SVCB address hints, and
  additional records so later connections to learned blocked IPs are dropped even without another
  visible domain.
- TLS filtering now tracks allowed HTTPS flows and drops unobserved opaque TLS/ECH traffic while
  domain filtering is active.
- Encrypted DNS blocking now covers common DoH, DoT, DoQ, and DNSCrypt ports and known resolver IP
  ranges, including IPv6 resolver ranges.
- QUIC blocking now covers UDP 443, 4433, and 8443 in both upload and download directions.
- IPv6 device handling now learns global IPv6 addresses during scans and relay traffic, exposes
  them in the UI, and refreshes active spoofing immediately when a new address is learned.
- IPv6 scanning now sends an all-nodes probe to shorten the time before dual-stack devices become
  visible.
- Running spoof sessions now refresh immediately when filters or newly learned IPv6 addresses
  change the target set.
- Stop/release/close now waits for restore paths and keeps retry state when restoration fails,
  instead of dropping state prematurely.
- The management UI now keeps category rows compact by default, makes Diagnostics closeable, shows
  protected-device badges, shows IPv6 addresses, and avoids selecting protected devices in bulk.
- The server now applies stricter same-origin API checks and security headers while preserving
  static panel access.

### Fixed
- Fixed a panel refresh/token loss path that could make the UI appear unauthorized after reload.
- Fixed bulk policy validation so failed multi-device changes do not partially mutate controller
  state.
- Fixed release and undo races so stale snapshots cannot overwrite newer policy state.
- Fixed temporary control expiry so filters survive block/throttle expiry when they were already
  active.
- Fixed relay handling for IPv6 TCP drops, IPv6 UDP drops, IPv6 fragments, gateway link-local DNS,
  and download-direction classification.
- Fixed DNS ECH stripping for additional records and TCP DNS responses.
- Fixed remote blocklist loading so cached data remains available when a refresh fails.
- Fixed CodeQL path-injection and review findings in the remote blocklist cache path.

### Security
- API requests now include a custom same-origin header in addition to the per-launch token.
- Content Security Policy is generated from the embedded panel script hash.
- Remote blocklist cache paths are constrained to known pack IDs.
- Protected host/gateway safeguards are enforced before block, throttle, filter, profile, undo,
  export, import, rule, pack, and toggle actions.
- Restoration is covered by additional stop, close, panic, restore-failure, and retry tests.

### Tests
- Added broad controller policy tests for profiles, previews, protected devices, policy templates,
  undo, temporary controls, restore failure handling, and concurrent policy races.
- Added relay tests for hard-drop TCP resets, UDP unreachable replies, IPv4/IPv6 routing, fragments,
  diagnostics, device counters, and IPv6 learned-address refresh hooks.
- Added filter tests for DNS A/AAAA response replacement, HTTPS/SVCB hints, SNI learning, ECH
  behavior, QUIC fallbacks, encrypted DNS resolver IPs, Firefox canary, pack metadata, and cache
  behavior.
- Added server tests for auth, Host/Origin checks, consent gating, profile/policy APIs, pack
  refresh, security headers, and CSP generation.

### Known limitations
- Obfuscated VPNs, full peer-to-peer game traffic, enterprise switch protections, static ARP,
  Dynamic ARP Inspection, client isolation, and clients already using cached ECH keys may still
  bypass or reduce filtering.
- IPv6 control remains best effort and depends on discovering an IPv6 router and learning each
  device's IPv6 addresses on the LAN.

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
