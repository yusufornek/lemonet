<p align="center">
  <img src="https://github.com/user-attachments/assets/dcd35175-7595-44ff-8f0c-3d2bf3e538ee" alt="lemonet" width="280">
</p>

# lemonet

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-555.svg)

A free, open-source, cross-platform tool for taking control of your own local network. Run
`lemonet` and a clean control panel opens in your browser. From there you can discover the
devices on your network, cut a device off, throttle its bandwidth, and block sites, games, or
VPNs by category — over both IPv4 and IPv6.

lemonet is built for network owners, administrators, and educators who want a capable, modern,
auditable alternative to closed tools, without ads, paywalls, or platform lock-in.

> Status: pre-1.0. The engine and interfaces are settled and the core works end to end on
> Linux and macOS; Windows support and packaged releases are in progress.

## Ethical and legal use

lemonet is a network administration and diagnostics tool intended **only** for networks that you
own or for which you have **explicit, written authorization** to manage and test.

Using lemonet to interfere with, intercept, or disrupt traffic on networks you do not own or are
not authorized to manage may be **illegal** in your jurisdiction and can carry serious civil and
criminal penalties. Laws vary by country. Consult local regulations and obtain authorization
before use.

By downloading, installing, or running lemonet you agree that **you alone are responsible** for
how you use it. The software is provided "as is", without warranty of any kind, and the authors
and contributors accept **no liability** for any misuse, damage, or legal consequences arising
from its use. See [docs/ETHICS.md](docs/ETHICS.md) for the full policy.

## What it does

- **Discover** devices on the LAN with IP, MAC, vendor, hostname, and a best-effort device type.
- **Cut** a device's connectivity on or off.
- **Throttle** a device's upload and download bandwidth in real time.
- **Filter** sites, ads, and whole categories per device, with custom allow/block domain rules.

Everything is controlled from a local web panel that the binary serves on `127.0.0.1` and opens
automatically in your browser. A management view handles per-device rules and multi-device
selection.

## How it works, honestly

lemonet places itself between a device and the gateway on the same LAN — ARP for IPv4 and NDP for
IPv6 — then applies your policy to the traffic that flows through it. Forwarding and bandwidth
shaping run in user space, so behavior is the same on every platform. Site and category filtering
work at the DNS and TLS-SNI layers; lemonet does not decrypt traffic or install a certificate on
any device. All spoofing and forwarding state is restored when you stop or release a device.

This approach has real limits, and lemonet does not pretend otherwise:

- It works on cooperative home and small-office networks. Enterprise switches with Dynamic ARP
  Inspection, static ARP entries, or client isolation will defeat it.
- Encrypted bypass channels reduce filtering reliability. Obfuscated VPNs and full peer-to-peer
  game traffic are not reliably blockable.
- IPv6 control is best-effort and requires an IPv6 router on the LAN. Where there is none, only
  IPv4 is controlled.

## Requirements

- **Run:** administrator/root privileges (raw packet access), and a packet capture backend —
  libpcap on Linux/macOS (usually preinstalled), or [Npcap](https://npcap.com/) on Windows.
- **Build:** Go 1.25+. No Node toolchain is needed; the web panel ships pre-built and embedded.

## Build and run

```sh
git clone https://github.com/yusufornek/lemonet.git
cd lemonet
go build -o lemonet ./cmd/lemonet
sudo ./lemonet
```

To install it on your PATH:

```sh
sudo make install        # installs to /usr/local/bin
sudo lemonet
```

Run with `sudo`: raw packet access requires elevated privileges. `sudo` uses a restricted PATH,
so until lemonet is installed, run it as `sudo ./lemonet` from the build directory.

## Usage

1. Run `sudo lemonet`. It prints a loopback URL containing a one-time token and opens your browser.
2. Accept the first-run consent (you confirm you own or are authorized to manage the network).
3. **Scan** to list devices.
4. Block, throttle, or open **Manage** to add per-device filter rules — including blocking a
   specific site by typing its domain — across one or more selected devices.
5. Press Ctrl+C to stop; lemonet restores every device's network state before exiting.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) first. Report vulnerabilities privately per
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
