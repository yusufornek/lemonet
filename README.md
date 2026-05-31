<p align="center">
  <img src="https://github.com/user-attachments/assets/dcd35175-7595-44ff-8f0c-3d2bf3e538ee" alt="lemonet" width="180">
</p>

# lemonet

A free, open-source, cross-platform tool for taking control of your own local network. Run
`lemonet` and a clean control panel opens in your browser. From there you can discover the
devices on your network, cut a device off, throttle its bandwidth, and block sites, games, or
VPNs by category.

lemonet is built for network owners, administrators, and educators who want a capable, modern,
auditable alternative to closed tools, without ads, paywalls, or platform lock-in.

> Status: early development. The architecture and interfaces are settled; features are landing
> incrementally. See [open issues](https://github.com/yusufornek/lemonet/issues) for current work.

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
from its use.

Do not use lemonet for unauthorized access, harassment, or disruption of other people's
connectivity. See [docs/ETHICS.md](docs/ETHICS.md) for the full policy.

## What it does

- **Discover** devices on the LAN with IP, MAC, vendor, and hostname.
- **Cut** a device's connectivity on or off.
- **Throttle** a device's upload and download bandwidth in real time.
- **Filter** sites, games, VPNs, ads, and other categories per device.

All of this is controlled from a local web panel that the binary serves on `127.0.0.1` and opens
automatically in your browser.

## How it works, honestly

lemonet places itself between a target device and the gateway on the same LAN (ARP-based
man-in-the-middle), then applies your policy to the traffic that flows through it. Bandwidth
shaping runs in user space, so it behaves the same on every platform. Site and category filtering
work at the DNS and TLS-SNI layers; lemonet does not decrypt traffic or install a certificate on
any device.

This approach has real limits, and lemonet will not pretend otherwise:

- It works on cooperative home and small-office networks. Enterprise switches with Dynamic ARP
  Inspection, static ARP entries, or client isolation will defeat it.
- Encrypted bypass channels reduce filtering reliability. Obfuscated VPNs and full peer-to-peer
  game traffic are not reliably blockable.
- v1.0 controls IPv4 only. On dual-stack networks, a device may still reach IPv6 destinations.

## Requirements

- Administrator/root privileges (raw packet access).
- A packet capture backend: libpcap on Linux/macOS, [Npcap](https://npcap.com/) on Windows
  (installed separately).

## Building from source

```sh
git clone https://github.com/yusufornek/lemonet.git
cd lemonet
# build the web panel
cd web && npm install && npm run build && cd ..
# build the binary
go build -o lemonet ./cmd/lemonet
sudo ./lemonet
```

To make `lemonet` available as a command on your PATH:

```sh
sudo make install        # installs to /usr/local/bin
sudo lemonet
```

Run it with `sudo` because raw packet access requires elevated privileges. `sudo` uses a
restricted PATH, so until lemonet is installed, run it as `sudo ./lemonet` from the build
directory.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md) first. Security reports go through
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
