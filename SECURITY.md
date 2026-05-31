# Security policy

## Reporting a vulnerability

Do not open a public issue for security vulnerabilities. Report them privately through GitHub's
[private vulnerability reporting](https://github.com/yusufornek/lemonet/security/advisories/new)
for this repository.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- Affected version or commit.

You can expect an initial response within 7 days. Once a fix is available, we will coordinate
disclosure and credit you if you wish.

## Supported versions

During pre-1.0 development, only the latest release and `main` receive security fixes. A formal
support window will be defined at the 1.0 release.

## Scope

lemonet is a privileged network tool. Reports of particular interest include: bypass of the
loopback-only binding or capability token, Host/Origin or CSRF validation gaps, incomplete
restoration of ARP or forwarding state, and privilege-handling flaws.
