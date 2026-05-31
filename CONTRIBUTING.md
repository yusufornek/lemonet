# Contributing to lemonet

Thanks for your interest in improving lemonet. This guide covers how to build, the standards we
hold code to, and how to submit changes.

## Authorized testing only

lemonet is a network control tool. Test your changes only against networks you own or are
authorized to manage. Pull requests must not include logs, captures, or data from networks you do
not control.

## Development setup

Requirements: Go 1.25+, Node.js 20+, and a packet capture backend (libpcap on Linux/macOS, Npcap
on Windows).

```sh
git clone https://github.com/yusufornek/lemonet.git
cd lemonet
cd web && npm install && npm run build && cd ..
go build ./cmd/lemonet
```

Run the test suite and linters before opening a pull request:

```sh
go test ./...
go vet ./...
golangci-lint run
gofmt -l .        # must print nothing
```

## Code standards

- **English only** in code, comments, identifiers, and documentation. Turkish belongs only in
  `locales/tr.json`.
- **Clean, self-documenting code.** Comment only what is genuinely non-obvious, in one or two
  lines. No filler, no narration, no decorative banners, no emojis.
- **Small, focused packages.** Keep the public surface minimal.
- **Tests** for engine, enforcement, and filtering logic.
- Code must be `gofmt`-clean and pass `golangci-lint`.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`). This drives semantic versioning and the changelog.
- Keep pull requests focused and describe the motivation, not just the change.
- Link the issue you are addressing.
- Confirm tests and linters pass locally.

## Dependencies

lemonet is MIT-licensed and links only permissively licensed code (MIT, BSD, ISC, Apache-2.0, or
the Go standard library and `golang.org/x`). **Do not add GPL/AGPL dependencies.** A GPL tool may
only be invoked as a separate process, never linked or vendored. State the license of any new
dependency in your pull request.
