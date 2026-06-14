.PHONY: build web test lint fmt clean run install uninstall

PREFIX ?= /usr/local
GO ?= $(shell if [ -x /opt/homebrew/bin/go ]; then printf /opt/homebrew/bin/go; else command -v go; fi)
GOFLAGS ?= -buildvcs=false

build: web
	$(GO) build $(GOFLAGS) -o lemonet ./cmd/lemonet

install: build
	install -m 0755 lemonet $(PREFIX)/bin/lemonet

uninstall:
	rm -f $(PREFIX)/bin/lemonet

web:
	@if [ -f web/package.json ]; then cd web && npm install && npm run build; else test -f web/dist/index.html; fi

test:
	$(GO) test $(GOFLAGS) ./...

lint:
	$(GO) vet ./...
	golangci-lint run
	gofmt -l .

fmt:
	gofmt -w .

run: build
	sudo ./lemonet

clean:
	rm -f lemonet lemonet.exe
	@if [ -f web/package.json ]; then rm -rf web/dist; fi
