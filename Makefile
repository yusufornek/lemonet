.PHONY: build web test lint fmt clean run install uninstall

PREFIX ?= /usr/local

build: web
	go build -o lemonet ./cmd/lemonet

install: build
	install -m 0755 lemonet $(PREFIX)/bin/lemonet

uninstall:
	rm -f $(PREFIX)/bin/lemonet

web:
	cd web && npm install && npm run build

test:
	go test ./...

lint:
	go vet ./...
	golangci-lint run
	gofmt -l .

fmt:
	gofmt -w .

run: build
	sudo ./lemonet

clean:
	rm -f lemonet lemonet.exe
	rm -rf web/dist
