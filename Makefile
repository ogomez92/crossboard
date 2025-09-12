# Simple build helpers

DIST ?= dist
BIN  ?= crossboard
PKG  ?= ./cmd/crossboard

.PHONY: build clean build-os-arch

build:
	mkdir -p $(DIST)
	GOFLAGS=$(GOFLAGS) go build -o $(DIST)/$(BIN) $(PKG)

# Usage: make build-os-arch OS=linux ARCH=amd64
build-os-arch:
	@if [ -z "$(OS)" ] || [ -z "$(ARCH)" ]; then \
		echo "Usage: make build-os-arch OS=<goos> ARCH=<goarch>"; \
		echo "Example: make build-os-arch OS=linux ARCH=amd64"; \
		exit 2; \
	fi
	mkdir -p $(DIST)
	GOOS=$(OS) GOARCH=$(ARCH) GOFLAGS=$(GOFLAGS) go build -o $(DIST)/$(BIN)-$(OS)-$(ARCH) $(PKG)

clean:
	rm -rf $(DIST)
