SHELL := /bin/bash

# Reuse local module/cache directories unless overridden by caller.
export GOMODCACHE ?= $(CURDIR)/.gomodcache
export GOCACHE ?= $(CURDIR)/.gocache

BINARY ?= uot
BIN_DIR ?= $(CURDIR)/bin

.PHONY: build test test-short test-integration bench fmt tidy clean

build: ## Build the uot agent and udpmon helper into ./bin
	@mkdir -p $(BIN_DIR)
	GO111MODULE=on go build -o $(BIN_DIR)/$(BINARY) ./cmd/uot
	GO111MODULE=on go build -o $(BIN_DIR)/udpmon ./cmd/udpmon

fmt: ## Format Go sources
	gofmt -w $$(git ls-files '*.go')

 tidy: ## Run go mod tidy to sync deps
	GO111MODULE=on go mod tidy

 test: ## Run all unit+integration tests (may require elevated perms for UDP bind)
	GO111MODULE=on go test ./... -count=1

 test-short: ## Run tests with -short flag (skips integration by default)
	GO111MODULE=on go test -short ./...

test-integration: ## Only run the integration test package
	GO111MODULE=on go test ./internal/agent -run Integration -count=1

bench: ## Run localhost performance benchmark (may take time)
	GO111MODULE=on go test ./internal/agent -run '^$$' -bench=BenchmarkLocalhostTunnel -count=1

clean: ## Remove build artifacts and local caches
	rm -rf $(BIN_DIR) $(GOMODCACHE) $(GOCACHE)
