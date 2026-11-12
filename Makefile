GO ?= go
BIN := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(shell git rev-parse HEAD 2>/dev/null) -X main.date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
FUZZTIME ?= 30s
BINARIES := tollkeeper:./cmd/tollkeeper devissuer:./cmd/devissuer mcpbench:./cmd/mcpbench democlient:./cmd/democlient \
	notes-server:./examples/servers/notes weather-server:./examples/servers/weather \
	files-server:./examples/servers/files noop-server:./examples/servers/noop

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Format code
	golangci-lint fmt ./...

.PHONY: lint
lint: ## golangci-lint, no-comments checker and tidy check
	golangci-lint run ./...
	$(GO) run ./internal/tools/nocomments
	$(GO) mod tidy -diff

.PHONY: test
test: ## Unit and in-process integration tests with the race detector
	$(GO) test -race -shuffle=on -count=1 ./...

.PHONY: cover
cover: ## Coverage report
	$(GO) test -count=1 -covermode=atomic -coverprofile=cover.out ./...
	$(GO) tool cover -func=cover.out | tail -1

.PHONY: fuzz
fuzz: ## Run every fuzz target for FUZZTIME
	$(GO) test -run='^$$' -fuzz='^FuzzParseEnvelope$$' -fuzztime=$(FUZZTIME) ./internal/gateway
	$(GO) test -run='^$$' -fuzz='^FuzzRejectDuplicateKeys$$' -fuzztime=$(FUZZTIME) ./internal/gateway
	$(GO) test -run='^$$' -fuzz='^FuzzVerify$$' -fuzztime=$(FUZZTIME) ./internal/audit
	$(GO) test -run='^$$' -fuzz='^FuzzPolicyArgs$$' -fuzztime=$(FUZZTIME) ./internal/policy
	$(GO) test -run='^$$' -fuzz='^FuzzQualify$$' -fuzztime=$(FUZZTIME) ./internal/catalog

.PHONY: bench
bench: ## Micro-benchmarks (count=10) into bench/results/raw
	@mkdir -p bench/results/raw
	$(GO) test -run='^$$' -bench=. -benchmem -count=10 ./internal/... | tee bench/results/raw/$(shell git rev-parse --short HEAD).txt

.PHONY: bench-e2e
bench-e2e: build ## End-to-end overhead benchmark (gateway vs direct)
	$(BIN)/mcpbench overhead -bin-dir $(BIN) -out bench/results

.PHONY: build
build: ## Build all binaries into ./bin
	@mkdir -p $(BIN)
	@for b in $(BINARIES); do \
		CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/$${b%%:*} $${b#*:} || exit 1; \
	done

.PHONY: vuln
vuln: ## govulncheck
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

.PHONY: up
up: ## docker compose up the demo stack
	docker compose up --build -d --wait

.PHONY: demo
demo: up ## Run the scripted demo against the compose stack
	$(GO) run ./cmd/democlient

.PHONY: down
down: ## Stop the demo stack
	docker compose down -v

.PHONY: snapshot
snapshot: ## goreleaser snapshot build
	goreleaser release --snapshot --clean --skip=sign,publish

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN) dist cover.out
