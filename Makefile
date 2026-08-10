# meshp — development makefile
#
# Tool versions are pinned here so CI and laptops agree. Tools are fetched on
# demand with `go run`; nothing needs to be installed globally except Go,
# Docker and Node.

BUF_VERSION      := v1.47.2
SQLC_VERSION     := v1.27.0
GOLANGCI_VERSION := v1.62.2

VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS  := -X github.com/meshpnet/meshp/internal/version.version=$(VERSION) \
            -X github.com/meshpnet/meshp/internal/version.commit=$(COMMIT)

BINARIES := meshp meshpd meshp-control meshp-relay

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: $(addprefix bin/,$(BINARIES)) ## Build all four binaries

bin/%:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/$*

.PHONY: test
test: ## Run unit tests
	go test ./... -race -count=1

.PHONY: lint
lint: ## Run golangci-lint and go vet
	go vet ./...
	go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_VERSION) run

.PHONY: proto
proto: ## Generate Go code from proto/ (ADR-0008)
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) generate

.PHONY: proto-lint
proto-lint: ## Lint protos and check backwards compatibility against main
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) lint
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) breaking --against '.git#branch=main'

.PHONY: sqlc
sqlc: ## Generate type-safe database access from migrations/ and queries/
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

.PHONY: generate
generate: proto sqlc ## Run all code generation

.PHONY: dev
dev: ## Bring up Postgres and meshp-control
	docker compose up --build

.PHONY: dev-down
dev-down: ## Tear down the dev stack and its volumes
	docker compose down -v

.PHONY: standalone-check
standalone-check: ## ADR-0009: the OSS core must build and test with no proprietary deps
	@! grep -rn --include='*.go' 'meshpnet/meshp-cloud' . \
		|| (echo "FAIL: OSS core imports meshp-cloud"; exit 1)
	@echo "OK: no proprietary imports"

.PHONY: license-boundary
license-boundary: standalone-check ## Alias kept for CI readability

.PHONY: clean
clean:
	rm -rf bin dist proto/gen internal/store/gen
