# meshp — development makefile
#
# CI calls these targets rather than reimplementing them in YAML, so anything
# that fails on a pull request fails the same way on a laptop. Tool versions are
# pinned here and fetched on demand with `go run`; nothing needs installing
# globally except Go, Docker and Node.

BUF_VERSION      := v1.47.2
SQLC_VERSION     := v1.27.0
GOLANGCI_VERSION := v2.12.2
GOVULN_VERSION   := v1.6.0

VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

# The container image tag. Overridable so CI can build a throwaway tag without
# clobbering whatever a developer has locally.
IMAGE    ?= meshp:ci

# The Go image used for the data-plane tests. Matches the toolchain CI uses; kept here
# rather than inline so there is one place to change when the toolchain moves.
GO_IMAGE_VERSION ?= 1.25
LDFLAGS  := -X github.com/meshpnet/meshp/internal/version.version=$(VERSION) \
            -X github.com/meshpnet/meshp/internal/version.commit=$(COMMIT)

BINARIES := meshp meshpd meshp-control meshp-relay

# Every platform meshp ships on, minus iOS: ios/arm64 needs cgo and an Xcode
# toolchain, so it is compiled by meshp-ios rather than here. A target dropping
# off this list is a platform we have quietly stopped supporting.
CROSS_TARGETS := linux/amd64 linux/arm64 linux/arm \
                 darwin/amd64 darwin/arm64 \
                 windows/amd64 windows/arm64 \
                 freebsd/amd64 android/arm64

# Three tiers, because the packages differ in what a coverage number is worth.
#
# Pure decision logic — addressing, health, selection, cryptography — has no I/O to
# stub and no excuse for a gap, so it is held high. Packages that touch files, sockets
# and processes have error paths that cost more to reach than they are worth, so they
# are held lower rather than pretended into the top tier. Packages needing PostgreSQL
# are checked separately: without a database their tests skip, and the figure would be
# meaningless rather than merely low.
COVER_FLOOR_PKGS := internal/clock internal/health internal/ipam internal/routes internal/keys internal/challenge internal/logx internal/controlurl internal/peerset internal/wgplan
COVER_FLOOR      := 90

COVER_FLOOR_IO_PKGS := internal/agentapi internal/agentstate internal/httpx internal/tunnel
COVER_FLOOR_IO      := 75

COVER_FLOOR_DB_PKGS := internal/store internal/enroll internal/api internal/session
COVER_FLOOR_DB      := 75

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

## --- build ----------------------------------------------------------------

# Everything a binary is built from. Without prerequisites the bin/% rule is
# considered up to date the moment the file exists, so `make build` silently stops
# rebuilding after the first run and hands you a stale binary — which is exactly
# what happened while wiring up the store. Declaring the targets .PHONY instead
# does not work: make will not apply a pattern rule to a phony target, so nothing
# builds at all.
#
# The .sql files are inputs too, because migrations are embedded into the binary.
BUILD_INPUTS := $(shell find cmd internal migrations proto -name '*.go' -o -name '*.sql' 2>/dev/null) \
                go.mod $(wildcard go.sum)

.PHONY: build
build: $(addprefix bin/,$(BINARIES)) ## Build all four binaries

bin/%: $(BUILD_INPUTS)
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o $@ ./cmd/$*

.PHONY: cross
cross: ## Verify every shipping platform still compiles
	@fail=0; \
	for t in $(CROSS_TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; \
	  if GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -o /dev/null ./... 2>/dev/null; then \
	    printf "  %-16s ok\n" "$$t"; \
	  else \
	    printf "  %-16s FAILED\n" "$$t"; fail=1; \
	  fi; \
	done; \
	exit $$fail

.PHONY: clean
clean:
	rm -rf bin dist cover.out proto/gen internal/store/gen

## --- test -----------------------------------------------------------------

.PHONY: test
test: ## Run unit tests with the race detector
	go test ./... -race -count=1

.PHONY: cover
cover: ## Run tests with coverage and print the total
	go test ./... -covermode=atomic -coverprofile=cover.out -count=1
	@go tool cover -func=cover.out | tail -1

.PHONY: cover-check
cover-check: ## Fail if an invariant-bearing package drops below the floor
	@fail=0; \
	for pkg in $(COVER_FLOOR_PKGS); do \
	  pct=$$(go test ./$$pkg/ -cover -count=1 2>/dev/null | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p'); \
	  if [ -z "$$pct" ]; then printf "  %-22s no coverage reported\n" "$$pkg"; fail=1; continue; fi; \
	  if [ "$$(awk -v p=$$pct -v f=$(COVER_FLOOR) 'BEGIN{print (p+0>=f+0)}')" = "1" ]; then \
	    printf "  %-22s %6s%%  ok\n" "$$pkg" "$$pct"; \
	  else \
	    printf "  %-22s %6s%%  below the %s%% floor\n" "$$pkg" "$$pct" "$(COVER_FLOOR)"; fail=1; \
	  fi; \
	done; \
	exit $$fail

.PHONY: integration
integration: ## Run the tests that need PostgreSQL (set MESHP_TEST_DATABASE_URL)
	@test -n "$(MESHP_TEST_DATABASE_URL)" || { echo "set MESHP_TEST_DATABASE_URL"; exit 2; }
	go test ./... -race -count=1

.PHONY: cover-check-db
cover-check-db: ## Coverage floor for packages that need PostgreSQL
	@test -n "$(MESHP_TEST_DATABASE_URL)" || { echo "set MESHP_TEST_DATABASE_URL"; exit 2; }
	@fail=0; \
	for pkg in $(COVER_FLOOR_DB_PKGS); do \
	  pct=$$(go test ./$$pkg/ -cover -count=1 2>/dev/null | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p'); \
	  if [ -z "$$pct" ]; then printf "  %-22s no coverage reported\n" "$$pkg"; fail=1; continue; fi; \
	  if [ "$$(awk -v p=$$pct -v f=$(COVER_FLOOR_DB) 'BEGIN{print (p+0>=f+0)}')" = "1" ]; then \
	    printf "  %-22s %6s%%  ok\n" "$$pkg" "$$pct"; \
	  else \
	    printf "  %-22s %6s%%  below the %s%% floor\n" "$$pkg" "$$pct" "$(COVER_FLOOR_DB)"; fail=1; \
	  fi; \
	done; \
	exit $$fail

.PHONY: cover-check-io
cover-check-io: ## Coverage floor for packages that do local I/O
	@fail=0; \
	for pkg in $(COVER_FLOOR_IO_PKGS); do \
	  pct=$$(go test ./$$pkg/ -cover -count=1 2>/dev/null | sed -n 's/.*coverage: \([0-9.]*\)%.*/\1/p'); \
	  if [ -z "$$pct" ]; then printf "  %-22s no coverage reported\n" "$$pkg"; fail=1; continue; fi; \
	  if [ "$$(awk -v p=$$pct -v f=$(COVER_FLOOR_IO) 'BEGIN{print (p+0>=f+0)}')" = "1" ]; then \
	    printf "  %-22s %6s%%  ok\n" "$$pkg" "$$pct"; \
	  else \
	    printf "  %-22s %6s%%  below the %s%% floor\n" "$$pkg" "$$pct" "$(COVER_FLOOR_IO)"; fail=1; \
	  fi; \
	done; \
	exit $$fail

.PHONY: fuzz-seeds
fuzz-seeds: ## Run every fuzz target against its seed corpus (fast)
	go test ./... -run '^Fuzz' -count=1

.PHONY: fuzz
fuzz: ## Fuzz one target: make fuzz PKG=./internal/ipam FUZZ=FuzzAllocatorOperations TIME=60s
	@test -n "$(PKG)" -a -n "$(FUZZ)" || { echo "usage: make fuzz PKG=./internal/ipam FUZZ=FuzzX [TIME=60s]"; exit 2; }
	go test $(PKG) -run '^$$' -fuzz '^$(FUZZ)$$' -fuzztime $(or $(TIME),60s)

## --- lint and generate ----------------------------------------------------

.PHONY: fmt
fmt: ## Format all Go code
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any Go file is not gofmt clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt clean:"; echo "$$unformatted" | sed 's/^/  /'; exit 1; fi; \
	echo "  all files are gofmt clean"

.PHONY: lint
lint: fmt-check ## Run go vet and golangci-lint
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run

.PHONY: tidy-check
tidy-check: ## Fail if go.mod or go.sum are not what `go mod tidy` would write
	@# -diff reports what would change and writes nothing, so this cannot leave the
	@# working tree modified if it is interrupted.
	@go mod tidy -diff || { \
	  echo "go.mod or go.sum is not tidy; run 'go mod tidy' and commit the result"; \
	  exit 1; \
	}
	@echo "  go.mod and go.sum are tidy"

.PHONY: vuln
vuln: ## Check dependencies and stdlib against the Go vulnerability database
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION) ./...

.PHONY: proto
proto: ## Generate Go code from proto/
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) generate

.PHONY: proto-lint
proto-lint: ## Lint protos and reject changes that break deployed agents
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) lint
	go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) breaking --against '.git#branch=main'

.PHONY: sqlc
sqlc: ## Generate type-safe database access from migrations/ and queries/
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION) generate

.PHONY: generate
generate: proto sqlc ## Run all code generation

## --- invariants -----------------------------------------------------------

.PHONY: standalone-check
standalone-check: ## Invariant 12: the core must not depend on the commercial layer
	@if grep -rn --include='*.go' 'meshpnet/meshp-cloud' . ; then \
	  echo "FAIL: the open core imports meshp-cloud"; exit 1; \
	fi
	@echo "  no proprietary imports"

.PHONY: e2e
e2e: build ## Enrol a device end to end against MESHP_TEST_DATABASE_URL
	@test -n "$(MESHP_TEST_DATABASE_URL)" || { echo "set MESHP_TEST_DATABASE_URL"; exit 2; }
	@./scripts/e2e-enrol.sh "$(MESHP_TEST_DATABASE_URL)"

.PHONY: image
image: ## Build the container image (VERSION and COMMIT are stamped in)
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  -f deploy/docker/Dockerfile \
	  -t $(IMAGE) .

.PHONY: image-smoke
image-smoke: image ## Start the image against MESHP_TEST_DATABASE_URL and wait for readiness
	@test -n "$(MESHP_TEST_DATABASE_URL)" || { echo "set MESHP_TEST_DATABASE_URL"; exit 2; }
	@MESHP_IMAGE=$(IMAGE) MESHP_DATABASE_URL="$(MESHP_TEST_DATABASE_URL)" ./scripts/image-smoke.sh

.PHONY: e2e-tunnel
e2e-tunnel: ## Run the end-to-end enrolment with real tunnels, in a privileged Linux container
	@# The whole stack where a tunnel is actually possible: control plane, two daemons,
	@# real interfaces. On macOS the plain `make e2e` skips the tunnel assertions, so this
	@# is the only way to exercise them from here.
	@./scripts/e2e-tunnel.sh

.PHONY: dataplane
dataplane: ## Run the data-plane tests against real interfaces, in a privileged Linux container
	@# Privileged and Linux, because there is no way to create a WireGuard interface
	@# without both. On a Linux host with root, `sudo -E go test ./internal/wglink/` does
	@# the same thing without Docker.
	docker run --rm --privileged \
	  -v "$(CURDIR)":/src -w /src \
	  -v "$$(go env GOMODCACHE)":/go/pkg/mod \
	  golang:$(GO_IMAGE_VERSION)-alpine sh -c \
	  'apk add --no-cache iproute2 wireguard-tools >/dev/null && go test ./internal/wglink/ -count=1 -v'

.PHONY: migrate-check
migrate-check: ## Apply, roll back and re-apply every migration against MESHP_TEST_DATABASE_URL
	@test -n "$(MESHP_TEST_DATABASE_URL)" || { echo "set MESHP_TEST_DATABASE_URL"; exit 2; }
	@./scripts/migrate-check.sh "$(MESHP_TEST_DATABASE_URL)"

## --- aggregate ------------------------------------------------------------

.PHONY: ci
ci: lint tidy-check standalone-check build cross test cover-check cover-check-io fuzz-seeds ## Everything CI runs, minus the jobs needing Postgres
	@echo
	@echo "  all local CI checks passed"

.PHONY: dev
dev: ## Bring up Postgres, the control plane and a relay
	docker compose up --build

.PHONY: dev-down
dev-down: ## Tear down the dev stack and its volumes
	docker compose down -v

.PHONY: protect
protect: ## Apply branch and tag protection: make protect REPO=meshp
	@test -n "$(REPO)" || { echo "usage: make protect REPO=meshp [ENFORCEMENT=active|disabled]"; exit 2; }
	@./scripts/protect-repo.sh "$(REPO)" $(or $(ENFORCEMENT),active)
