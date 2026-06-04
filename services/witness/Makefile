# standalone-witness — make targets
#
# Build / test / lint targets, plus the local-dev orchestration
# wrappers documented in scripts/local/README.dev.md.

GO ?= go

# Version stamped into the binary (main.version). Derived from git;
# overridable: make build VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
# Reproducible-build flags: -trimpath strips local paths; -buildvcs
# stamps VCS metadata.
BUILDFLAGS := -trimpath -buildvcs=true -ldflags "$(LDFLAGS)"

# Local-dev parameters. Overridable on the command line:
#
#   make run-local WITNESS_COUNT=3
#   make dev-up    WITNESS_COUNT=3 WITNESS_PORT_BASE=9001
WITNESS_COUNT      ?= 1
WITNESS_PORT_BASE  ?= 19001

DEV_COMPOSE_FILE := .run/docker-compose.yml
DEV_COMPOSE      := docker compose -f $(DEV_COMPOSE_FILE)

.PHONY: build test test-short test-race vet tidy clean help \
        vuln sbom \
        gen-fixtures run-local run-local-down clean-run print-env \
        dev-preflight dev-up dev-down dev-logs dev-status

help: ## List available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Build / test ────────────────────────────────────────────────

build: ## Compile the witness binary to ./bin/standalone-witness (version-stamped)
	@mkdir -p ./bin
	$(GO) build $(BUILDFLAGS) -o ./bin/standalone-witness ./cmd/witness

test: ## Run the full test suite (unit + daemon e2e)
	$(GO) test -count=1 ./...

test-short: ## Run only the fast unit tests (skips the daemon e2e)
	$(GO) test -short -count=1 ./...

test-race: ## Run the full test suite with the race detector
	$(GO) test -race -count=1 ./...

vuln: ## Scan for known vulnerabilities (govulncheck)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

sbom: ## Generate a CycloneDX SBOM at ./bin/sbom.json (needs cyclonedx-gomod)
	@mkdir -p ./bin
	$(GO) run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest mod \
		-json -output ./bin/sbom.json
	@echo "wrote ./bin/sbom.json"

vet: ## go vet across all packages
	$(GO) vet ./...

tidy: ## go mod tidy + verify
	$(GO) mod tidy
	$(GO) mod verify

clean: ## Remove build artifacts
	rm -rf ./bin

# ── Local-dev: fixtures + Go-native orchestration ───────────────

gen-fixtures: ## Generate .run/witnesses/*.pem + .run/network-bootstrap.json
	$(GO) run ./cmd/gen-fixtures \
	    -out-dir=.run \
	    -out-bootstrap=.run/network-bootstrap.json \
	    -witnesses=$(WITNESS_COUNT)

run-local: ## No-Docker escape hatch: spawn N witness daemons as bare processes
	./scripts/run-local.sh \
	    --witnesses $(WITNESS_COUNT) \
	    --port-base $(WITNESS_PORT_BASE)

run-local-down: ## Stop daemons spawned by `make run-local`
	./scripts/run-local.sh down

print-env: ## Print `export LEDGER_*` lines for the running fleet — use: eval "$$(make -s print-env)"
	@if [ -f .run/witness.env ]; then \
	  cat .run/witness.env; \
	else \
	  echo "no .run/witness.env — boot a fleet first (make run-local / make dev-up)" >&2; exit 1; \
	fi

clean-run: ## Tear down anything in .run/ AND remove the directory
	@./scripts/run-local.sh down 2>/dev/null || true
	@if [ -f $(DEV_COMPOSE_FILE) ]; then $(DEV_COMPOSE) down -v 2>/dev/null || true; fi
	rm -rf .run

# ── Local-dev: Docker compose orchestration (default path) ──────

dev-preflight: ## Validate that go + docker + docker compose are usable
	@command -v go >/dev/null 2>&1 || { \
	  echo "FAIL: go not on PATH"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { \
	  echo "FAIL: docker not on PATH"; exit 1; }
	@docker compose version >/dev/null 2>&1 || { \
	  echo "FAIL: docker compose v2 not available"; \
	  echo "      install Docker Compose v2 (the v1 'docker-compose' CLI is not supported)"; \
	  exit 1; }
	@docker info >/dev/null 2>&1 || { \
	  echo "FAIL: docker daemon not reachable"; \
	  echo "      start Docker Desktop, or 'sudo systemctl start docker'"; \
	  exit 1; }
	@echo "dev-preflight: go ok, docker ok, docker compose ok, daemon reachable"

dev-up: dev-preflight gen-fixtures ## Boot K=N witness fleet under Docker (default local-dev path)
	WITNESS_COUNT=$(WITNESS_COUNT) WITNESS_PORT_BASE=$(WITNESS_PORT_BASE) \
	    ./scripts/local/render-compose.sh
	$(DEV_COMPOSE) up -d --build
	@echo "waiting for witness fleet to report healthy..."
	@for i in $$(seq 1 60); do \
	  unhealthy=$$($(DEV_COMPOSE) ps --format '{{.Health}}' | grep -vc '^healthy$$' || true); \
	  if [ "$$unhealthy" = "0" ]; then \
	    echo "ready: all $(WITNESS_COUNT) witness(es) healthy"; \
	    ./scripts/local/write-env.sh $(WITNESS_COUNT) $(WITNESS_PORT_BASE) .run/network-bootstrap.json .run; \
	    exit 0; \
	  fi; \
	  sleep 2; \
	done; \
	echo "FAIL: witnesses did not report healthy in time; run 'make dev-logs'"; \
	exit 1

dev-down: ## Tear down the Docker witness fleet AND its volumes
	@if [ -f $(DEV_COMPOSE_FILE) ]; then \
	  $(DEV_COMPOSE) down -v; \
	else \
	  echo "no $(DEV_COMPOSE_FILE); nothing to tear down."; \
	fi

dev-logs: ## Tail logs from every Docker witness container
	$(DEV_COMPOSE) logs -f

dev-status: ## Show Docker witness service status
	$(DEV_COMPOSE) ps
