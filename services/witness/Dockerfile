# syntax=docker/dockerfile:1
# Multi-stage build for the standalone-witness service: the daemon (cmd/witness)
# AND the fixture generator (cmd/gen-fixtures) in one image. The daemon is the
# default entrypoint; gen-fixtures is reachable via `--entrypoint /gen-fixtures`
# so a strict-pull deployment can mint witness keys + the network bootstrap from
# the SAME published image — no source checkout needed.
#
# CROSS-MODULE BUILD: the witness depends on the sibling `libs` module via a
# `replace => ../../libs` directive in go.mod (libs/tracing), so the build
# CONTEXT is the REPO ROOT (not services/witness). Build from the repo root:
#   docker build -f services/witness/Dockerfile -t witness:local .
#
# Run the daemon (non-root; mount the key readable by uid 65532):
#   docker run --rm -v $(pwd)/.run:/keys:ro -p 8081:8081 witness:local \
#     -addr=:8081 -key-file=/keys/witnesses/witness-1.pem \
#     -bootstrap=/keys/network-bootstrap.json
#
# Mint fixtures (writes to a mounted, writable dir):
#   docker run --rm --entrypoint /gen-fixtures -v $(pwd)/.run:/out witness:local \
#     -out-dir=/out -out-bootstrap=/out/network-bootstrap.json -witnesses=5
#
# Behind a TLS-inspecting egress proxy, pass the trust bundle (no-op when absent):
#   docker build -f services/witness/Dockerfile \
#     --secret id=ca_bundle,src=/etc/ssl/certs/ca-certificates.crt -t witness:local .
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
# Cross-compile from the native build platform to TARGETOS/TARGETARCH (set by
# buildx) — no QEMU-emulated compilation. CGO is off, so this is a pure
# cross-compile and stays fast for arm64 on an amd64 runner.
ARG TARGETOS TARGETARCH

WORKDIR /src

# The sibling libs module is the `replace => ../../libs` target; copy it first so
# the cross-module require resolves, then the service module.
COPY libs/ ./libs/
COPY services/witness/ ./services/witness/

WORKDIR /src/services/witness

# Build the witness module standalone (its go.mod + local replace), not under
# the repo workspace.
ENV GOWORK=off

# Deps are public, so no VCS auth. The optional ca_bundle secret trusts a
# TLS-inspecting proxy's CA; cache mounts speed re-builds without bloating the
# final image.
RUN --mount=type=secret,id=ca_bundle \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    go mod download

# VERSION is stamped into main.version. Defaults to "docker" when the build arg
# is omitted so an unstamped image is still identifiable.
ARG VERSION=docker

# Static, reproducible binaries (daemon + fixture generator). CGO off so the
# runtime needs no glibc shim; -trimpath strips local paths.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
      -ldflags "-X main.version=${VERSION}" -o /witness ./cmd/witness && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
      -o /gen-fixtures ./cmd/gen-fixtures

# ── Runtime ────────────────────────────────────────────────────
# Pinned base (not :latest) for reproducible, auditable rebuilds.
FROM alpine:3.21

RUN --mount=type=secret,id=ca_bundle \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    apk --no-cache add ca-certificates wget tzdata \
    && adduser -D -H -u 65532 witness

WORKDIR /

COPY --from=builder /witness /witness
COPY --from=builder /gen-fixtures /gen-fixtures

# Run as a non-root, no-home user. The mounted key file + bootstrap must be
# readable by uid 65532 (gen-fixtures runs with a writable mount; override the
# uid with `docker run --user` when minting into a host-owned dir).
USER 65532:65532

EXPOSE 8081

# Healthcheck hits /healthz — the daemon's built-in liveness endpoint. Returns
# "ok" with 200 when the cosign handler is wired and listening. The witness serves
# HTTPS when -tls-cert/-tls-key are set (main.go: tlsEnabled), plain HTTP otherwise
# — so probe BOTH schemes (HTTP first: the compose / e2e default; then HTTPS with
# --no-check-certificate for the self-signed cert) and pass if either returns "ok".
# -T 1 bounds each attempt under the 3s timeout.
#
# NOTE: Kubernetes IGNORES this directive — kubelet runs the chart probes. This
# HEALTHCHECK governs docker / docker-compose / Swarm only.
HEALTHCHECK --interval=2s --timeout=3s --retries=10 --start-period=2s \
    CMD wget -q -T 1 -O- http://localhost:8081/healthz 2>/dev/null | grep -q '^ok$' \
        || wget -q -T 1 --no-check-certificate -O- https://localhost:8081/healthz 2>/dev/null | grep -q '^ok$' \
        || exit 1

ENTRYPOINT ["/witness"]
