# syntax=docker/dockerfile:1
# Multi-stage build for the auditor daemon (cmd/auditor). Env-driven; the same
# image runs under docker-compose or k8s.
#
# CROSS-MODULE BUILD: the auditor depends on the sibling `libs` module via a
# `replace => ../../libs` directive in go.mod, so the build CONTEXT is the REPO
# ROOT (not services/auditor). Build from the repo root with:
#
#   docker build -f services/auditor/Dockerfile -t auditor:local .
#
# Behind a TLS-inspecting egress proxy (corporate net / CI sandbox), pass the
# trust bundle so module + package fetches verify (no-op when absent):
#
#   docker build -f services/auditor/Dockerfile \
#     --secret id=ca_bundle,src=/etc/ssl/certs/ca-certificates.crt \
#     -t auditor:local .
#
# GOWORK=off so the build resolves deps through each module's go.mod + the local
# replace, not the repo go.work (whose other members aren't copied into the
# image — this matches the per-module CI build). All deps are public (baseproof) or
# local (libs), so no VCS auth is needed.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
# Cross-compile from the native build platform to TARGETOS/TARGETARCH (set by
# buildx) — no QEMU-emulated compilation. CGO is off, so this is a pure
# cross-compile and stays fast for arm64 on an amd64 runner.
ARG TARGETOS TARGETARCH

WORKDIR /src

# The sibling libs module is the `replace => ../../libs` target; copy it first so
# the cross-module require resolves, then the service module.
COPY libs/ ./libs/
COPY services/auditor/ ./services/auditor/

WORKDIR /src/services/auditor

# Build the auditor module standalone (its go.mod + local replace), not under the
# repo workspace.
ENV GOWORK=off

# Module + checksum-db fetches go over HTTPS. The optional ca_bundle secret
# trusts a TLS-inspecting proxy's CA (no-op when absent). Cache mounts speed
# re-builds without bloating the final image.
RUN --mount=type=secret,id=ca_bundle \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    go mod download

ARG VERSION=docker
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath -buildvcs=false \
    -ldflags "-X main.version=${VERSION}" \
    -o /auditor ./cmd/auditor

# ── Runtime ────────────────────────────────────────────────────
# Pinned base (not :latest) for reproducible, auditable rebuilds.
FROM alpine:3.21

# Trust the optional proxy CA before apk fetches over HTTPS (no-op when absent),
# then install runtime deps. The ca-certificates package re-resolves public roots
# so the final image trusts them for the auditor's own outbound TLS (peer feeds).
RUN --mount=type=secret,id=ca_bundle \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    apk --no-cache add ca-certificates tzdata wget \
    && adduser -D -H -u 65532 auditor

WORKDIR /
COPY --from=builder /auditor /auditor

# Non-root: the auditor reads public tiles + a mounted gossip signing key; never
# raw network keys. uid 65532 is the conventional distroless "nonroot" id.
USER 65532:65532

EXPOSE 8088

# Liveness over plain HTTP — the auditor's /healthz needs no client cert.
HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=3s \
    CMD wget -q -O- http://localhost:8088/healthz | grep -q '^ok$' || exit 1

ENTRYPOINT ["/auditor"]
