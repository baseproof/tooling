# syntax=docker/dockerfile:1
# Multi-stage build for cmd/ledger. The binary is fully env-driven (LEDGER_*),
# so the SAME image runs under the local dev scripts, docker-compose, or k8s —
# configured only by env + mounted Secret/ConfigMap files. No config is baked in.
#
# Build from the MONOREPO ROOT — the context must include the sibling libs/
# module (ledger's `replace => ../../libs` target), the same cross-module shape
# as services/witness/Dockerfile:
#   docker build -f services/ledger/scripts/local/Dockerfile .
#
# Behind a TLS-inspecting egress proxy (CI sandbox / corporate net), pass the
# trust bundle so module + package fetches verify (no-op when absent):
#   docker build -f services/ledger/scripts/local/Dockerfile \
#     --secret id=ca_bundle,src=/etc/ssl/certs/ca-certificates.crt .
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
# Cross-compile from the native build platform to TARGETOS/TARGETARCH (set by
# buildx) — no QEMU-emulated compilation. CGO is off, so this is a pure
# cross-compile and stays fast for arm64 on an amd64 runner.
ARG TARGETOS TARGETARCH

WORKDIR /src

# Cross-module build (mirrors services/witness/Dockerfile): the build CONTEXT is
# the REPO ROOT so the sibling libs module — ledger's `replace => ../../libs`
# target — is in scope. Copy libs/ first so the cross-module require resolves,
# then the ledger module (with its committed go.work + third_party/tessera
# submodule that the default fork variant links).
COPY libs/ ./libs/
COPY services/ledger/ ./services/ledger/

WORKDIR /src/services/ledger

# All deps are public (baseproof SDK + the AWS/badger/etc. modules), so no VCS auth
# is needed. The optional ca_bundle secret trusts a TLS-inspecting proxy's CA;
# cache mounts speed re-builds without bloating the final image.
RUN --mount=type=secret,id=ca_bundle \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    go mod download

# VERSION is stamped into main.Version; defaults to "docker" for unstamped
# (local) builds. Build the daemon PLUS the ops CLIs (submit-stamp seeds an
# entry; genesis-ceremony mints/assembles a network constitution) so an image-only deployment can
# seed + bootstrap from the SAME image — no source checkout, no `go run`. Static,
# reproducible binaries: CGO off, -trimpath, -buildvcs=false.
ARG VERSION=docker
# TESSERA_VARIANT selects the in-process Tessera implementation (see
# tessera/FORK.md). Default `fork` links the in-repo third_party/tessera
# submodule via the committed go.work (deterministic Appender.Shutdown). The
# fork build therefore requires the submodule to be present in the build context
# (the publishing workflow checks it out with submodules: recursive). `upstream`
# ignores the workspace (GOWORK=off) and builds the go.mod-pinned Google tessera.
ARG TESSERA_VARIANT=fork
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ "${TESSERA_VARIANT}" = "upstream" ]; then export GOWORK=off; fi; \
    echo "tessera variant: ${TESSERA_VARIANT} (GOWORK=${GOWORK:-auto})"; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -ldflags "-X main.Version=${VERSION}" \
      -o /ledger ./cmd/ledger && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -ldflags "-X main.Version=${VERSION}" \
      -o /ledger-reader ./cmd/ledger-reader && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -o /submit-stamp ./cmd/submit-stamp && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -o /genesis-ceremony ./cmd/genesis-ceremony && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -o /backfill ./cmd/backfill && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -o /audit ./cmd/audit && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -o /admission-authority ./cmd/admission-authority && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath -buildvcs=false -o /rebuild-projection ./cmd/rebuild-projection

# ── Runtime ────────────────────────────────────────────────────
# Pinned base (not :latest) for reproducible, auditable rebuilds.
FROM alpine:3.21

RUN --mount=type=secret,id=ca_bundle \
    if [ -s /run/secrets/ca_bundle ]; then \
      cat /run/secrets/ca_bundle >> /etc/ssl/certs/ca-certificates.crt; \
    fi; \
    apk --no-cache add ca-certificates tzdata wget \
    && adduser -D -H -u 65532 ledger \
    # Data dirs (LEDGER_WAL_PATH / TESSERA_STORAGE_DIR / TESSERA_ANTISPAM_PATH
    # defaults) and the standard config-injection root /etc/ledger, owned by the
    # non-root uid so a PVC (k8s, via fsGroup) or bind mount (compose) is writable
    # and mounted Secrets/ConfigMaps at /etc/ledger/{tls,keys,peer,bootstrap.json}
    # are readable. No config is baked in — only the empty, correctly-owned dirs.
    && mkdir -p /var/lib/baseproof/wal /var/lib/baseproof/tessera \
                /var/lib/baseproof/tessera-antispam \
                /etc/ledger/tls /etc/ledger/keys /etc/ledger/peer \
    && chown -R 65532:65532 /var/lib/baseproof /etc/ledger

WORKDIR /
COPY --from=builder /ledger /ledger
# ledger-reader is the PG-OFF read front (Phase 1, 1.3): serves horizon / inclusion
# / SMT / entry / receipt proofs reconstructed from the object-store archives when
# Postgres is unreachable. Reachable via `--entrypoint /ledger-reader`.
COPY --from=builder /ledger-reader /ledger-reader
# Ops CLIs (reachable via `--entrypoint /submit-stamp` etc.) for image-only
# seeding + bootstrap generation — the daemon stays the default entrypoint.
COPY --from=builder /submit-stamp /submit-stamp
COPY --from=builder /genesis-ceremony /genesis-ceremony
# backfill seeds VALID, INTERCONNECTED authority entries that populate the SMT
# (submit-stamp only emits commentary). Reachable via `--entrypoint /backfill`.
COPY --from=builder /backfill /backfill
# audit is the stateless light-client auditor: verifies the K-of-N cosigned
# checkpoint, then SMT proofs against the witnessed root. `--entrypoint /audit`.
COPY --from=builder /audit /audit
# admission-authority is the G-authorized publisher of the on-log admission
# keyset (schema + admission_authority_v1 snapshot). `--entrypoint /admission-authority`.
COPY --from=builder /admission-authority /admission-authority
# rebuild-projection reconstructs the Postgres projection from tiles + bytestore
# (POSIX dir, or --tiles-from-bytestore for the object-store / DR path).
# `--entrypoint /rebuild-projection`.
COPY --from=builder /rebuild-projection /rebuild-projection

EXPOSE 8080

# Liveness: the ledger serves /healthz ("ok" + 200) once it is listening. The
# listener is HTTPS iff a TLS cert+key are configured (wire.go: HTTPTLSEnabled =
# TLSCertFile != "" && TLSKeyFile != ""), plain HTTP otherwise — so probe BOTH
# schemes and pass if either returns "ok": HTTP first (the compose / e2e default),
# then HTTPS with --no-check-certificate (kubelet-style: accept the self-signed
# in-binary cert). -T 2 bounds each attempt under the 3s timeout.
#
# NOTE: Kubernetes IGNORES this directive — kubelet runs the chart's
# liveness/readiness probes, whose scheme is driven by .Values.tls.enabled in the
# Helm deployment (deployment.yaml). This HEALTHCHECK governs docker /
# docker-compose / Swarm only.
HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=5s \
    CMD wget -q -T 2 -O- http://localhost:8080/healthz 2>/dev/null | grep -q '^ok$' \
        || wget -q -T 2 --no-check-certificate -O- https://localhost:8080/healthz 2>/dev/null | grep -q '^ok$' \
        || exit 1

# Run non-root (uid 65532, the distroless "nonroot" id) — matches witness /
# auditor / aggregator, and satisfies a k8s runAsNonRoot PodSecurityContext. The
# data dirs + /etc/ledger were chown'd to 65532 above; mounted Secrets/PVCs must
# be readable/writable by this uid (k8s: fsGroup; compose: a matching mount).
USER 65532:65532

ENTRYPOINT ["/ledger"]
