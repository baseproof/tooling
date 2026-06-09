# Configuration & secret injection (ledger / witness / auditor)

The service images are **orchestrator-agnostic**: nothing environment-specific is
baked in. The *same* published image runs under `docker run`, docker-compose, or
Kubernetes — only the injected configuration differs. This document is the
contract.

## Two inputs, two mechanisms

| Input | Mechanism | docker-compose | Kubernetes |
|---|---|---|---|
| Plain config | environment variables (per-service prefix) | `environment:` | `envFrom: configMapRef` + `env:` |
| Secrets (DB DSN) | env from a secret | `environment:` (dev) | `env.valueFrom.secretKeyRef` |
| Certs / keys / bootstrap | a **file**, delivered by a **mount** | bind-mount `:ro` | Secret/ConfigMap volume |

### The standard-mount convention (certs / keys / bootstrap)

Every file input resolves in this order:

1. **Explicit path** — the `*_FILE` env var (ledger/auditor) or the flag
   (witness). Honored verbatim; a missing file fails loudly (you asked for it).
2. **Standard mount path** — if the env/flag is unset and a file exists at the
   conventional `/etc/<svc>/…` path below, it is used. **Drop a Secret at the
   standard path and it just works, with zero env wiring.**
3. **PaaS secret-file path** — else, if a file exists at the flat
   `/etc/secrets/<name>` twin (where Render-class platforms place uploaded
   secret files), it is used. Flat names are the standard leaf names; the
   ledger's outbound peer material is disambiguated as `peer-tls.crt`,
   `peer-tls.key`, `peer-ca.crt`.
4. **Unset** — feature off (byte-identical to the pre-convention default).

This is implemented in the binaries (`resolveFile` in
`cmd/ledger/env.go`, `cmd/witness/main.go`, `cmd/auditor/main.go`), so it holds
identically across every orchestrator, and is pinned by unit tests
(`env_resolve_test.go` / `resolve_test.go`).

## Standard paths

| | ledger (`/etc/ledger`) | witness (`/etc/witness`) | auditor (`/etc/auditor`) |
|---|---|---|---|
| env/flag prefix | `LEDGER_*` | `WITNESS_*` (also flags) | `AUDITOR_*` |
| server TLS cert | `tls/tls.crt` | `tls/tls.crt` | — (plain HTTP) |
| server TLS key | `tls/tls.key` | `tls/tls.key` | — |
| inbound mTLS CA | `tls/client-ca.crt` ¹ | — | — |
| signing key(s) | `keys/signer.pem`, `keys/tessera-signer.pem` | `keys/witness.pem` | `keys/gossip-signing.pem` |
| outbound peer mTLS | `peer/{ca.crt,tls.crt,tls.key}` | — | — |
| network bootstrap | `bootstrap.json` | `bootstrap.json` | `bootstrap.json` |
| amendment manifest | — | — | `amendment.json` |
| listen port | 8080 | 8081 | 8088 |
| DB (env, not a file) | `LEDGER_DATABASE_URL` | — | `AUDITOR_GOSSIP_DSN` |

¹ Inbound mTLS enforcement uses a **dedicated** `client-ca.crt` filename — not the
cert-manager-conventional `ca.crt` that ships next to a server `tls.crt`/`tls.key`
— so a stray `ca.crt` can never silently start requiring client certificates.

The standard TLS filenames (`tls.crt` / `tls.key`) match a `kubernetes.io/tls`
Secret exactly, so a cert-manager `Certificate` mounted at `/etc/<svc>/tls` works
with no further wiring.

## Kubernetes (Helm)

Each service has a chart under `services/<svc>/deploy/helm/<svc>`. The chart
renders the non-secret `*_*` env into a ConfigMap (consumed via `envFrom`) and
**mounts the operator's Secrets at the standard paths** — it never puts a cert
path in env. Example (witness):

```yaml
# values.yaml
signingKey:   { existingSecret: witness-key }       # → /etc/witness/keys/witness.pem
bootstrap:    { existingSecret: witness-bootstrap }  # → /etc/witness/bootstrap.json
serverTLS:    { existingSecret: witness-tls }        # → /etc/witness/tls/{tls.crt,tls.key}
tls:          { enabled: true }                       # flips probe scheme to HTTPS
```

```sh
kubectl -n witness create secret generic witness-key \
    --from-file=witness.pem=witness-1.pem
kubectl -n witness create secret generic witness-bootstrap \
    --from-file=bootstrap.json=network-bootstrap.json
kubectl -n witness create secret tls witness-tls --cert=tls.crt --key=tls.key
helm -n witness install w services/witness/deploy/helm/witness -f values.yaml
```

### Postgres on Kubernetes (ledger, auditor)

Both DB-backed charts support **both** database modes — pick exactly one:

- **In-cluster via Helm** — `postgresql.enabled=true` runs the bitnami
  postgresql sub-chart; the pod composes the DSN (`LEDGER_DATABASE_URL` /
  `AUDITOR_GOSSIP_DSN`) at boot from the sub-chart's Service and auth Secret,
  so the chart never has to know the password value.
- **Existing endpoint** — `externalDatabase.existingSecret` (ledger) /
  `database.existingSecret` (auditor) references a pre-created Secret holding
  the full DSN under the canonical key (rotation via external-secrets, Vault,
  etc.); or `…url` inline for dev/CI (the chart wraps it in a Secret).

Configuring none fails at `helm install` time (template-time validation), not
as a CrashLoop.

### Secret hygiene in the charts

Secret volumes mount with `defaultMode: 0440` (owner root, group-readable);
each chart's default `podSecurityContext` sets `fsGroup: 65532` so the
non-root process reads them while they stay non-world-readable. The pods do
not mount ServiceAccount tokens (`automountServiceAccountToken: false`) —
none of these services calls the Kubernetes API. The ledger chart's `fsGroup`
is also what makes fresh PVCs writable by the non-root image.

## docker-compose

Set the `*_*` env and bind-mount the cert dir at the standard path:

```yaml
services:
  witness:
    image: ghcr.io/baseproof/tooling/witness:0.1.5
    environment:
      WITNESS_ADDR: ":8081"
      WITNESS_COSIGN_SCHEME: "ecdsa"
    volumes:
      - ./.run/witness:/etc/witness:ro   # witness.pem, bootstrap.json, tls/ auto-detected
```

The ledger's `scripts/local/docker-compose.yml` is the minimal canonical example
(`LEDGER_*` env, in-process Tessera, optional `/etc/ledger` mount).

## Platform-as-a-Service (Render, Cloud Run, Heroku, Railway)

The same images run on single-container PaaS platforms with no compose and no
chart — three platform contracts are honored:

- **`PORT`** — when the service's own addr var (`LEDGER_ADDR` / `WITNESS_ADDR`
  / `AUDITOR_LISTEN_ADDR`) is unset and the platform injects `PORT` (Render
  defaults it to 10000; Cloud Run/Heroku/Railway set it too), the daemon
  listens on `:$PORT`. An explicitly set addr var always wins, so existing
  compose/k8s deployments are untouched. (`ledger-reader` honors it too.)
- **Secret files** — Render places uploaded secret files at
  `/etc/secrets/<filename>`; that path is probed automatically (resolution
  tier 3 above). Upload `signer.pem`, `tessera-signer.pem`, `bootstrap.json`
  (ledger), `witness.pem` + `bootstrap.json` (witness), `gossip-signing.pem` +
  `bootstrap.json` (auditor) and they are picked up with zero env.
- **TLS at the platform proxy** — Render terminates HTTPS at its load balancer
  and forwards plain HTTP to the container. The ledger refuses a plaintext
  listener by default, so set **`LEDGER_ALLOW_PLAINTEXT=true`** there (the
  witness serves plaintext with a warning; the auditor is HTTP-only). Do not
  mount server TLS material on such platforms.

Remaining per-service needs: the ledger wants a persistent disk mounted at
`/var/lib/baseproof` and a managed-Postgres `LEDGER_DATABASE_URL`; the auditor
wants `AUDITOR_GOSSIP_DSN`; the witness is stateless.

## Why this is agnostic

- Binaries read config from env/flags and auto-detect files at the standard
  paths — **no path, DSN, DID, or key is compiled in**.
- All five service images run as the non-root uid `65532`; the config root
  `/etc/<svc>` (and the ledger's data dirs) are pre-created and owned by it, so a
  k8s `runAsNonRoot` PodSecurityContext (and read-only root filesystem for the
  stateless services) is satisfied out of the box.
- The witness accepts `WITNESS_*` env in addition to its flags, so it injects
  through a ConfigMap/Secret exactly like the env-driven services.

JN services (network-api, aggregator) follow the identical convention — see
`clearcompass-ai/judicial-network` → `deployment/CONFIG_INJECTION.md`.
