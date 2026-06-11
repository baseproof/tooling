/*
FILE PATH: main.go

DESCRIPTION:

	A minimal standalone witness HTTP server. Loads a single witness
	EC private key (PEM) + the network bootstrap doc and serves
	POST /v1/cosign on the configured port. Designed for
	multi-instance deployments where a writer ledger needs N external
	witnesses to drive a real K-of-N quorum without spinning up N
	full ledgers.

USAGE:

	./bin/standalone-witness \
	    -addr :8081 \
	    -key-file .run/witnesses/witness-1.pem \
	    -bootstrap .run/network-bootstrap.json

WHAT IT IS NOT:

	This is NOT a full ledger, and it is NOT a stateful history
	authority. It does NOT participate in gossip, hold a database,
	write tiles, run a builder loop, or accept admissions. It is a
	BLIND NOTARY: it lends its cryptographic weight (1-of-N) attesting
	that a tree head was presented at a moment in time. Rollback/fork
	DETECTION is owned by downstream auditors (the judicial network)
	via the gossip feed + EquivocationFinding — not by this daemon.
	See internal/serve for the full rationale.

PRODUCTION SURFACE:

  - TLS: -tls-cert/-tls-key serve HTTPS; omit both for plaintext
    (only behind a TLS-terminating proxy).
  - Metrics: Prometheus at GET /metrics (same listener).
  - Liveness: GET /healthz.
  - Rate limit: -max-rps/-burst (DoS protection; off by default).
  - Server timeouts bound slowloris / idle-connection exhaustion.
  - Graceful shutdown: SIGINT/SIGTERM → 5s drain.
*/
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdklog "github.com/baseproof/baseproof/log"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/tracing"
	"github.com/baseproof/tooling/services/witness/internal/blskey"
	"github.com/baseproof/tooling/services/witness/internal/obs"
	"github.com/baseproof/tooling/services/witness/internal/serve"
	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

// version is stamped at build time via
// -ldflags "-X main.version=<tag>". "dev" for un-stamped builds.
var version = "dev"

// envOr returns the env var value, or fallback when unset/blank. It makes every
// flag below ALSO settable by a WITNESS_* env var, so a k8s ConfigMap/Secret
// (envFrom) or a docker-compose `environment:` configures the witness identically
// to the CLI — the same image runs anywhere. An explicit flag still wins, because
// the flag default IS the env value (a passed flag overrides it).
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// resolveFile implements the standard cert/key/bootstrap injection convention:
// an explicit value (flag or WITNESS_* env) wins; otherwise the first existing
// file among the conventional candidates is used, in order: the standard mount
// path (/etc/witness/… — k8s Secret volume / compose bind mount), then the PaaS
// secret-file path (/etc/secrets/<name>, where Render-class platforms place
// uploaded secret files). No candidate ⇒ "" (byte-identical to the prior
// behavior). The stats are boot-only.
func resolveFile(explicit string, candidates ...string) string {
	if explicit != "" {
		return explicit
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// portAddrOr returns ":$PORT" when the platform injects PORT (the Render /
// Cloud Run / Heroku contract), else the baked fallback. Consulted only after
// -addr and WITNESS_ADDR, so it never overrides an operator-set address.
func portAddrOr(fallback string) string {
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		return ":" + p
	}
	return fallback
}

func main() {
	addr := flag.String("addr", envOr("WITNESS_ADDR", portAddrOr(":8081")),
		"HTTP listen address (env: WITNESS_ADDR; a platform-injected PORT is honored when both are unset)")
	keyFile := flag.String("key-file", os.Getenv("WITNESS_KEY_FILE"),
		"path to the witness private key in PEM form (env: WITNESS_KEY_FILE; "+
			"default /etc/witness/keys/witness.pem if mounted). secp256k1 "+
			"(witkey) for -cosign-scheme=ecdsa; BLS12-381 (blskey) for "+
			"-cosign-scheme=bls — the PEM type is checked, so a key of the "+
			"wrong scheme fails loudly at boot.")
	cosignScheme := flag.String("cosign-scheme", envOr("WITNESS_COSIGN_SCHEME", "ecdsa"),
		"witness cosignature scheme (env: WITNESS_COSIGN_SCHEME): ecdsa (secp256k1, the default; key is a "+
			"genesis did:key in the bootstrap) or bls (BLS12-381 G2; the witness "+
			"is NOT a genesis did:key — it joins the verifying set on-log via the "+
			"WitnessEndpointDeclaration emitted at boot, see -public-url).")
	publicURL := flag.String("public-url", os.Getenv("WITNESS_PUBLIC_URL"),
		"the witness's externally-reachable base https:// URL (env: WITNESS_PUBLIC_URL). Used only with "+
			"-cosign-scheme=bls to build the on-log WitnessEndpointDeclaration "+
			"(scheme/key/PoP) the daemon logs at boot for submission; consumers "+
			"resolve this witness's BLS key by it. Ignored for ecdsa.")
	bootstrapFile := flag.String("bootstrap", os.Getenv("WITNESS_BOOTSTRAP_FILE"),
		"path to the network BootstrapDocument JSON (env: WITNESS_BOOTSTRAP_FILE; "+
			"default /etc/witness/bootstrap.json if mounted), for NetworkID")
	cosignPurposes := flag.String("cosign-purposes", envOr("WITNESS_COSIGN_PURPOSES", "tree-head"),
		"comma-separated cosign purposes this witness will sign (env: WITNESS_COSIGN_PURPOSES): "+
			"tree-head (default), rotation, escrow-override. Tree-head-only is "+
			"the least-privilege default; widen to e.g. 'tree-head,rotation' only "+
			"if this witness contributes its own witness-set rotation cosignature "+
			"over /v1/cosign (in this ecosystem rotation is gossip-collected, so "+
			"the default is correct).")
	tlsCert := flag.String("tls-cert", os.Getenv("WITNESS_TLS_CERT_FILE"),
		"path to the TLS certificate, PEM (env: WITNESS_TLS_CERT_FILE; default "+
			"/etc/witness/tls/tls.crt if mounted); enables HTTPS when set with -tls-key")
	tlsKey := flag.String("tls-key", os.Getenv("WITNESS_TLS_KEY_FILE"),
		"path to the TLS private key, PEM (env: WITNESS_TLS_KEY_FILE; default "+
			"/etc/witness/tls/tls.key if mounted); required with -tls-cert")
	maxRPS := flag.Float64("max-rps", 0,
		"token-bucket rate limit for /v1/cosign in requests/sec; 0 disables")
	burst := flag.Int("burst", 0,
		"token-bucket burst for -max-rps (defaults to ceil(max-rps) when unset)")
	showVersion := flag.Bool("version", false, "print version and exit")
	otlpEndpoint := flag.String("otlp-traces-endpoint", os.Getenv("WITNESS_OTLP_TRACES_ENDPOINT"),
		"OpenTelemetry traces endpoint: \"\"=off, \"stdout\", or host:port for OTLP HTTP")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// Standard-path fallback (after parse, so an explicit flag/env still wins):
	// a Secret/volume mounted at the conventional /etc/witness/… path — or a
	// Render-class secret file at /etc/secrets/<name> — is picked up with zero
	// flags/env: the "drop the certs and it just works" convention.
	*keyFile = resolveFile(*keyFile, "/etc/witness/keys/witness.pem", "/etc/secrets/witness.pem")
	*bootstrapFile = resolveFile(*bootstrapFile, "/etc/witness/bootstrap.json", "/etc/secrets/bootstrap.json")
	*tlsCert = resolveFile(*tlsCert, "/etc/witness/tls/tls.crt", "/etc/secrets/tls.crt")
	*tlsKey = resolveFile(*tlsKey, "/etc/witness/tls/tls.key", "/etc/secrets/tls.key")

	if *keyFile == "" || *bootstrapFile == "" {
		fmt.Fprintln(os.Stderr, "standalone-witness: -key-file and -bootstrap are required")
		flag.Usage()
		os.Exit(2)
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(os.Stderr, "standalone-witness: -tls-cert and -tls-key must be set together")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Tracing: installs the global W3C propagator (so the ledger's cosign→witness
	// hop continues the same trace) and, when an endpoint is set, exports the
	// witness's own SERVER span. Always returns a usable shutdown.
	traceShutdown, err := tracing.Setup(tracing.Config{
		ServiceName:    "witness",
		ServiceVersion: version,
		Endpoint:       *otlpEndpoint,
	})
	if err != nil {
		logger.Error("tracing setup", "error", err)
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = traceShutdown(ctx)
	}()

	doc, err := loadBootstrap(*bootstrapFile)
	if err != nil {
		logger.Error("load bootstrap", "path", *bootstrapFile, "error", err)
		os.Exit(1)
	}
	identity, err := doc.IDs()
	if err != nil {
		logger.Error("derive network identity from bootstrap", "error", err)
		os.Exit(1)
	}

	allowedPurposes, err := serve.ParseAllowedPurposes(*cosignPurposes)
	if err != nil {
		logger.Error("parse -cosign-purposes", "error", err)
		os.Exit(2)
	}

	cfg := serve.Config{
		NetworkID:       identity.NetworkID,
		AllowedPurposes: allowedPurposes,
		Logger:          logger,
	}

	handler, err := buildCosignHandler(*cosignScheme, *keyFile, *publicURL, cfg, logger)
	if err != nil {
		logger.Error("build cosign handler", "scheme", *cosignScheme, "error", err)
		os.Exit(1)
	}

	// Observability + DoS protection wrap the cosign handler.
	// Metrics is OUTERMOST so rate-limited 429s are still counted.
	metrics := obs.NewMetrics(version)
	limiter := obs.NewLimiter(*maxRPS, effectiveBurst(*maxRPS, *burst))
	cosignHandler := metrics.Instrument("v1_cosign", obs.RateLimit(limiter, handler))

	mux := http.NewServeMux()
	mux.Handle("POST /v1/cosign", cosignHandler)
	mux.Handle("GET /metrics", metrics.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr: *addr,
		// OTel SERVER span (outermost): extracts the caller's traceparent so the
		// cosign request continues the ledger's checkpoint trace.
		Handler:           sdklog.NewOTelHandler(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	tlsEnabled := *tlsCert != ""
	logger.Info("standalone-witness ready",
		"version", version,
		"addr", *addr,
		"tls", tlsEnabled,
		"network_did", identity.DID,
		"key_file", *keyFile,
		"cosign_scheme", *cosignScheme,
		"cosign_purposes", *cosignPurposes,
		"max_rps", *maxRPS,
	)
	if !tlsEnabled {
		logger.Warn("serving plaintext HTTP — terminate TLS at a proxy or set -tls-cert/-tls-key")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		var serveErr error
		if tlsEnabled {
			serveErr = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			serveErr = srv.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("standalone-witness stopped")
}

// effectiveBurst defaults the token-bucket burst to ceil(rps) when
// the operator leaves -burst unset, so a steady rps is allowed
// without a one-token-at-a-time stutter.
func effectiveBurst(rps float64, burst int) int {
	if burst > 0 {
		return burst
	}
	if rps <= 0 {
		return 0
	}
	b := int(rps)
	if float64(b) < rps {
		b++
	}
	if b < 1 {
		b = 1
	}
	return b
}

// buildCosignHandler loads the witness signing key for the selected cosign
// scheme and constructs the /v1/cosign handler.
//
//   - ecdsa (default): the secp256k1 witkey PEM → serve.Build (the witness is a
//     genesis did:key in the bootstrap; consumers resolve it via KeysFromDIDs).
//   - bls: the BLS12-381 blskey PEM → cosign.NewBLSWitnessSigner via
//     serve.BuildSigner. A BLS key cannot be a did:key, so the witness
//     SELF-DECLARES on-log: it emits a WitnessEndpointDeclaration (PubKeyID +
//     scheme/key/PoP) for submission as BP-ENTRY-WITNESS-ENDPOINT-V1, by which
//     consumers resolve its key (network.ResolveWitnessKeyAt). -public-url
//     supplies the declaration's endpoint.
func buildCosignHandler(scheme, keyFile, publicURL string, cfg serve.Config, logger *slog.Logger) (http.Handler, error) {
	switch scheme {
	case "ecdsa":
		priv, err := loadECPrivateKey(keyFile)
		if err != nil {
			return nil, fmt.Errorf("load secp256k1 witness key %q: %w", keyFile, err)
		}
		cfg.WitnessKey = priv
		return serve.Build(cfg)
	case "bls":
		priv, err := blskey.LoadPEM(keyFile)
		if err != nil {
			return nil, fmt.Errorf("load BLS witness key %q: %w", keyFile, err)
		}
		handler, err := serve.BuildSigner(cosign.NewBLSWitnessSigner(priv), cfg)
		if err != nil {
			return nil, err
		}
		id := blskey.PubKeyID(blskey.PubKey(priv))
		idHex := hex.EncodeToString(id[:])
		if publicURL == "" {
			logger.Warn("BLS witness: set -public-url to emit the on-log WitnessEndpointDeclaration "+
				"(consumers resolve this witness by its PubKeyID)", "pub_key_id", idHex)
		} else if decl, derr := blskey.EndpointDeclaration(priv, map[string]string{"BaseproofWitness": publicURL}); derr != nil {
			logger.Warn("BLS witness: -public-url did not yield a valid declaration",
				"pub_key_id", idHex, "public_url", publicURL, "error", derr)
		} else if encoded, eerr := network.EncodeWitnessEndpointDeclarationPayload(decl); eerr != nil {
			logger.Warn("BLS witness: encode declaration", "pub_key_id", idHex, "error", eerr)
		} else {
			logger.Info("BLS witness on-log declaration — submit as BP-ENTRY-WITNESS-ENDPOINT-V1 "+
				"so the network resolves this witness's key", "pub_key_id", idHex, "declaration", string(encoded))
		}
		return handler, nil
	default:
		return nil, fmt.Errorf("unknown -cosign-scheme %q (valid: ecdsa, bls)", scheme)
	}
}

// loadECPrivateKey loads the witness's secp256k1 signing key (witkey PEM).
// secp256k1 is the Baseproof witness/cosign curve; a legacy P-256 "EC PRIVATE
// KEY" file fails the witkey type check loudly rather than cosigning on the
// wrong curve.
func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	return witkey.LoadPEM(path)
}

func loadBootstrap(path string) (network.BootstrapDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return network.BootstrapDocument{}, fmt.Errorf("read: %w", err)
	}
	var probe network.BootstrapDocument
	if err := json.Unmarshal(data, &probe); err != nil {
		return network.BootstrapDocument{}, fmt.Errorf("unmarshal: %w", err)
	}
	ids, err := probe.IDs()
	if err != nil {
		return network.BootstrapDocument{}, fmt.Errorf("derive network identity: %w", err)
	}
	// #75 Phase B — fail-closed first contact with the witness's OWN mounted
	// constitution: self-pinned to the NetworkID it derives and admitted through
	// the same door every client uses (strict decode, canonical-subset hash, the
	// genesis ceremony whenever the policy requires it). A witness must refuse
	// to cosign FOR a require network whose constitution it cannot verify.
	verified, err := network.LoadVerifiedBootstrap(data, [32]byte(ids.NetworkID))
	if err != nil {
		return network.BootstrapDocument{}, fmt.Errorf(
			"first-contact verification failed (stripped/incomplete genesis ceremony?): %w", err)
	}
	return *verified, nil
}
