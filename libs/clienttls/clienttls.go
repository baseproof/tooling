/*
Package clienttls is the canonical builder for a binary's single outbound
*http.Client — the one client every SDK constructor in that process receives
and threads through every peer-ledger / witness / artifact-store hop.

The v1.27.x contract for binaries built on libs/:

 1. Build EXACTLY ONE outbound *http.Client at boot via BuildFromEnv (or the
    flag-driven Flags.Client). Pass the result into every SDK / libs/*
    constructor that takes a *http.Client field.
 2. The construction call returns an explicit Posture (mTLS | Plaintext) so
    operators see at startup which mode the binary entered. There is no
    third "silent default" posture; half-configurations (cert without key)
    are startup-fatal.
 3. libs/* and the baseproof SDK itself never construct a fallback
    *http.Client. Every config struct that carries Client requires it
    non-nil; every constructor errors on nil. Consumers that need a
    plaintext client construct it explicitly (the Plaintext posture).

WHY THIS PACKAGE EXISTS

	Three binaries — the ledger (LEDGER_PEER_*), the auditor service
	(AUDITOR_PEER_*), and the JN (API_LEDGER_*) — each implemented the
	same "build one mTLS client at boot, fail closed on half-config" logic.
	Three implementations, three subtle differences, zero shared tests.
	Future networks would have made it four, then five. clienttls is the
	one place that logic lives.

ENV-VAR SCHEME

	BuildFromEnv reads four env vars under a caller-chosen prefix:

	  <prefix>CLIENT_CERT_FILE    — PEM client cert (mTLS material)
	  <prefix>CLIENT_KEY_FILE     — PEM private key matching the cert
	  <prefix>CA_FILE             — optional PEM CA pinning peer server certs
	                                (empty → system roots)
	  <prefix>HTTP_TIMEOUT        — optional Go-duration string
	                                (empty → DefaultTimeout)

	Example prefixes:
	  "LEDGER_PEER_"     — the ledger binary's outbound to peer ledgers
	  "AUDITOR_PEER_"    — the auditor's outbound to peer ledgers + did:web
	  "API_LEDGER_"      — the JN network-api's outbound to the ledger

	The trailing underscore is part of the prefix the caller supplies.

POSTURE LOGGING

	Every successful BuildFromEnv emits exactly one log line at startup
	("posture = MTLS" or "posture = PLAINTEXT") so operators can grep for
	the binary's actual transport mode without reading code. Silent
	demotion is impossible by construction.
*/
package clienttls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	sdklog "github.com/baseproof/baseproof/log"
)

// DefaultTimeout applies when the caller does not supply <prefix>HTTP_TIMEOUT
// (BuildFromEnv) or a Timeout on Flags.Client. 10s matches the prior pattern
// across the ledger, auditor, and JN binaries' hand-rolled clients.
const DefaultTimeout = 10 * time.Second

// Posture is the categorical transport mode the binary booted into. Returned
// from BuildFromEnv so callers can log + assert (some deployments are
// configured to refuse Plaintext at startup; the categorical type makes that
// check a single comparison instead of a CertFile == "" string check).
type Posture int

const (
	// PostureUnset is the zero value — never returned from a successful
	// build. Construction either succeeds with MTLS / Plaintext or
	// returns an error.
	PostureUnset Posture = iota

	// PostureMTLS means cert + key (and optionally CA) were loaded
	// successfully; the returned *http.Client presents the client cert
	// on every connection and verifies peer servers against the
	// configured CA (or the system roots).
	PostureMTLS

	// PostureServerVerify means NO client cert is presented but the peer
	// server's certificate IS verified against a pinned CA (the
	// <prefix>CA_FILE bundle). This is the open-HTTPS / zero-trust posture:
	// the binary cryptographically authenticates WHO the server is, while
	// presenting no client cert — the ledger gates writes on the in-body
	// signature, not transport identity. Reached two ways: explicitly via
	// <prefix>ALLOW_SELF_SIGNED=1 (CA required, fail-closed if missing — the
	// auditable "I trust this self-signed/private CA" declaration), or
	// implicitly when only a CA (no client cert) is configured. Verification
	// is ALWAYS on; this is never InsecureSkipVerify.
	PostureServerVerify

	// PosturePlaintext means cert + key were both unset AND no CA was
	// configured; the returned *http.Client is sdklog.DefaultClient(timeout,
	// nil) — TLS 1.2+ verifying against the SYSTEM roots, no client cert
	// presented. Explicit because v1.27.x forbids silent demotion: the caller
	// asked for plaintext (by leaving the env vars unset) and got plaintext.
	PosturePlaintext
)

// String returns the all-caps name suitable for log lines.
func (p Posture) String() string {
	switch p {
	case PostureMTLS:
		return "MTLS"
	case PostureServerVerify:
		return "SERVER-VERIFY"
	case PosturePlaintext:
		return "PLAINTEXT"
	default:
		return "UNSET"
	}
}

// Flags is the flag.FlagSet binding for binaries that prefer CLI flags over
// env vars (most CLI tools). Bind registers `-client-cert`, `-client-key`,
// `-ca-cert` on the supplied flag.FlagSet. The two binaries that use this
// today are the ledger's CLI tools (cmd/{audit,backfill,admission-authority,
// submit-stamp}); the JN's judicial-cli SHOULD use this once it adopts mTLS.
//
// For long-running binaries that read env at boot, prefer BuildFromEnv.
type Flags struct {
	// CertFile is the PEM client certificate. Required to enable mTLS.
	CertFile string

	// KeyFile is the PEM private key matching CertFile. Required.
	KeyFile string

	// CAFile is the PEM CA bundle for verifying peer servers' certs.
	// Optional — empty falls back to system roots.
	CAFile string

	// RequireMTLS makes a would-be Plaintext posture (cert+key both unset) a
	// startup-fatal ErrPlaintextRefused instead of an allowed PosturePlaintext.
	// Secure-by-default callers — the ledger edge (AUDITOR_PEER_ / API_LEDGER_ /
	// LEDGER_PEER_) and the CLI tools — set it; a proxy-terminated or loopback-dev
	// deployment leaves it off. Default false keeps the library non-breaking: the
	// policy (when to require) lives in the consumer, not here.
	RequireMTLS bool

	// AllowSelfSigned is the explicit opt-in for reaching a peer that presents a
	// privately-signed / self-signed SERVER cert over open HTTPS without mTLS.
	// When set it builds a PostureServerVerify client that pins CAFile (which
	// becomes REQUIRED — a self-signed cert MUST be verified against a known CA;
	// missing CAFile is the startup-fatal ErrSelfSignedNoCA) and presents no
	// client cert. It overrides RequireMTLS for the no-client-cert case — the
	// operator has DECLARED the open posture intentionally and auditably. It is
	// never InsecureSkipVerify: verification stays on, pinned to CAFile.
	AllowSelfSigned bool
}

// Bind registers the three flags onto fs. Flag names match the
// LEDGER_PEER_* / AUDITOR_PEER_* env-var stems so operators see one
// consistent vocabulary across the network.
func (f *Flags) Bind(fs *flag.FlagSet) {
	fs.StringVar(&f.CertFile, "client-cert", "",
		"PEM client certificate for mTLS (requires -client-key)")
	fs.StringVar(&f.KeyFile, "client-key", "",
		"PEM client private key for mTLS (requires -client-cert)")
	fs.StringVar(&f.CAFile, "ca-cert", "",
		"PEM CA bundle for verifying peer server certs (optional; defaults to system roots)")
	fs.BoolVar(&f.RequireMTLS, "require-mtls", false,
		"fail closed if no client cert is configured (refuse plaintext) — secure-by-default edge clients set this")
	fs.BoolVar(&f.AllowSelfSigned, "allow-self-signed", false,
		"verify the server against -ca-cert with no client cert (open HTTPS to a privately-signed ledger); requires -ca-cert")
}

// Configured reports whether both cert and key are set — the minimum for an
// mTLS handshake. A non-empty CAFile alone does NOT enable mTLS (the client
// cannot authenticate without a key).
func (f *Flags) Configured() bool {
	return f.CertFile != "" && f.KeyFile != ""
}

// Client returns the *http.Client + Posture pair for the configured flags.
// Failure modes (each returns a non-nil error; the caller MUST surface it
// rather than silently fall back to plaintext):
//   - CertFile set without KeyFile (or vice versa) → ErrHalfConfigured
//   - Cert/key files unreadable or unparseable → wrapped from the SDK loader
//   - CAFile set but empty after parse → wrapped from the SDK loader
//
// When both CertFile and KeyFile are empty the call returns
// PosturePlaintext + sdklog.DefaultClient(timeout, nil) — explicit plaintext,
// loggable.
//
// timeout <= 0 falls back to DefaultTimeout.
func (f *Flags) Client(timeout time.Duration) (*http.Client, Posture, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	certSet := f.CertFile != ""
	keySet := f.KeyFile != ""
	if certSet != keySet {
		return nil, PostureUnset, fmt.Errorf("%w: cert=%q key=%q (must both be set or both unset)",
			ErrHalfConfigured, f.CertFile, f.KeyFile)
	}
	// AllowSelfSigned asserts "the peer's server cert is self-signed/private";
	// that assertion is meaningless — and unsafe — without a CA to pin it to, so
	// a missing CAFile is startup-fatal regardless of client-cert state. This is
	// the guarantee that the posture can never silently degrade to system-roots
	// or skip-verify.
	if f.AllowSelfSigned && f.CAFile == "" {
		return nil, PostureUnset, ErrSelfSignedNoCA
	}
	if !certSet {
		// No client cert. AllowSelfSigned (CA already guaranteed above) pins the
		// CA and verifies the server — open HTTPS, no client cert — overriding
		// RequireMTLS because the operator declared it explicitly.
		if f.AllowSelfSigned {
			cfg, err := serverVerifyTLSConfig(f.CAFile)
			if err != nil {
				return nil, PostureUnset, err
			}
			return sdklog.DefaultClient(timeout, cfg), PostureServerVerify, nil
		}
		if f.RequireMTLS {
			return nil, PostureUnset, ErrPlaintextRefused
		}
		// Honor an explicitly-provided CA even without a client cert: pinning a
		// CA only ADDS a trusted root, never weakens verification. Absent a CA,
		// fall back to the system roots (PosturePlaintext).
		if f.CAFile != "" {
			cfg, err := serverVerifyTLSConfig(f.CAFile)
			if err != nil {
				return nil, PostureUnset, err
			}
			return sdklog.DefaultClient(timeout, cfg), PostureServerVerify, nil
		}
		return sdklog.DefaultClient(timeout, nil), PosturePlaintext, nil
	}
	tlsCfg, err := sdklog.LoadClientTLSConfig(sdklog.ClientTLSConfig{
		ClientCertFile: f.CertFile,
		ClientKeyFile:  f.KeyFile,
		RootCAFile:     f.CAFile,
	})
	if err != nil {
		return nil, PostureUnset, fmt.Errorf("clienttls: load TLS material: %w", err)
	}
	return sdklog.DefaultClient(timeout, tlsCfg), PostureMTLS, nil
}

// serverVerifyTLSConfig builds a server-verify-only *tls.Config that pins caFile
// and presents NO client cert (open HTTPS). It is the tooling-owned
// counterpart to sdklog.LoadClientTLSConfig (which requires a client cert): the
// SDK's DefaultClient/DefaultTransport accept any *tls.Config, so the env policy
// — "verify a self-signed/private CA without mTLS" — lives here, not in the SDK.
// InsecureSkipVerify is never set.
func serverVerifyTLSConfig(caFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("clienttls: read CA %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("clienttls: CA %q contains no parseable certificates", caFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

// ErrHalfConfigured is returned when one of {CertFile, KeyFile} is set
// without the other. Half-configuration is unambiguously an operator error
// — the binary refuses to start rather than guess what was intended.
var ErrHalfConfigured = errors.New("clienttls: cert and key must both be set or both unset")

// ErrPlaintextRefused is returned when RequireMTLS is set but no client cert+key
// were configured. Secure-by-default callers fail closed rather than dial a peer
// in the clear. Set <prefix>CLIENT_CERT_FILE + CLIENT_KEY_FILE to satisfy it, or
// leave RequireMTLS off (proxy-terminated / loopback-dev).
var ErrPlaintextRefused = errors.New("clienttls: mTLS required but no client cert configured")

// ErrSelfSignedNoCA is returned when AllowSelfSigned (<prefix>ALLOW_SELF_SIGNED)
// is set but no CAFile (<prefix>CA_FILE) is configured. A self-signed / private
// server cert MUST be pinned to a known CA — the library refuses to skip
// verification, so the omission is startup-fatal rather than a silent demotion.
var ErrSelfSignedNoCA = errors.New("clienttls: ALLOW_SELF_SIGNED set but no CA_FILE configured (a self-signed server cert must be pinned to a CA; verification is never skipped)")

// envTruthy reports whether an env value means "on" (1/true/yes/on, any case).
func envTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// BuildFromEnv is the env-driven cousin of Flags.Client — the form long-
// running daemons use at boot. Reads four env vars under the given prefix
// (see the package docstring for the scheme) and returns the resulting
// client + Posture, logging the posture explicitly on success.
//
// On any failure (half-config, unreadable cert/key/CA, unparseable timeout),
// returns (nil, PostureUnset, err). Callers MUST surface the error — there is
// no silent fallback.
//
// prefix should end with an underscore, e.g. "LEDGER_PEER_". The function
// reads exactly:
//
//	<prefix>CLIENT_CERT_FILE
//	<prefix>CLIENT_KEY_FILE
//	<prefix>CA_FILE
//	<prefix>HTTP_TIMEOUT  (optional; Go duration string)
func BuildFromEnv(prefix string, logger *slog.Logger) (*http.Client, Posture, error) {
	return buildFromEnv(prefix, logger, envTruthy(os.Getenv(prefix+"REQUIRE_MTLS")))
}

// BuildFromEnvRequire is BuildFromEnv for the secure-by-default EDGE: a plaintext
// posture (no client cert) is startup-fatal UNLESS <prefix>ALLOW_PLAINTEXT is set.
// Edge services that reach a peer over the mTLS edge (auditor→ledger, JN→ledger)
// use this so a missing client cert fails closed at boot instead of dialing in the
// clear. <prefix>ALLOW_PLAINTEXT=1 is the opt-out (TLS-terminating proxy /
// loopback-dev).
func BuildFromEnvRequire(prefix string, logger *slog.Logger) (*http.Client, Posture, error) {
	return buildFromEnv(prefix, logger, !envTruthy(os.Getenv(prefix+"ALLOW_PLAINTEXT")))
}

func buildFromEnv(prefix string, logger *slog.Logger, requireMTLS bool) (*http.Client, Posture, error) {
	if logger == nil {
		logger = slog.Default()
	}
	f := Flags{
		CertFile:        os.Getenv(prefix + "CLIENT_CERT_FILE"),
		KeyFile:         os.Getenv(prefix + "CLIENT_KEY_FILE"),
		CAFile:          os.Getenv(prefix + "CA_FILE"),
		RequireMTLS:     requireMTLS,
		AllowSelfSigned: envTruthy(os.Getenv(prefix + "ALLOW_SELF_SIGNED")),
	}
	timeout := DefaultTimeout
	if raw := os.Getenv(prefix + "HTTP_TIMEOUT"); raw != "" {
		t, err := time.ParseDuration(raw)
		if err != nil {
			return nil, PostureUnset, fmt.Errorf("clienttls: parse %sHTTP_TIMEOUT=%q: %w",
				prefix, raw, err)
		}
		if t <= 0 {
			return nil, PostureUnset, fmt.Errorf("clienttls: %sHTTP_TIMEOUT must be positive (got %s)",
				prefix, raw)
		}
		timeout = t
	}
	client, posture, err := f.Client(timeout)
	if err != nil {
		return nil, PostureUnset, fmt.Errorf("clienttls: env-prefix %q: %w", prefix, err)
	}
	switch posture {
	case PostureMTLS:
		logger.Info("clienttls: outbound posture = MTLS",
			"prefix", prefix,
			"client_cert", f.CertFile,
			"ca_file", f.CAFile,
			"timeout", timeout)
	case PostureServerVerify:
		logger.Info("clienttls: outbound posture = SERVER-VERIFY "+
			"(TLS 1.3, self-signed/private CA pinned, no client cert)",
			"prefix", prefix,
			"ca_file", f.CAFile,
			"allow_self_signed", f.AllowSelfSigned,
			"timeout", timeout)
	case PosturePlaintext:
		logger.Info("clienttls: outbound posture = PLAINTEXT (TLS 1.2+, server-verify-only); "+
			"set "+prefix+"CLIENT_CERT_FILE + "+prefix+"CLIENT_KEY_FILE for mTLS",
			"prefix", prefix,
			"timeout", timeout)
	}
	return client, posture, nil
}
