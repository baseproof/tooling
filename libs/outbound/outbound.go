// Package outbound is the canonical "one outbound *http.Client per binary"
// hoist. It's a thin typed wrapper around libs/clienttls — the value it
// adds is not behaviour, it's a NAME the binary can declare exactly once
// at boot and thread into every libs/* and SDK constructor that takes a
// *http.Client.
//
// # Why this package exists
//
// The v1.27.x contract is "every binary builds ONE outbound client at
// boot via clienttls.BuildFromEnv (or equivalent that returns an explicit
// Posture), then threads that client into every outbound SDK constructor;
// libs/* itself never silently constructs a fallback *http.Client".
//
// The recurring failure mode is binary main.go doing:
//
//	httpClient := &http.Client{Timeout: 10 * time.Second}
//
// — inline, untyped, posture-blind, and at one of N call sites instead
// of ONE. That construction sidesteps every mTLS posture decision the
// operator made; it's the exact "silent plaintext" anti-pattern the
// SDK removed in v1.25.0+v1.27.0 from its own constructors.
//
// The type outbound.Client lets a CI grep distinguish "the binary
// hoisted its outbound client (good)" from "the binary built a raw
// &http.Client{...} (bad)". scripts/client-contract.sh greps every
// service binary's main.go for the latter and fails the build.
//
// # What it is not
//
// This package owns NO transport logic; everything routes through
// libs/clienttls. The wrapper exists purely so the binary's outbound
// client has a DECLARED, GREP-ABLE type. If you only need the
// *http.Client itself (no posture log, no CI gate), just call
// clienttls.BuildFromEnv directly — the SDK constructors accept
// *http.Client unchanged.
//
// # Usage
//
//	out, err := outbound.HoistFromEnv("AUDITOR_PEER_", logger)
//	if err != nil { return err }
//	logger.Info("outbound posture", "posture", out.Posture)
//	// Thread out.Client (the embedded *http.Client) into every outbound
//	// SDK constructor:
//	puller, _ := peers.NewPeerPuller(peers.PeerPullerConfig{
//	    HTTPClient: out.Client,
//	    // ...
//	})
package outbound

import (
	"log/slog"
	"net/http"

	"github.com/baseproof/tooling/libs/clienttls"
)

// Client is the binary's hoisted outbound *http.Client paired with the
// posture (mTLS / plaintext) it was constructed under. The *http.Client is
// embedded so callers can use the wrapper directly for one-off Do/Get
// calls; the field name Client also lets callers pass the inner pointer to
// SDK constructors that take an *http.Client.
//
// The wrapper exists purely to give the binary's outbound client a
// declared, grep-able type — scripts/client-contract.sh treats a raw
// &http.Client{...} in a service binary main.go as the anti-pattern to
// catch.
type Client struct {
	*http.Client
	Posture clienttls.Posture
}

// HoistFromEnv is the canonical "build the binary's outbound client" call.
// Every binary should call this exactly once at boot, then thread the
// returned Client (or its embedded *http.Client) into every libs/* and SDK
// constructor that takes a *http.Client.
//
// prefix is the env-var prefix passed to clienttls.BuildFromEnv (e.g.
// "AUDITOR_PEER_", "LEDGER_PEER_", "API_LEDGER_"). The env scheme is
// documented on clienttls.BuildFromEnv.
//
// Returns:
//   - mTLS configured (both cert+key set): Client with Posture=MTLS
//   - plaintext (neither cert nor key set): Client with Posture=Plaintext
//   - half-configured (cert XOR key): error (no silent demotion)
//   - bad cert/key paths: error wrapping clienttls.LoadClientTLSConfig
//
// On success, clienttls logs the posture exactly once at construction.
func HoistFromEnv(prefix string, logger *slog.Logger) (*Client, error) {
	hc, posture, err := clienttls.BuildFromEnv(prefix, logger)
	if err != nil {
		return nil, err
	}
	return &Client{Client: hc, Posture: posture}, nil
}

// HoistFromEnvRequire is HoistFromEnv for the secure-by-default EDGE: it requires
// mTLS (a plaintext posture is startup-fatal) unless <prefix>ALLOW_PLAINTEXT is
// set. Edge services that reach a peer over the mTLS edge (auditor→ledger,
// JN→ledger) use this so a missing client cert fails closed at boot rather than
// dialing in the clear. See clienttls.BuildFromEnvRequire.
func HoistFromEnvRequire(prefix string, logger *slog.Logger) (*Client, error) {
	hc, posture, err := clienttls.BuildFromEnvRequire(prefix, logger)
	if err != nil {
		return nil, err
	}
	return &Client{Client: hc, Posture: posture}, nil
}
