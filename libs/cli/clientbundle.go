// Package cli is the unified baseproof client: it submits entries to a network,
// generates + verifies proofs, and drives the loadgen engine — all bound to ONE
// network by a client bundle. The baseproof-cli binary is a thin dispatcher over
// this package; the e2e harness imports the same package (and libs/loadgen) so
// what CI exercises is exactly what an operator runs.
package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/baseproof/tooling/libs/clienttls"
	"github.com/baseproof/tooling/libs/messages"
)

// ClientBundleFormat tags the artifact so a reader rejects an unknown vintage.
const ClientBundleFormat = "baseproof-client-bundle/v1"

// Transport is the client's TLS posture for reaching the network's ledger. It
// maps 1:1 onto clienttls.Flags so the CLI shares the proven edge-client wiring
// (open-HTTPS server-verify, mTLS, or pinned-CA) instead of re-hand-rolling it.
type Transport struct {
	CAFile          string `json:"ca_file,omitempty"`
	ClientCertFile  string `json:"client_cert_file,omitempty"`
	ClientKeyFile   string `json:"client_key_file,omitempty"`
	AllowSelfSigned bool   `json:"allow_self_signed,omitempty"`
}

// Admission carries the network's write-admission posture for the submit/load
// paths: Mode B PoW (the default) needs the epoch window; Mode A uses a credit
// token passed per-invocation.
type Admission struct {
	EpochWindowSec uint64 `json:"epoch_window_sec,omitempty"`
}

// ClientBundle is the per-network artifact that binds the unified CLI to ONE
// network: where the ledger is (Endpoint), who to trust (NetworkID + QuorumK +
// the bootstrap hash, all fetched + verified at use, not embedded), which log to
// write (LogDID), and how to reach it (Transport). It is small, static and
// authored-once — the "name the network, act" handle, distributed per network.
type ClientBundle struct {
	Format        string    `json:"format"`
	NetworkID     string    `json:"network_id"`                        // 64-hex
	Endpoint      string    `json:"endpoint"`                          // ledger base URL (reads + ungated writes)
	LogDID        string    `json:"log_did"`                           // destination log (submit/load)
	QuorumK       int       `json:"quorum_k"`                          // witness quorum (proof)
	BootstrapHash string    `json:"bootstrap_document_hash,omitempty"` // 64-hex genesis pin
	Transport     Transport `json:"transport"`
	Admission     Admission `json:"admission,omitempty"`

	// WriteEndpoint is the JN enforcer's base URL for a GATED network. When set,
	// `submit` writes THROUGH the JN — POST <WriteEndpoint>/v1/entries/submit over
	// the Transport mTLS — instead of direct to the ledger's /v1/entries. The JN
	// runs its admission gate (cosignature + prerequisite policy) and mints the
	// gate-5 WriteAuthorization the ledger requires; a direct write to a gated
	// ledger is refused. READS (proof/info) always use Endpoint (the ledger). Empty
	// ⇒ the ungated posture: writes go direct to the ledger. The CLI stays
	// domain-agnostic — it signs (optionally with cosigners) and posts; the JN owns
	// the domain policy.
	WriteEndpoint string `json:"write_endpoint,omitempty"`

	// Messages is the set of foundational message structures this network admits
	// (canonical names from libs/messages). Empty ⇒ unconstrained. A client checks
	// AcceptsMessage before submitting; `info` prints the set so an operator can
	// see "what can I say to this network".
	Messages []string `json:"messages,omitempty"`
	// Schemas maps a governance/vocabulary section name to the sequence on THIS
	// network's log where its schema lives — the per-network payload vocabulary.
	Schemas map[string]uint64 `json:"schemas,omitempty"`
	// Federation lists the networks this one cites (cross-log anchors), so a
	// client can see the whole federation, not just one log.
	Federation []FederatedNet `json:"federation,omitempty"`
}

// FederatedNet names a network cited by this one in the federation.
type FederatedNet struct {
	Name      string `json:"name,omitempty"`
	NetworkID string `json:"network_id"`         // 64-hex
	Endpoint  string `json:"endpoint,omitempty"` // optional ledger base URL
}

// LoadClientBundle reads and validates a client bundle JSON file.
func LoadClientBundle(path string) (*ClientBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("client bundle: read %s: %w", path, err)
	}
	// Strict decode: an unknown field is a typo or a forward-incompatible
	// bundle this binary must not silently misread (e.g. a write_endpoint a
	// pre-field binary would drop, treating a gated network as ungated).
	// Pre-launch the clean break is correct; DisallowUnknownFields rejects
	// rather than drops. The bundle's open vocabulary (the Schemas map keys,
	// Messages, Federation entries) is value-space and unaffected — only
	// unknown STRUCT keys reject.
	var b ClientBundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("client bundle: parse %s: %w", path, err)
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// validate checks the always-required fields. Command-specific requirements
// (LogDID for submit/load; NetworkID + QuorumK for proof) are enforced by the
// typed accessors below so each command fails with a precise message.
func (b *ClientBundle) validate() error {
	if b.Format != ClientBundleFormat {
		return fmt.Errorf("client bundle: format %q, want %q", b.Format, ClientBundleFormat)
	}
	if b.Endpoint == "" {
		return fmt.Errorf("client bundle: endpoint is required")
	}
	if bad := messages.Unknown(b.Messages); len(bad) > 0 {
		return fmt.Errorf("client bundle: unknown message structure(s) %v — not in the foundational catalog", bad)
	}
	for i, f := range b.Federation {
		if _, err := hexID(f.NetworkID); err != nil {
			return fmt.Errorf("client bundle: federation[%d] (%q) network_id %w", i, f.Name, err)
		}
	}
	return nil
}

// hexID decodes a 64-hex (32-byte) identifier.
func hexID(s string) ([32]byte, error) {
	var id [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return id, fmt.Errorf("must be 64 hex chars (32 bytes), got %q", s)
	}
	copy(id[:], raw)
	return id, nil
}

// AcceptsMessage reports whether the network admits the named foundational
// structure. A bundle with no Messages list does not constrain (returns true).
func (b *ClientBundle) AcceptsMessage(name string) bool {
	if len(b.Messages) == 0 {
		return true
	}
	for _, m := range b.Messages {
		if m == name {
			return true
		}
	}
	return false
}

// RequireLogDID returns the destination log DID or an error naming what the
// submit/load paths need.
func (b *ClientBundle) RequireLogDID() (string, error) {
	if b.LogDID == "" {
		return "", fmt.Errorf("client bundle has no log_did (required to submit/load to a network)")
	}
	return b.LogDID, nil
}

// NetworkID32 decodes the 64-hex NetworkID. Required for proof verification (the
// resolver + the verify-time pin).
func (b *ClientBundle) NetworkID32() ([32]byte, error) {
	id, err := hexID(b.NetworkID)
	if err != nil {
		return id, fmt.Errorf("client bundle: network_id %w", err)
	}
	return id, nil
}

// HTTPClient builds the outbound client for this bundle's transport posture,
// reusing clienttls (the same server-verify / mTLS rules as the rest of the
// fleet). timeout ≤ 0 falls back to the clienttls default.
func (b *ClientBundle) HTTPClient(timeout time.Duration) (*http.Client, error) {
	f := clienttls.Flags{
		CAFile:          b.Transport.CAFile,
		CertFile:        b.Transport.ClientCertFile,
		KeyFile:         b.Transport.ClientKeyFile,
		AllowSelfSigned: b.Transport.AllowSelfSigned,
	}
	c, _, err := f.Client(timeout)
	if err != nil {
		return nil, fmt.Errorf("client bundle: build transport: %w", err)
	}
	return c, nil
}
