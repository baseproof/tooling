/*
FILE PATH: internal/serve/serve.go

Witness cosignature endpoint construction. Wraps the SDK's universal
cosign handler (cosign.NewWitnessHandler) with the witness daemon's
local monotonicity guard that refuses to cosign a tree head smaller
than the largest tree head this process has previously signed.

# WHY THIS LIVES UNDER internal/

Per the architectural separation: this is witness-daemon application
state and middleware. It is not a library the Ledger consumes — the
Ledger does not act as a witness. Placing the code under internal/
has two effects:

 1. Go's compiler refuses imports of internal/ packages from outside
    this module. No external repository — including the Ledger — can
    reach this code.

 2. This module never imports github.com/clearcompass-ai/ledger; the
    boundary is enforced before linting can even run.

# WHAT THE WRAPPER ADDS OVER cosign.NewWitnessHandler

The SDK ships a wire-complete cosign handler — JSON parsing,
network/purpose/hash-algo validation, payload decoding (including the
canonical tree-head payload: root_hash ‖ smt_root ‖ receipt_root ‖
tree_size), signing, and response encoding. It does not encode
WITNESS-DEPLOYMENT-LOCAL rules like "refuse rollbacks", because such
rules are deployment-specific and the SDK is the universal contract.

This file adds exactly one thing on top of the SDK handler:

  - In-memory concurrent-misfire guard: within a single process, do
    not cosign a tree_size strictly smaller than the largest this
    process has signed since boot. PER-PROCESS, EPHEMERAL BY DESIGN —
    it resets to zero on restart and is NOT persisted. See the
    "BLIND NOTARY" section for why that is correct, not a gap.

# BLIND NOTARY — WHY THIS DAEMON IS STATELESS

This witness is a Blind Notary. Its job is to lend its cryptographic
weight (one of N) attesting that a specific tree head was presented
to it at a moment in time. It does NOT — and architecturally must
not — try to enforce the log's history. Three facts make a
persistent rollback guard here both futile and harmful:

 1. Size-only monotonicity does not prevent a fork. A malicious
    ledger holding lastSignedSize=100 can rewrite entries 1..99,
    append one leaf, and present a completely different TreeHead at
    TreeSize=101. A stateful guard sees 101 > 100 and happily
    cosigns the fork. Real fork prevention requires persisting
    RootHash AND verifying an RFC 6962 consistency proof on every
    request — which this daemon cannot do: it has no log access.

 2. Persistence would put an fsync on the cosign hot path
    (persist→fsync→sign is the only crash-safe order), collapsing a
    RAM-speed notary into a disk-bound one and bottlenecking the
    ledger's admission phase — for ZERO cryptographic gain per (1).

 3. Rollback and fork detection are a DETECTIVE control owned by the
    auditors, not a preventative one owned by the witness. The
    Judicial Network pulls the gossip feed, mathematically checks the
    cosigned sequence, and on any rollback/fork emits an
    EquivocationFinding that permanently burns the ledger's identity.
    That is where history is enforced.

So the guard below is RAM-only and exists solely to catch accidental
concurrent/duplicate misfires within one process. It is not a
cross-restart authority and must never be made one.

# CONCURRENT-MISFIRE GUARD

A pre-handler middleware reads the request body once (capped at
MaxRequestBytes), peeks at the cosign.WireRequest's purpose field,
and for PurposeTreeHead extracts the embedded tree_size. On a
smaller tree_size the response is 409 Conflict + a WireError-shaped
JSON body. On non-tree-head purposes (rotation, escrow override) the
middleware passes through unchanged.

Body re-injection: the middleware replaces r.Body with a
bytes.Reader over the buffered bytes so the inner handler reads the
same content. No mutation of headers or method.

State semantics: lastSignedSize advances at middleware entry on the
optimistic assumption that the inner handler will accept the request.
If the inner handler rejects for a downstream reason (bad network,
malformed payload), lastSignedSize stays advanced — a re-attempt at
exactly the rejected size becomes a no-op next time. Reset to zero on
restart, by design (see BLIND NOTARY above).
*/
package serve

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/baseproof/baseproof/crypto/cosign"
)

// Config configures the witness cosign endpoint.
type Config struct {
	// WitnessKey is the ECDSA private key used to sign tree heads.
	// Injected from HSM/config. Never persisted in plaintext.
	// BLS witnesses inject a different signer via BuildSigner.
	WitnessKey *ecdsa.PrivateKey

	// NetworkID is the deployment's 32-byte cosign-domain identifier,
	// derived at boot from the network bootstrap document. Witnesses
	// for the same network share the same value; signatures produced
	// under one NetworkID never verify under another.
	NetworkID cosign.NetworkID

	// AllowedPurposes narrows the signing surface to the listed
	// purposes. nil ⇒ accept any registered Purpose — a signing
	// oracle for tree-head, rotation, AND escrow-override, which is
	// rarely what an operator wants. The daemon's default is the
	// least-privilege {cosign.PurposeTreeHead: {}} (see
	// ParseAllowedPurposes); widen only for a witness that also
	// contributes witness-set rotation cosignatures over /v1/cosign.
	AllowedPurposes map[cosign.Purpose]struct{}

	// MaxRequestBytes caps request body size. <= 0 ⇒
	// cosign.DefaultMaxRequestBytes (64 KiB).
	MaxRequestBytes int64

	Logger *slog.Logger
}

// Build constructs the witness cosign handler ready to mount at
// POST /v1/cosign. Wraps cosign.NewWitnessHandler with the
// monotonicity guard.
//
// Returns an error if the SDK handler factory rejects the config
// (zero NetworkID, missing signer, etc.).
func Build(cfg Config) (http.Handler, error) {
	if cfg.WitnessKey == nil {
		return nil, fmt.Errorf("standalone-witness/serve: WitnessKey required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	signer := cosign.NewECDSAWitnessSigner(cfg.WitnessKey)
	return BuildSigner(signer, cfg)
}

// BuildSigner is the BLS-or-custom-signer variant of Build.
// Witnesses with HSM-backed BLS keys construct a custom
// cosign.WitnessSigner and pass it here.
func BuildSigner(signer cosign.WitnessSigner, cfg Config) (http.Handler, error) {
	if signer == nil {
		return nil, fmt.Errorf("standalone-witness/serve: signer required")
	}
	cfg.Logger = orDefaultLogger(cfg.Logger)
	maxBytes := orDefaultMaxBytes(cfg.MaxRequestBytes)

	inner, err := newSDKHandler(signer, cfg, maxBytes)
	if err != nil {
		return nil, err
	}
	state := newGuardState()
	return state.wrap(maxBytes, cfg.Logger, inner), nil
}

func orDefaultLogger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

func orDefaultMaxBytes(n int64) int64 {
	if n <= 0 {
		return cosign.DefaultMaxRequestBytes
	}
	return n
}

// purposeTokens maps the operator-facing CLI vocabulary to the SDK
// cosign.Purpose constants. PurposeGossipEventV1 is intentionally
// absent — gossip envelopes transit /v1/gossip, and the SDK's
// DecodeWirePayload rejects that purpose on the cosign path anyway.
var purposeTokens = map[string]cosign.Purpose{
	"tree-head":       cosign.PurposeTreeHead,
	"rotation":        cosign.PurposeRotation,
	"escrow-override": cosign.PurposeEscrowOverride,
}

// ParseAllowedPurposes maps a comma-separated token list into the
// Config.AllowedPurposes set. Whitespace around tokens is trimmed.
//
// An empty result is rejected: a witness that signs nothing is a
// misconfiguration, and — critically — an empty (but non-nil) map
// passed to the SDK handler would 403 every request including
// tree-head. Unknown tokens are rejected so a typo (e.g.
// "treehead") fails fast at boot instead of silently producing a
// witness that rejects all traffic.
func ParseAllowedPurposes(csv string) (map[cosign.Purpose]struct{}, error) {
	out := make(map[cosign.Purpose]struct{})
	for _, raw := range strings.Split(csv, ",") {
		tok := strings.TrimSpace(raw)
		if tok == "" {
			continue
		}
		p, ok := purposeTokens[tok]
		if !ok {
			return nil, fmt.Errorf(
				"standalone-witness/serve: unknown cosign purpose %q (valid: tree-head, rotation, escrow-override)",
				tok)
		}
		out[p] = struct{}{}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("standalone-witness/serve: no cosign purposes specified")
	}
	return out, nil
}

// newSDKHandler builds the SDK cosign handler from a Config.
func newSDKHandler(signer cosign.WitnessSigner, cfg Config, maxBytes int64) (http.Handler, error) {
	inner, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
		Signer:          signer,
		AllowedNetworks: map[cosign.NetworkID]struct{}{cfg.NetworkID: {}},
		AllowedPurposes: cfg.AllowedPurposes,
		MaxRequestBytes: maxBytes,
		Logger:          cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("standalone-witness/serve: build SDK handler: %w", err)
	}
	return inner, nil
}

// ─────────────────────────────────────────────────────────────────
// Concurrent-misfire guard (RAM-only; see BLIND NOTARY in the header)
// ─────────────────────────────────────────────────────────────────

// guardState owns the per-process, in-memory lastSignedSize. It is
// EPHEMERAL: reset to zero on restart, never persisted. It catches
// accidental concurrent/duplicate misfires within one process — it
// is NOT a cross-restart rollback authority and must not be made
// one (a size-only check cannot prevent forks; that is the auditors'
// job via gossip + EquivocationFinding).
type guardState struct {
	mu             sync.Mutex
	lastSignedSize uint64
}

func newGuardState() *guardState { return &guardState{} }

// wrap returns middleware that rejects tree-head rollbacks with 409
// Conflict before the inner handler sees the request. Only
// PurposeTreeHead carries a tree_size; all other purposes (rotation,
// escrow override) pass through unchanged.
func (s *guardState) wrap(maxBytes int64, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, "read body failed")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		var req cosign.WireRequest
		if jsonErr := json.Unmarshal(body, &req); jsonErr != nil {
			next.ServeHTTP(w, r)
			return
		}

		treeSize, ok := extractTreeSize(req.Purpose, req.Payload)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		s.mu.Lock()
		if treeSize < s.lastSignedSize {
			prev := s.lastSignedSize
			s.mu.Unlock()
			logger.Warn("cosign: rejected rollback attempt",
				"purpose", string(req.Purpose),
				"requested", treeSize,
				"last_signed", prev)
			writeError(w, http.StatusConflict,
				fmt.Sprintf("tree_size rollback rejected: requested=%d last_signed=%d",
					treeSize, prev))
			return
		}
		s.lastSignedSize = treeSize
		s.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// extractTreeSize returns the tree-head payload's TreeSize for
// PurposeTreeHead. ok=false means the purpose is not a tree-head
// purpose OR the payload didn't parse — both cases pass through to
// the inner handler unchanged.
//
// The canonical cosign.WireTreeHeadPayload carries root_hash ‖
// smt_root ‖ receipt_root ‖ tree_size; the guard reads only
// tree_size, so the receipt_root addition does not affect it.
func extractTreeSize(purpose cosign.Purpose, payload json.RawMessage) (uint64, bool) {
	if purpose != cosign.PurposeTreeHead {
		return 0, false
	}
	var th cosign.WireTreeHeadPayload
	if err := json.Unmarshal(payload, &th); err != nil {
		return 0, false
	}
	return th.TreeSize, true
}

// writeError emits a WireError-shaped JSON response so callers
// parse a single error envelope across SDK + monotonicity
// rejections.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(cosign.WireError{Error: message})
}
