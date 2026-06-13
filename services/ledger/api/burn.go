/*
FILE PATH: services/ledger/api/burn.go

GET /v1/burn — the network's burn (equivocation) status as a FETCHED FACT, for
the v2 self-anchored proof's burn_attestation section.

A network is "burned" the moment it is observed equivocating — signing two
different cosigned tree heads at the same tree size. The ledger learns this from
the gossip network: a KindEquivocationFinding event naming this log as its target
(findings.EquivocationFinding.TargetLogDID). This endpoint reports that observed
state; it is NEVER a hardcoded constant, so a producer cannot mint a "clean" proof
over a log that the network already knows is burned.

Response: {"is_burned": bool}. The proof's as_of is the checkpoint tree size, which
the gather (libs/bundle) supplies when it encodes the burn_attestation — this
endpoint reports only the fact, not the checkpoint it will be stamped against.

LIMITATION (spec §9): this is a MINT-TIME snapshot. A network that equivocates
AFTER a proof is minted cannot be caught by a purely offline verifier; burn is the
one guarantee no wave offers offline.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	sdkgossip "github.com/baseproof/baseproof/gossip"
)

// BurnSource answers whether a log has been observed equivocating (a burn).
type BurnSource interface {
	IsBurned(ctx context.Context, logDID string) (bool, error)
}

// NewBurnHandler creates GET /v1/burn for this ledger's own log (logDID). A nil
// source (gossip disabled) reports is_burned=false — the honest answer when the
// ledger has no equivocation-observation capability (no evidence of burn).
func NewBurnHandler(src BurnSource, logDID string, logger *slog.Logger) http.HandlerFunc {
	return NewBurnHandlerWithDeclared(src, nil, logDID, logger)
}

// DeclaredBurnSource answers the AUTHORITATIVE burn question from the
// on-log record: the quorum-cosigned EntryNetworkBurnV1 the burn door
// (POST /v1/network/burn → BurnProcessor) committed and verified. The
// rc10 OR-semantics ruling (tooling#110):
//
//	is_burned = declared (on-log walk, authoritative)
//	         OR observed (gossip equivocation, evidence-tier)
//
// and ANY source error is a serve ABORT (503) — never a false bool in
// either direction. nil = no declared-burn capability wired (a reader
// binary): observed-only, the honest pre-#110-door posture.
type DeclaredBurnSource interface {
	DeclaredBurn(ctx context.Context) (bool, error)
}

// NewBurnHandlerWithDeclared creates GET /v1/burn with both legs.
func NewBurnHandlerWithDeclared(observed BurnSource, declared DeclaredBurnSource, logDID string, logger *slog.Logger) http.HandlerFunc {
	if logger == nil {
		logger = slog.Default()
	}
	return func(w http.ResponseWriter, r *http.Request) {
		burned := false
		if declared != nil {
			d, err := declared.DeclaredBurn(r.Context())
			if err != nil {
				// The walk refusing (e.g. an unauthorized on-log burn) is
				// misbehavior evidence — ABORT, never serve "not burned"
				// over poison (the SDK INPUT CONTRACT both this endpoint
				// and EncodeBurnAttestation inherit).
				logger.Error("burn status: declared leg", "error", err, "log_did", logDID)
				http.Error(w, "burn status unavailable", http.StatusServiceUnavailable)
				return
			}
			burned = burned || d
		}
		if !burned && observed != nil {
			b, err := observed.IsBurned(r.Context(), logDID)
			if err != nil {
				logger.Error("burn status", "error", err, "log_did", logDID)
				http.Error(w, "burn status unavailable", http.StatusServiceUnavailable)
				return
			}
			burned = burned || b
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"is_burned": burned})
	}
}

// GossipBurnSource reads burn status from the gossip store: a log is burned iff the
// store holds a KindEquivocationFinding naming it as the target log.
type GossipBurnSource struct {
	store sdkgossip.Store
}

// NewGossipBurnSource wires a burn source over the gossip store. A nil store
// (gossip disabled) is admissible — IsBurned then reports false.
func NewGossipBurnSource(store sdkgossip.Store) *GossipBurnSource {
	return &GossipBurnSource{store: store}
}

// IsBurned scans the gossip store's equivocation findings for one targeting logDID.
// Equivocation findings are rare network-wide (a healthy network has none), so the
// kind-filtered scan is bounded, not O(N).
func (s *GossipBurnSource) IsBurned(ctx context.Context, logDID string) (bool, error) {
	if s == nil || s.store == nil {
		return false, nil // no gossip ⇒ no equivocation observed
	}
	kind := sdkgossip.KindEquivocationFinding
	burned := false
	err := s.store.Iterate(ctx, sdkgossip.Filter{Kind: &kind}, func(ev sdkgossip.SignedEvent) error {
		decoded, derr := sdkgossip.DecodeWireBody(sdkgossip.KindEquivocationFinding, ev.Body)
		if derr != nil {
			return nil // an undecodable finding event — skip defensively, never crash
		}
		if w, ok := decoded.(sdkgossip.WireEquivocationFinding); ok && w.TargetLogDID == logDID {
			burned = true
		}
		return nil
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		return false, err
	}
	return burned, nil
}
