// FILE PATH: libs/monitoring/equivocation_response.go
//
// DESCRIPTION:
//
//	EquivocationResponder is the "act" for a VERIFIED equivocation finding
//	pulled from a peer feed: it drives the slasher, which re-verifies (defense
//	in depth) and records the proof, dropping the offending ledger's trust to
//	zero once the slash threshold is crossed. A slashed ledger's voting weight
//	in consortium decisions becomes zero — the emergency trust response to a
//	ledger that signed two conflicting histories.
//
//	The slasher is referenced through a minimal local interface so this package
//	takes no dependency on equivocation/ (the concrete *equivocation.Slasher is
//	wired in at the composition root), keeping monitoring acyclic.
package monitoring

import (
	"context"
	"errors"
	"log/slog"

	"github.com/baseproof/baseproof/gossip/findings"
)

// equivApplier is the slash side EquivocationResponder drives.
// *equivocation.Slasher satisfies it.
type equivApplier interface {
	Apply(ctx context.Context, finding *findings.EquivocationFinding) error
}

// ErrEquivocationResponse wraps responder failures.
var ErrEquivocationResponse = errors.New("monitoring/equivocation_response")

// EquivocationResponder applies verified equivocation findings to the slasher.
type EquivocationResponder struct {
	slasher equivApplier
	logger  *slog.Logger
}

// NewEquivocationResponder wires the responder to a slash applier. nil logger ⇒
// slog.Default().
func NewEquivocationResponder(slasher equivApplier, logger *slog.Logger) (*EquivocationResponder, error) {
	if slasher == nil {
		return nil, errors.New("monitoring/equivocation_response: nil slasher")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &EquivocationResponder{slasher: slasher, logger: logger}, nil
}

// Respond drives the slasher on a VERIFIED equivocation finding. The finding
// must already have passed the gossip verifier; the slasher independently
// re-verifies before recording, so a finding that fails the second check is
// dropped rather than penalising an innocent ledger.
func (r *EquivocationResponder) Respond(ctx context.Context, finding *findings.EquivocationFinding) error {
	if finding == nil {
		return errors.New("monitoring/equivocation_response: nil finding")
	}
	r.logger.Error("monitoring/equivocation_response: verified equivocation observed — slashing",
		slog.String("ledger_endpoint", finding.LedgerEndpoint))
	if err := r.slasher.Apply(ctx, finding); err != nil {
		return errors.Join(ErrEquivocationResponse, err)
	}
	return nil
}
