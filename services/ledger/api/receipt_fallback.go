/*
FILE PATH: api/receipt_fallback.go

FallbackReceiptProver — graceful PG→archive degradation for the receipt endpoint.

WHY (1.2a step 2): the receipt handler's ReceiptProver is EntryIndexReceiptRanger
(entry_index, PG). When PG is unavailable — or the entry's metadata row was GC'd —
the per-checkpoint commitment archive (store.ArchiveReceiptRanger) can still
reconstruct the proof from object storage. This prover tries PG first and falls back
to the archive on an INFRASTRUCTURE error only; a genuine "no receipt for this seq"
(smt.ErrReceiptLeafNotFound) is NOT masked by the fallback — it is the honest
negative the handler maps to 404.
*/
package api

import (
	"context"
	"errors"
	"log/slog"

	"github.com/baseproof/baseproof/core/smt"
)

// FallbackReceiptProver composes a primary (PG) and fallback (archive) ReceiptProver.
// Both satisfy ReceiptProver; the archive ranger is store.ArchiveReceiptRanger.
type FallbackReceiptProver struct {
	Primary  ReceiptProver
	Fallback ReceiptProver
	Logger   *slog.Logger
}

// ReceiptInclusionProof tries Primary; on a non-leaf-not-found error, tries Fallback.
func (p *FallbackReceiptProver) ReceiptInclusionProof(ctx context.Context, fromSeq, toSeq, targetSeq uint64) (*smt.ReceiptInclusionProof, error) {
	proof, err := p.Primary.ReceiptInclusionProof(ctx, fromSeq, toSeq, targetSeq)
	if err == nil {
		return proof, nil
	}
	// A genuine "no receipt committed for this seq" is authoritative — do NOT let the
	// archive mask it (the archive would return the same, or worse, a stale set).
	if errors.Is(err, smt.ErrReceiptLeafNotFound) {
		return nil, err
	}
	if p.Fallback == nil {
		return nil, err
	}
	fb, ferr := p.Fallback.ReceiptInclusionProof(ctx, fromSeq, toSeq, targetSeq)
	if ferr != nil {
		// Both failed: surface both causes (the PG error is the primary signal; the
		// archive error explains why the safety net didn't catch it).
		if p.Logger != nil {
			p.Logger.Warn("receipt prover: primary and fallback both failed",
				"target", targetSeq, "primary_err", err, "fallback_err", ferr)
		}
		return nil, errors.Join(err, ferr)
	}
	if p.Logger != nil {
		p.Logger.Info("receipt prover: served from archive fallback", "target", targetSeq, "primary_err", err)
	}
	return fb, nil
}
