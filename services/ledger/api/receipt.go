/*
FILE PATH: api/receipt.go

GET /v1/receipt/proof/{seq} — the entry's RECEIPT-inclusion proof, the third
cosigned-root leg of a v2 self-anchored proof (the verifier binds it to
cosigned_head.receipt_root via smt.VerifyReceiptInclusion).

# WHY A FIRST-COVERING CHECKPOINT (not the latest horizon)

A cosigned ReceiptRoot is a PER-CHECKPOINT DELTA over (prevPublishedSize,
thisSize] (builder/checkpoint_loop.go receiptRootForCheckpoint), NOT a cumulative
tree. So an entry's receipt lives ONLY in the FIRST published checkpoint that
covers it; the latest horizon's delta would not contain an older entry's receipt.
The handler therefore resolves the smallest cosigned tree_size >= seq+1, builds
the proof over that checkpoint's receipt range, and returns the head it binds to —
so a consumer anchors receipt_proof to the SAME cosigned roots as root_hash and
smt_root.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/store"
)

// apitypesHeadToSDK converts the ledger's apitypes cosigned head to the SDK's
// types.CosignedTreeHead (the shape EncodeReceiptProof + the v2 verifier consume).
// Delegates to store.HeadToSDK — the single mapping the backfill also uses, so a
// stored head maps to the SDK shape identically on both paths.
func apitypesHeadToSDK(h *apitypes.CosignedTreeHead) types.CosignedTreeHead {
	return store.HeadToSDK(h)
}

// ReceiptHeadResolver resolves the published checkpoint a receipt proof binds to.
type ReceiptHeadResolver interface {
	// CosignedSizeAtOrAbove returns the smallest cosigned tree_size >= minSize
	// (the first checkpoint covering an entry), false if none.
	CosignedSizeAtOrAbove(ctx context.Context, minSize uint64, minSigs int) (uint64, bool, error)
	// CosignedSizeBelow returns the largest cosigned tree_size < size (the
	// previous published checkpoint — the receipt delta range start), false if none.
	CosignedSizeBelow(ctx context.Context, size uint64, minSigs int) (uint64, bool, error)
	// GetBySize returns the cosigned head at exactly size (with its signatures).
	GetBySize(ctx context.Context, size uint64) (*apitypes.CosignedTreeHead, error)
}

// ReceiptProver builds the receipt-membership proof over a checkpoint's receipt
// range [fromSeq, toSeq] for the entry at targetSeq.
type ReceiptProver interface {
	ReceiptInclusionProof(ctx context.Context, fromSeq, toSeq, targetSeq uint64) (*smt.ReceiptInclusionProof, error)
}

// ReceiptDeps wires GET /v1/receipt/proof/{seq}.
type ReceiptDeps struct {
	Heads    ReceiptHeadResolver
	Receipts ReceiptProver
	MinSigs  int // quorum K: the distinct-signer threshold a published checkpoint must meet
	Logger   *slog.Logger
}

func (d *ReceiptDeps) logger() *slog.Logger {
	if d != nil && d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// NewReceiptProofHandler creates GET /v1/receipt/proof/{seq}.
func NewReceiptProofHandler(deps *ReceiptDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if deps == nil || deps.Heads == nil || deps.Receipts == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusServiceUnavailable, "receipt proofs not available")
			return
		}
		seq, err := strconv.ParseUint(strings.TrimSpace(r.PathValue("seq")), 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "seq must be a non-negative integer")
			return
		}

		// First cosigned checkpoint covering seq (TreeSize >= seq+1).
		cSize, ok, err := deps.Heads.CosignedSizeAtOrAbove(ctx, seq+1, deps.MinSigs)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "resolve covering checkpoint")
			deps.logger().Error("receipt proof: covering checkpoint", "seq", seq, "error", err)
			return
		}
		if !ok {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "no cosigned checkpoint covers this seq yet")
			return
		}

		head, err := deps.Heads.GetBySize(ctx, cSize)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "load checkpoint head")
			deps.logger().Error("receipt proof: head", "seq", seq, "size", cSize, "error", err)
			return
		}
		if head == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound, http.StatusNotFound, "checkpoint head not found")
			return
		}

		// The checkpoint's receipt delta range: [prevCheckpointSize, cSize-1].
		fromSeq := uint64(0)
		if prev, has, perr := deps.Heads.CosignedSizeBelow(ctx, cSize, deps.MinSigs); perr != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "resolve receipt range")
			deps.logger().Error("receipt proof: range", "seq", seq, "error", perr)
			return
		} else if has {
			fromSeq = prev
		}
		toSeq := cSize - 1

		proof, err := deps.Receipts.ReceiptInclusionProof(ctx, fromSeq, toSeq, seq)
		if err != nil {
			if errors.Is(err, smt.ErrReceiptLeafNotFound) {
				writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
					http.StatusNotFound, "no receipt committed for this seq")
				return
			}
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "receipt proof generation failed")
			deps.logger().Error("receipt proof: generate", "seq", seq, "from", fromSeq, "to", toSeq, "error", err)
			return
		}

		// Embed the covering-checkpoint head IN the section: ReceiptRoot is a
		// per-checkpoint delta, so the v2 verifier reconstructs the receipt against
		// THIS head's ReceiptRoot (not the proof's horizon head). The gather passes
		// the section through verbatim.
		section, err := bundle.EncodeReceiptProof(proof, apitypesHeadToSDK(head))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "encode receipt proof")
			deps.logger().Error("receipt proof: encode", "seq", seq, "error", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		// Content-deterministic: the proof binds to the entry's FIRST covering
		// checkpoint (a fixed, witness-cosigned head), so it never changes for this
		// seq — cacheable forever, the read-cost-bounding hot-path cache (2.3).
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"receipt_proof": section, // v2 receipt_proof section — drop straight into a proof
			"checkpoint":    head,    // the cosigned head it binds to (root_hash + smt_root + receipt_root)
		})
	}
}
