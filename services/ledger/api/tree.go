/*
FILE PATH: api/tree.go

Tree head distribution and Merkle proof endpoints.

CHANGES FROM PHASE 4 PREP:
  - NewTreeHeadHandler now accepts ?size=N query parameter.
    GET /v1/tree/head → latest cosigned tree head (existing)
    GET /v1/tree/head?size=N → tree head at specific size (NEW)
    Falls through to existing Latest() when no parameter.
    Uses TreeHeadStore.GetBySize() which already exists (store/tree_heads.go).
*/
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	sdkgossip "github.com/baseproof/baseproof/gossip"
	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/apitypes"
)

// ConsistencyProver generates consistency proofs.
type ConsistencyProver interface {
	ConsistencyProof(oldSize, newSize uint64) (any, error)
}

// InclusionProver generates inclusion proofs for HTTP passthrough.
type InclusionProver interface {
	RawInclusionProof(position, treeSize uint64) (any, error)
}

// TreeDeps holds dependencies for tree handlers.
type TreeDeps struct {
	TreeHeadStore TreeHeadFetcher
	Inclusion     InclusionProver
	Consistency   ConsistencyProver
	Logger        *slog.Logger
}

// NewTreeHeadHandler creates GET /v1/tree/head[?size=N].
// Without ?size=N: returns latest cosigned tree head (existing behavior).
// With ?size=N: returns tree head at that specific size via GetBySize().
func NewTreeHeadHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var head *apitypes.CosignedTreeHead
		var err error

		// Check for ?size=N parameter (blocks fraud_proofs).
		sizeStr := r.URL.Query().Get("size")
		if sizeStr != "" {
			size, parseErr := strconv.ParseUint(sizeStr, 10, 64)
			if parseErr != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
					http.StatusBadRequest, "invalid size parameter")
				return
			}
			// GetBySize exists in store/tree_heads.go — returns tree head
			// at specific size, used by equivocation monitor and fraud proofs.
			head, err = deps.TreeHeadStore.GetBySize(ctx, size)
		} else {
			head, err = deps.TreeHeadStore.Latest(ctx)
		}

		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "failed to fetch tree head")
			deps.Logger.Error("tree head fetch", "error", err)
			return
		}
		if head == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, "no cosigned tree head available")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, head.TreeSize))
		w.Header().Set("Cache-Control", "public, max-age=5")

		// Per-witness cosignatures are persisted as JSON-marshaled
		// types.WitnessSignature in the signature column (see
		// witnessclient/head_sync.go persistSignatures). Decode each
		// back and re-emit in the canonical gossip wire trio
		// {pub_key_id, scheme_tag, sig_bytes} so a consumer can
		// reconstruct an SDK-native CosignedTreeHead via
		// findings.CosignedTreeHeadFromWire and verify the K-of-N
		// quorum with Verify(set) — no out-of-band hop. The store's
		// `signer` (witness endpoint) and `sig_algo` columns are
		// denormalized metadata, not the authoritative material.
		sigs := make([]sdkgossip.WireWitnessSignature, 0, len(head.Signatures))
		for _, s := range head.Signatures {
			var ws sdktypes.WitnessSignature
			if err := json.Unmarshal(s.Signature, &ws); err != nil {
				deps.Logger.Warn("tree head: skip undecodable witness signature",
					"signer", s.Signer, "error", err)
				continue
			}
			sigs = append(sigs, sdkgossip.WireWitnessSignature{
				PubKeyID:  hex.EncodeToString(ws.PubKeyID[:]),
				SchemeTag: ws.SchemeTag,
				SigBytes:  hex.EncodeToString(ws.SigBytes),
			})
		}

		// Response is a flat gossip.WireCosignedTreeHead plus the
		// log's hash_algo. All FOUR cosigned roots are emitted —
		// root_hash, smt_root, receipt_root, tree_size — so the full
		// 104-byte canonical cosign message (RootHash ‖ SMTRoot ‖
		// ReceiptRoot ‖ TreeSize) can be reconstructed and the
		// signatures verified. receipt_root was previously dropped,
		// which silently broke cosignature verification for any batch
		// carrying Web3 receipts: the payload could not be rebuilt, so
		// every signature check failed. smt_root/receipt_root are zero
		// hex when the deployment publishes no SMT projection / no
		// receipts (the cosign payload Validate exempts a zero
		// ReceiptRoot).
		_ = json.NewEncoder(w).Encode(struct {
			sdkgossip.WireCosignedTreeHead
			HashAlgo uint16 `json:"hash_algo"`
		}{
			WireCosignedTreeHead: sdkgossip.WireCosignedTreeHead{
				RootHash:    hex.EncodeToString(head.RootHash[:]),
				SMTRoot:     hex.EncodeToString(head.SMTRoot[:]),
				ReceiptRoot: hex.EncodeToString(head.ReceiptRoot[:]),
				TreeSize:    head.TreeSize,
				Signatures:  sigs,
			},
			HashAlgo: head.HashAlgo,
		})
	}
}

// NewTreeInclusionHandler creates GET /v1/tree/inclusion/{seq}.
func NewTreeInclusionHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		seqStr := r.PathValue("seq")
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid sequence number")
			return
		}

		head, err := deps.TreeHeadStore.Latest(ctx)
		if err != nil || head == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassDBQueryFailed,
				http.StatusServiceUnavailable, "no tree head available")
			return
		}

		// Optional ?tree_size=N requests the proof against a SPECIFIC tree size
		// (default: the current head). An auditor rebuilding the witness-rotation
		// chain needs a proof bound to the witness-COSIGNED horizon (which lags
		// the live head), not the live sub-quorum head — so it pins the size to
		// horizon.TreeSize here. N must be in (seq, head.TreeSize]: a leaf is only
		// provable in a tree that already commits it, and we cannot prove against
		// a future size we have not built.
		treeSize := head.TreeSize
		if ts := r.URL.Query().Get("tree_size"); ts != "" {
			parsed, perr := strconv.ParseUint(ts, 10, 64)
			if perr != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
					http.StatusBadRequest, "invalid tree_size")
				return
			}
			if parsed == 0 || parsed > head.TreeSize {
				writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
					http.StatusBadRequest,
					fmt.Sprintf("tree_size %d out of range (1..%d)", parsed, head.TreeSize))
				return
			}
			treeSize = parsed
		}

		if deps.Inclusion == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusServiceUnavailable, "inclusion proofs not available")
			return
		}

		proof, err := deps.Inclusion.RawInclusionProof(seq, treeSize)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusNotFound,
				fmt.Sprintf("inclusion proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

// NewTreeConsistencyHandler creates GET /v1/tree/consistency/{old}/{new}.
func NewTreeConsistencyHandler(deps *TreeDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		oldStr := r.PathValue("old")
		newStr := r.PathValue("new")
		oldSize, err1 := strconv.ParseUint(oldStr, 10, 64)
		newSize, err2 := strconv.ParseUint(newStr, 10, 64)
		if err1 != nil || err2 != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid tree sizes")
			return
		}
		if oldSize >= newSize {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "old size must be less than new size")
			return
		}

		if deps.Consistency == nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusServiceUnavailable, "consistency proofs not available")
			return
		}

		proof, err := deps.Consistency.ConsistencyProof(oldSize, newSize)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusNotFound,
				fmt.Sprintf("consistency proof: %s", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}
