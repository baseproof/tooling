/*
FILE PATH: api/proofs.go

SMT proof endpoints under baseproof v0.3.0 (Jellyfish/Patricia trie).
Single membership/non-membership proofs, batch multiproofs, and
current-root query.

# V0.3.0 ARCHITECTURE

The handlers operate against a shared smt.Tree whose internal rootHash
is advanced by the builder loop after each atomic commit. The tree's
LeafStore is a PostgresLeafStore; its NodeStore is a TailedNodeStore
(in-memory tail of un-tiled nodes + read-through to content-addressed
tiles — the node DAG no longer lives in PG). Both are content-addressed
and concurrent-read-safe. Proof generation walks the trie through the
NodeStore directly — no materialisation, no per-request O(N) snapshot.

The "Materializable" interface and "liveTree" indirection used in
v0.2.0 are GONE. Their entire purpose was to work around the v0.2.0
SDK's collectLeafHashes type-switch that short-circuited Tree.Root for
PostgresLeafStore. v0.3.0 fixes that at the SDK level; the workaround
is technical debt.

# CONCURRENCY

The shared tree.Root reads under the SDK's internal mutex; per-request
reads (Get/GetLeaf/GenerateMembershipProof/etc.) are safe concurrent
with the builder's writes (the single writer holds the same mutex for
the rootHash advance + SetRoot call).
*/
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/store"
)

// SMTRootReader reads the authoritative current SMT root. The
// production wiring (store.SMTRootStateStore) satisfies this; tests
// can inject fakes. When nil, /v1/smt/root falls back to tree.Root.
type SMTRootReader interface {
	ReadRoot(ctx context.Context) ([32]byte, error)
}

// SMTDeps holds dependencies for SMT proof handlers.
//
// Tree is the SDK's v0.3.0 smt.Tree, shared with the builder loop.
// LeafStore is the same store the tree wraps — exposed here for the
// Count() call on /v1/smt/root. RootState, when set, satisfies the
// O(1) root read; production wiring always sets it.
type SMTDeps struct {
	Tree      *smt.Tree
	LeafStore smt.LeafStore
	RootState SMTRootReader
	Logger    *slog.Logger

	// A4c cutover switch. ProofSource selects pg (default — the live-tree
	// path, unchanged), tiles (de-polluted), or shadow (serve pg, also
	// compute from tiles and log mismatches — the evidence to gate the
	// cutover on). Tiles/TileCache are consulted only for tiles/shadow.
	ProofSource store.SMTProofSource
	Tiles       store.SMTTileStore
	TileCache   *smt.TileCache

	// Horizon, when set, is the read-front anchor: proofs are generated
	// as-of the latest published witness-cosigned SMTRoot (the horizon)
	// rather than the live mutable root, and the cosigned checkpoint is
	// bundled into the response. This closes the fetch-head-then-fetch-proof
	// race — the proof and the head are bound to the same root. nil ⇒ legacy
	// live-root serving (dev / test / unconfigured deployments).
	Horizon HorizonReader
}

// NewSMTProofHandler creates GET /v1/smt/proof/{key}.
//
// Behaviour:
//   - leaf present at key  → membership proof (TerminalKind = leaf,
//     TerminalLeaf.Key == key)
//   - leaf absent          → non-membership proof (TerminalKind one of
//     leaf-blocking / branch-mismatch / empty)
//
// The response shape is {"type": "membership"|"non_membership",
// "proof": types.SMTProof}. The Jellyfish-shape SMTProof's exported
// fields marshal directly via encoding/json.
func NewSMTProofHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		keyHex := r.PathValue("key")
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil || len(keyBytes) != 32 {
			writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
				http.StatusBadRequest, "key must be 64 hex characters (32 bytes)")
			return
		}

		var key [32]byte
		copy(key[:], keyBytes)

		// ── As-of anchor resolution ──────────────────────────────
		// A membership proof is trust-rooted only when anchored on a
		// witness-cosigned root. Resolve the anchor in priority order:
		//   1. explicit ?smt_root=hex     → prove as-of a client-chosen root
		//   2. else the published horizon  → prove as-of the cosigned SMTRoot
		//      and bundle the checkpoint (the client re-verifies K-of-N)
		//   3. else (no horizon wired)     → legacy: prove at the live root
		if rootHex := strings.TrimSpace(r.URL.Query().Get("smt_root")); rootHex != "" {
			rootBytes, derr := hex.DecodeString(rootHex)
			if derr != nil || len(rootBytes) != 32 {
				writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
					http.StatusBadRequest, "smt_root must be 64 hex characters (32 bytes)")
				return
			}
			var root [32]byte
			copy(root[:], rootBytes)
			serveAsOfProof(ctx, w, deps, key, root, nil)
			return
		}

		if deps.Horizon != nil {
			head, raw, herr := deps.Horizon.ReadHorizon(ctx)
			if herr != nil {
				if errors.Is(herr, os.ErrNotExist) {
					// Pre-genesis: no cosigned checkpoint published yet. 503 —
					// the read front has nothing trust-rooted to anchor on.
					writeTypedError(ctx, w, apitypes.ErrorClassHorizonUnavailable,
						http.StatusServiceUnavailable, "no cosigned checkpoint published yet")
					return
				}
				writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
					http.StatusInternalServerError, "horizon read failed")
				deps.Logger.Error("smt proof: horizon read", "error", herr)
				return
			}
			serveAsOfProof(ctx, w, deps, key, head.SMTRoot, raw)
			return
		}

		serveLiveRootProof(ctx, w, deps, key)
	}
}

// serveAsOfProof generates a (non-)membership proof against a FIXED root over
// the configured substrate (pg node store / tiles / shadow) and writes
// {type, proof[, checkpoint]}. The "type" is read off the proof's terminal —
// never a live leaf lookup — so it is correct as-of the anchored root.
// checkpointRaw, when non-nil, is the published cosigned head bundled verbatim
// for the client to re-verify K-of-N out-of-band (the ledger cannot certify
// its own validity).
//
// Fail-closed error mapping (the anchor's provenance decides the class):
//   - ErrUnknownRoot with a bundled checkpoint (horizon anchor) ⇒ 500: the
//     ledger published a head whose own substrate it cannot serve — corruption
//     or a violated publish-on-durability gate, NOT "catching up".
//   - ErrUnknownRoot without a checkpoint (client-supplied root) ⇒ 404: the
//     caller asked to prove against a root this store does not retain.
//   - ErrNodeMissing ⇒ 500: interior DAG corruption, regardless of anchor.
func serveAsOfProof(ctx context.Context, w http.ResponseWriter, deps *SMTDeps, key, root [32]byte, checkpointRaw []byte) {
	proof, mismatch, err := store.GenerateSMTProof(ctx, deps.ProofSource,
		deps.Tree.Nodes(), deps.Tiles, deps.TileCache, root, key)
	if err != nil {
		switch {
		case errors.Is(err, smt.ErrUnknownRoot):
			if checkpointRaw != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError,
					"anchored checkpoint root not present in node store")
				deps.Logger.Error("smt proof: horizon root unknown (publish/tile-durability gate violated)",
					"root", hex.EncodeToString(root[:]), "source", string(deps.ProofSource))
			} else {
				writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
					http.StatusNotFound, "smt_root not found in node store")
			}
			return
		case errors.Is(err, smt.ErrNodeMissing):
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "interior node missing from node store")
			deps.Logger.Error("smt proof: interior node missing",
				"root", hex.EncodeToString(root[:]), "source", string(deps.ProofSource))
			return
		default:
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "proof generation failed")
			deps.Logger.Error("smt proof (as-of)", "error", err, "source", string(deps.ProofSource))
			return
		}
	}
	if mismatch {
		// Shadow evidence: a tile-served proof diverged from PG. Serve the
		// (PG) proof; surface the divergence for cutover gating.
		deps.Logger.Warn("smt proof shadow mismatch (pg vs tiles)", "key", hex.EncodeToString(key[:]))
	}
	typ := "non_membership"
	if proof.TerminalKind == types.SMTTerminalLeaf && proof.TerminalLeaf != nil && proof.TerminalLeaf.Key == key {
		typ = "membership"
	}
	resp := map[string]any{"type": typ, "proof": proof}
	if checkpointRaw != nil {
		// Additive third field; existing {type, proof} consumers ignore it.
		resp["checkpoint"] = json.RawMessage(checkpointRaw)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// serveLiveRootProof is the legacy path used when no horizon is wired and no
// explicit root is requested: proofs are generated at the live committed root
// (membership decided by a LeafStore pre-check). Retained verbatim for dev /
// test / unconfigured deployments; production wires a HorizonReader.
func serveLiveRootProof(ctx context.Context, w http.ResponseWriter, deps *SMTDeps, key [32]byte) {
	keyHex := hex.EncodeToString(key[:])
	leaf, _ := deps.Tree.GetLeaf(ctx, key)

	// ── A4c cutover: serve from tiles / shadow-compare ─────────────
	// pg (default/zero) falls through to the live-tree path below.
	if deps.ProofSource == store.SMTProofSourceTiles || deps.ProofSource == store.SMTProofSourceShadow {
		root, rErr := deps.Tree.Root(ctx)
		if rErr != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "current root unavailable")
			return
		}
		proof, mismatch, pErr := store.GenerateSMTProof(ctx, deps.ProofSource,
			deps.Tree.Nodes(), deps.Tiles, deps.TileCache, root, key)
		if pErr != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "proof generation failed")
			deps.Logger.Error("smt proof (tile source)", "error", pErr, "source", string(deps.ProofSource))
			return
		}
		if mismatch {
			// Shadow evidence: a tile-served proof diverged from PG.
			// Serve the (PG) proof; surface the divergence for cutover gating.
			deps.Logger.Warn("smt proof shadow mismatch (pg vs tiles)", "key", keyHex)
		}
		typ := "non_membership"
		if leaf != nil {
			typ = "membership"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"type": typ, "proof": proof})
		return
	}

	if leaf != nil {
		proof, pErr := deps.Tree.GenerateMembershipProof(ctx, key)
		if pErr != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "proof generation failed")
			deps.Logger.Error("membership proof", "error", pErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":  "membership",
			"proof": proof,
		})
		return
	}

	proof, err := deps.Tree.GenerateNonMembershipProof(ctx, key)
	if err != nil {
		writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
			http.StatusInternalServerError, "non-membership proof failed")
		deps.Logger.Error("non-membership proof", "error", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":  "non_membership",
		"proof": proof,
	})
}

// NewSMTBatchProofHandler creates POST /v1/smt/batch_proof.
//
// Body: {"keys": ["<hex>", ...]}, up to 1000 keys per request.
// Response: types.BatchProof with deduplicated SMTNodes covering
// every key's path from the SMT root. Verifier-side use:
// smt.VerifyBatchProof(proof, root).
func NewSMTBatchProofHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedBody,
				http.StatusBadRequest, "failed to read body")
			return
		}

		var req struct {
			Keys []string `json:"keys"`
		}
		if uErr := json.Unmarshal(body, &req); uErr != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedJSON,
				http.StatusBadRequest, "invalid JSON")
			return
		}
		if len(req.Keys) == 0 || len(req.Keys) > 1000 {
			writeTypedError(ctx, w, apitypes.ErrorClassBatchTooLarge,
				http.StatusBadRequest, "keys count must be 1-1000")
			return
		}

		keys := make([][32]byte, len(req.Keys))
		for i, kHex := range req.Keys {
			kb, dErr := hex.DecodeString(kHex)
			if dErr != nil || len(kb) != 32 {
				writeTypedError(ctx, w, apitypes.ErrorClassBadHexLength,
					http.StatusBadRequest, "each key must be 64 hex characters")
				return
			}
			copy(keys[i][:], kb)
		}

		proof, err := deps.Tree.GenerateBatchProof(ctx, keys)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
				http.StatusInternalServerError, "batch proof generation failed")
			deps.Logger.Error("batch proof", "error", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proof)
	}
}

// NewSMTRootHandler creates GET /v1/smt/root.
//
// Reads the authoritative root from deps.RootState (O(1)) when wired.
// Production wiring always sets RootState. When not wired (test
// fixtures), falls back to deps.Tree.Root which returns the tree's
// cached rootHash — still O(1) and consistent with the builder's
// in-memory state.
//
// # LIGHT-CLIENT WARNING (SDK v0.8.0+)
//
// The bytes served here carry NO cryptographic binding to the
// witness-cosigned tree head. An adversary on the read path
// could swap a forged root and produce membership proofs against
// it that pass every check OTHER than the witness signature.
//
// For trust-rooted SMT-root consumption, prefer /v1/tree/head's
// smt_root field — that value is bound into the witness K-of-N
// cosignature (baseproof SDK v0.8.0+; types.TreeHead.SMTRoot is in
// the cosign canonical payload). This handler remains for
// callers that already know the root they want (e.g. mid-batch
// proofs where the builder has advanced the SMT but witnesses
// haven't cosigned the new TreeSize yet).
func NewSMTRootHandler(deps *SMTDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var root [32]byte
		if deps.RootState != nil {
			r, err := deps.RootState.ReadRoot(ctx)
			if err != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "root state read failed")
				deps.Logger.Error("smt root: ReadRoot", "error", err)
				return
			}
			root = r
		} else {
			r, err := deps.Tree.Root(ctx)
			if err != nil {
				writeTypedError(ctx, w, apitypes.ErrorClassProofGenFailed,
					http.StatusInternalServerError, "root computation failed")
				deps.Logger.Error("smt root", "error", err)
				return
			}
			root = r
		}
		leafCount, _ := deps.LeafStore.Count(ctx)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"root":       hex.EncodeToString(root[:]),
			"leaf_count": leafCount,
		})
	}
}
