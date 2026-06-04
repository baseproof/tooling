/*
FILE PATH:

	api/bundle.go

DESCRIPTION:

	Part II.1 — GET /v1/bundle/{seq}?smt_key=hex.

	Assembles a v1 baseproof-bundle (SDK log/bundle.Bundle) for the
	entry at the requested sequence. Composes:

	  - BootstrapDocument (from cfg.GenesisBootstrapDocument)
	  - Entry wire bytes + log_time (from EntryFetcher)
	  - CosignedTreeHead (from TreeHeadStore.Latest)
	  - InclusionProof (from TesseraAdapter.TypedInclusionProof)
	  - SMTProof at the caller-supplied {smt_key} (from
	    smt.Tree.Prove)
	  - WitnessSetHint{SetHash} (from cosign.SetHash over the
	    current WitnessKeySet)

	The bundle is JCS-canonical (log/bundle/Encode produces the
	canonical wire form); a consumer running log/bundle/Decode +
	VerifyBundle reproduces every cryptographic check
	independently — no callback to this ledger required after
	download.

	?smt_key=hex is REQUIRED. The bundle's SMT proof must be a
	PRESENCE proof (TerminalLeaf != nil) for VerifyBundle to
	accept it (plan §I.1 / log/bundle/verify.go:185). The mapping
	from entry → SMT key is domain-specific; pushing the key into
	the query string lets consumers pick which leaf they want
	bound to the entry without the ledger inventing a mapping.
	An entry with no SMT effect (e.g., a commentary entry) is not
	bundle-able under VerifyBundle's contract; the caller's 400
	on missing/invalid smt_key signals the upstream check.

KEY ARCHITECTURAL DECISIONS:

  - CONTENT-DETERMINISTIC. The same (seq, smt_key, head)
    produces byte-identical bundles. max-age=31536000, immutable
    after the head is cosigned — historical bundles never
    change.

  - Composition via SDK log/bundle.BuildBundle through the
    BundleFetcher interface. api/ provides an inProcessFetcher
    adapter that closes over the local store/fetcher handles;
    api/ stays pgx-free at the boundary.

  - The fetcher does NOT issue HTTP calls. Every byte the SDK
    BuildBundle needs is already in this binary's address space.

    Plan §I.1 / §II.1.
*/
package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// BundleEntryFetcher is the api/ → entry-bytes surface. Returns the
// raw envelope wire bytes at a sequence plus the ledger's stamped
// log_time. nil bytes + nil error MUST NOT happen — callers
// expect (bytes, time, nil) on success and a typed error on
// not-found.
type BundleEntryFetcher interface {
	FetchEntryBytes(ctx context.Context, seq uint64) ([]byte, time.Time, error)
}

// BundleHeadFetcher is the api/ → cosigned-head surface. Returns
// the most-recent cosigned tree head ≥ seq. The SDK's BuildBundle
// uses the returned head's TreeSize as the inclusion-proof anchor
// and its SMTRoot as the SMT-proof anchor.
type BundleHeadFetcher interface {
	FetchCosignedHead(ctx context.Context, seq uint64) (types.CosignedTreeHead, error)
}

// BundleInclusionFetcher is the api/ → inclusion-proof surface.
// Mirrors TreeProofFetcher.RawInclusionProof but returns the
// SDK's typed types.MerkleProof so the bundle assembler can
// embed it directly.
type BundleInclusionFetcher interface {
	FetchInclusionProof(ctx context.Context, seq, treeSize uint64) (*types.MerkleProof, error)
}

// BundleSMTFetcher is the api/ → SMT-proof surface. Returns the
// presence (or non-presence) proof for the supplied 32-byte key
// against the supplied SMT root. The bundle assembler binds the
// returned proof to the CosignedTreeHead.SMTRoot — a mismatched
// root surfaces as a verification failure downstream.
type BundleSMTFetcher interface {
	FetchSMTProof(ctx context.Context, key, smtRoot [32]byte) (types.SMTProof, error)
}

// BundleWitnessSetHashFetcher computes the cosign.SetHash of the
// witness key set that cosigned the supplied head. Implementations
// typically derive the set hash from the head's signatures (the
// PubKeyIDs identify the set members) or query the witness_sets
// history table by effective_seq ≤ head.TreeSize.
type BundleWitnessSetHashFetcher interface {
	FetchWitnessSetHash(ctx context.Context, head types.CosignedTreeHead) ([32]byte, error)
}

// BundleDeps groups the four fetchers a bundle assembler needs.
// cmd/ledger constructs each adapter at boot and hands them to
// NewBundleHandler.
type BundleDeps struct {
	Bootstrap network.BootstrapDocument

	Entries   BundleEntryFetcher
	Heads     BundleHeadFetcher
	Inclusion BundleInclusionFetcher
	SMT       BundleSMTFetcher
	Witnesses BundleWitnessSetHashFetcher
}

// inProcessFetcher implements sdkbundle.BundleFetcher by closing
// over BundleDeps. The fetcher's per-field methods are pure
// composition; no HTTP, no out-of-process calls.
type inProcessFetcher struct {
	deps   BundleDeps
	smtKey [32]byte // captured per-request (one fetcher per request)
}

func (f *inProcessFetcher) FetchBootstrap(ctx context.Context) (*network.BootstrapDocument, error) {
	doc := f.deps.Bootstrap // value copy — caller MUST NOT mutate
	return &doc, nil
}

func (f *inProcessFetcher) FetchEntry(ctx context.Context, seq uint64) ([]byte, time.Time, error) {
	return f.deps.Entries.FetchEntryBytes(ctx, seq)
}

func (f *inProcessFetcher) FetchCosignedHead(ctx context.Context, seq uint64) (types.CosignedTreeHead, error) {
	return f.deps.Heads.FetchCosignedHead(ctx, seq)
}

func (f *inProcessFetcher) FetchInclusionProof(ctx context.Context, seq, treeSize uint64) (types.MerkleProof, error) {
	p, err := f.deps.Inclusion.FetchInclusionProof(ctx, seq, treeSize)
	if err != nil {
		return types.MerkleProof{}, err
	}
	if p == nil {
		return types.MerkleProof{}, fmt.Errorf("api/bundle: nil inclusion proof")
	}
	return *p, nil
}

func (f *inProcessFetcher) FetchSMTProof(ctx context.Context, seq uint64, smtRoot [32]byte) (types.SMTProof, error) {
	return f.deps.SMT.FetchSMTProof(ctx, f.smtKey, smtRoot)
}

func (f *inProcessFetcher) FetchWitnessSetHash(ctx context.Context, head types.CosignedTreeHead) ([32]byte, error) {
	return f.deps.Witnesses.FetchWitnessSetHash(ctx, head)
}

// NewBundleHandler returns the GET /v1/bundle/{seq}?smt_key=hex
// handler. Nil deps → handler 503 (the binary's bundle assembly
// path is not wired — degraded mode); empty Bootstrap → handler
// 404 (no genesis document means no NetworkID-bound bundle is
// constructible).
//
// Cache-Control: public, max-age=31536000, immutable. A bundle
// is content-deterministic once the cosigned head it anchors on
// has been published.
func NewBundleHandler(deps *BundleDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil {
			http.Error(w, "bundle assembly not configured", http.StatusServiceUnavailable)
			return
		}
		if deps.Bootstrap.NetworkName == "" {
			http.Error(w, "bundle assembly requires a bootstrap document", http.StatusNotFound)
			return
		}

		// Parse seq path param.
		seqRaw := strings.TrimSpace(r.PathValue("seq"))
		seq, err := strconv.ParseUint(seqRaw, 10, 64)
		if err != nil {
			http.Error(w, "seq must be a non-negative integer", http.StatusBadRequest)
			return
		}

		// Parse smt_key query param.
		keyRaw := strings.TrimSpace(r.URL.Query().Get("smt_key"))
		if keyRaw == "" {
			http.Error(w,
				"smt_key query parameter required (64-char lowercase hex)",
				http.StatusBadRequest)
			return
		}
		keyBytes, err := hex.DecodeString(keyRaw)
		if err != nil || len(keyBytes) != 32 {
			http.Error(w, "smt_key must be 64-char lowercase hex", http.StatusBadRequest)
			return
		}
		var smtKey [32]byte
		copy(smtKey[:], keyBytes)

		// Build the in-process fetcher; invoke the SDK's
		// BuildBundle. Errors from the fetcher's per-field
		// methods bubble up wrapped by BuildBundle.
		fetcher := &inProcessFetcher{deps: *deps, smtKey: smtKey}
		bundle, err := sdkbundle.BuildBundle(r.Context(), fetcher, seq)
		if err != nil {
			// Distinguish "entry not found" from other failures
			// — the bundle build wraps every error; we surface
			// the inner sentinel via errors.Is.
			if errors.Is(err, sdkbundle.ErrBundleBuildSequenceMismatch) {
				http.Error(w, fmt.Sprintf("bundle build failed: %v", err),
					http.StatusInternalServerError)
				return
			}
			http.Error(w, fmt.Sprintf("bundle build failed: %v", err),
				http.StatusInternalServerError)
			return
		}

		// Encode the JCS-canonical bundle bytes.
		bs, err := sdkbundle.Encode(bundle)
		if err != nil {
			http.Error(w, fmt.Sprintf("bundle encode failed: %v", err),
				http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bs)
	}
}
