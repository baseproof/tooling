/*
FILE PATH: cmd/ledger/boot/wire/bundle_adapters.go

DESCRIPTION:

	Part II.1 group D follow-up — production wiring of the
	bundle assembly path. The api package owns the GET
	/v1/bundle/{seq} handler (api/bundle.go) and declares five
	narrow fetcher interfaces (BundleEntryFetcher,
	BundleHeadFetcher, BundleInclusionFetcher, BundleSMTFetcher,
	BundleWitnessSetHashFetcher). This file composes the
	adapters that wrap existing ledger handles into those
	interfaces; api/ stays pgx-free and witnessclient-free at
	the boundary.

	The bundle assembly is in-process: every byte the SDK's
	log/bundle.BuildBundle needs is already in this binary's
	address space — no HTTP, no out-of-process calls.

WIRE MAP:

	BundleEntryFetcher           ← store.PostgresEntryFetcher.Fetch
	BundleHeadFetcher            ← treeHeadStoreCosignedAdapter
	                               (the same adapter II.9 wires
	                               for the parent-anchor flow)
	BundleInclusionFetcher       ← tessera.TesseraAdapter.
	                               TypedInclusionProof
	BundleSMTFetcher             ← smt.GenerateProofAt over
	                               smt.Tree.Nodes() + the
	                               cosigned SMT root
	BundleWitnessSetHashFetcher  ← witnessclient.HistoryFetcher.
	                               LoadSetAtSeq(head.TreeSize)
	                               → SetHash (already
	                               cosign.SetHash from the II.2
	                               history table).

ALIGNMENT WITH PRODUCT GOALS:

  - #4 cross-log attestation/verification — the bundle is the
    transport that lets a Judicial Network verifier confirm a
    cross-network field reference offline.
  - #5 Tessera-native S3/object store evidence — the inclusion
    proof reads via TesseraAdapter (which pulls tile bytes from
    the configured TileBackend).
  - #6 Zero-Trust — every byte the bundle ships is independently
    verifiable by the consumer via log/bundle.VerifyBundle. No
    field requires trusting this ledger; the bundle's NetworkID
    binds to the BootstrapDocument, the inclusion proof binds to
    the cosigned head's RootHash, the SMT proof binds to the
    cosigned head's SMTRoot, and the witness set hash resolves
    via the consumer's own /v1/network/witnesses/{set_hash}
    lookup.
  - #11 Bundle-format wire freeze — the SDK's
    log/bundle.Encode produces the JCS-canonical bytes; this
    handler serves them verbatim.
  - #13 Witness rotation without breaking historical bundles —
    the witness_set_hash field in the bundle points at the
    set ACTIVE at head.TreeSize (resolved via II.2's
    LoadSetAtSeq, which is the time-travel primitive over the
    witness_sets history table).
*/
package wire

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/network"
	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// ─────────────────────────────────────────────────────────────────────
// BundleEntryFetcher — entry wire bytes + log_time
// ─────────────────────────────────────────────────────────────────────

// bundleEntries wraps store.PostgresEntryFetcher.Fetch over a
// LogPosition built from (logDID, seq). The adapter returns
// CanonicalBytes + LogTime; the SDK's BuildBundle binds the bytes
// via envelope.OnLogEntryLeafHash (= H(0x00 || SHA-256(canonical)),
// the on-log-entry leaf the ledger's Tessera tree commits).
type bundleEntries struct {
	fetcher *store.PostgresEntryFetcher
	logDID  string
}

func (a *bundleEntries) FetchEntryBytes(ctx context.Context, seq uint64) ([]byte, time.Time, error) {
	pos := sdktypes.LogPosition{LogDID: a.logDID, Sequence: seq}
	entry, err := a.fetcher.Fetch(ctx, pos)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bundle: fetch entry %d: %w", seq, err)
	}
	if entry == nil {
		return nil, time.Time{}, fmt.Errorf("bundle: entry %d not found", seq)
	}
	return entry.CanonicalBytes, entry.LogTime, nil
}

// ─────────────────────────────────────────────────────────────────────
// BundleHeadFetcher — most-recent cosigned tree head ≥ seq
// ─────────────────────────────────────────────────────────────────────

// bundleHeads adapts treeHeadStoreCosignedAdapter (defined in
// wire.go for the II.9 parent-anchor flow). The bundle assembly
// requires a cosigned head that is current AS-OF (≥) the entry's
// seq; the simplest correct shape returns the LATEST cosigned
// head — historical bundles still anchor at the most recent head
// (the inclusion proof + SMT proof are both constructed against
// that head's TreeSize / SMTRoot). A nil head means no cosigned
// head has been published yet (pre-first-witness-round); the
// handler surfaces this as a 500 rather than serving a bundle
// against the live (uncosigned) root, which would be
// cryptographically invalid by VerifyBundle's contract.
type bundleHeads struct {
	heads treeHeadStoreCosignedAdapter
}

func (a *bundleHeads) FetchCosignedHead(ctx context.Context, _ uint64) (sdktypes.CosignedTreeHead, error) {
	head, err := a.heads.LatestCosigned(ctx)
	if err != nil {
		return sdktypes.CosignedTreeHead{}, fmt.Errorf("bundle: fetch cosigned head: %w", err)
	}
	if head == nil {
		return sdktypes.CosignedTreeHead{}, fmt.Errorf("bundle: no cosigned head available (pre-first-witness-round)")
	}
	return *head, nil
}

// ─────────────────────────────────────────────────────────────────────
// BundleInclusionFetcher — RFC 6962 inclusion proof
// ─────────────────────────────────────────────────────────────────────

// bundleInclusion wraps tessera.TesseraAdapter.TypedInclusionProof,
// which returns the SDK's *types.MerkleProof directly. The
// untyped-shape RawInclusionProof is for the JSON-encoding
// /v1/tree/inclusion handler. LeafHash is left zero by
// TypedInclusionProof; SDK BuildBundle binds it from
// envelope.OnLogEntryLeafHash against the fetched entry — the
// bundle handler's defense-in-depth check.
type bundleInclusion struct {
	adapter *tessera.TesseraAdapter
}

func (a *bundleInclusion) FetchInclusionProof(_ context.Context, seq, treeSize uint64) (*sdktypes.MerkleProof, error) {
	return a.adapter.TypedInclusionProof(seq, treeSize)
}

// ─────────────────────────────────────────────────────────────────────
// BundleSMTFetcher — Jellyfish SMT proof against the cosigned root
// ─────────────────────────────────────────────────────────────────────

// bundleSMT calls smt.GenerateProofAt against the cosigned head's
// SMTRoot — the historical primitive that reads ONLY the
// NodeStore (never the live LeafStore) so the proof is a
// deterministic function of (nodes, root, key). A proof against
// a past cosigned SMTRoot reproduces identically forever,
// independent of current leaf state.
type bundleSMT struct {
	tree *smt.Tree
}

func (a *bundleSMT) FetchSMTProof(_ context.Context, key, smtRoot [32]byte) (sdktypes.SMTProof, error) {
	proof, err := smt.GenerateProofAt(a.tree.Nodes(), smtRoot, key)
	if err != nil {
		return sdktypes.SMTProof{}, fmt.Errorf("bundle: SMT proof at root %x key %x: %w",
			smtRoot[:4], key[:4], err)
	}
	if proof == nil {
		return sdktypes.SMTProof{}, fmt.Errorf("bundle: GenerateProofAt returned nil proof (root=%x key=%x)",
			smtRoot[:4], key[:4])
	}
	return *proof, nil
}

// ─────────────────────────────────────────────────────────────────────
// BundleWitnessSetHashFetcher — cosign.SetHash via II.2 history table
// ─────────────────────────────────────────────────────────────────────

// bundleWitnessSetHash resolves the cosign.SetHash via the
// witness_sets history table — the same Part II.2 surface the
// /v1/network/witnesses/at endpoint reads. The history row's
// set_hash IS cosign.SetHash (computed at rotation time by
// witnessclient.RotationHandler), so the adapter just looks up
// the row active at head.TreeSize and decodes its SetHash hex
// into the [32]byte the bundle assembler wants.
//
// This is the genuinely-new code in II.1 group D wiring — the
// other four fetchers reuse adapters built for adjacent
// features. The design choice (table lookup vs. on-the-fly
// derivation from the head's signature PubKeyIDs) favors the
// table because:
//
//   - The PubKeyIDs in the head's signatures identify which
//     witnesses signed THIS head, not which witnesses are
//     CURRENTLY in the set; a partial-quorum head would miss
//     members. The set_hash is defined over ALL members, not
//     just the signers.
//   - The II.2 table row is keyed by effective_seq — the right
//     time-travel primitive when the head is from a historical
//     seq.
//   - The table row carries the set_hash that was COMPUTED at
//     rotation time via cosign.SetHash on the FULL set; the wire
//     contract guarantees this byte sequence is what the SDK's
//     log/bundle.VerifyBundle will look up via the consumer's
//     /v1/network/witnesses/{set_hash} round-trip.
//
// Goal #13 (witness rotation without breaking historical
// bundles) hinges on this: the bundle's witness_set_hash is the
// set ACTIVE at head.TreeSize, NOT the current set. A bundle
// minted in year-1 against witness-set-A continues to verify in
// year-20 even after a year-10 rotation to witness-set-B, because
// the consumer's /v1/network/witnesses/{set_hash} lookup
// resolves the historical set-A row.
type bundleWitnessSetHash struct {
	history *witnessclient.HistoryFetcher
}

func (a *bundleWitnessSetHash) FetchWitnessSetHash(ctx context.Context, head sdktypes.CosignedTreeHead) ([32]byte, error) {
	view, err := a.history.LoadSetAtSeq(ctx, head.TreeSize)
	if err != nil {
		return [32]byte{}, fmt.Errorf("bundle: load witness set at tree_size %d: %w",
			head.TreeSize, err)
	}
	hashBytes, err := hex.DecodeString(view.SetHash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("bundle: decode witness set hash %q: %w",
			view.SetHash, err)
	}
	if len(hashBytes) != 32 {
		return [32]byte{}, fmt.Errorf("bundle: witness set hash length %d, want 32",
			len(hashBytes))
	}
	var out [32]byte
	copy(out[:], hashBytes)
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// Composition
// ─────────────────────────────────────────────────────────────────────

// buildBundleDeps composes the BundleDeps struct the
// api.NewBundleHandler consumes. An empty bootstrap document —
// no NetworkName means a test / no-bootstrap-file deployment —
// returns nil deps, so the handler stays in 503 (bundle assembly
// not configured) rather than failing at the first request.
//
// All five adapters are independently nil-safe at construction:
// each panics or errors at FIRST USE if its captured handle is
// nil. This is the pattern used by every other Wire() adapter
// composition in this package — fail-fast at use time rather
// than guarded-construction-with-silent-degradation.
func buildBundleDeps(
	doc network.BootstrapDocument,
	entries *store.PostgresEntryFetcher,
	heads treeHeadStoreCosignedAdapter,
	inclusion *tessera.TesseraAdapter,
	tree *smt.Tree,
	history *witnessclient.HistoryFetcher,
	logDID string,
) *api.BundleDeps {
	if doc.NetworkName == "" {
		return nil
	}
	return &api.BundleDeps{
		Bootstrap: doc,
		Entries:   &bundleEntries{fetcher: entries, logDID: logDID},
		Heads:     &bundleHeads{heads: heads},
		Inclusion: &bundleInclusion{adapter: inclusion},
		SMT:       &bundleSMT{tree: tree},
		Witnesses: &bundleWitnessSetHash{history: history},
	}
}
