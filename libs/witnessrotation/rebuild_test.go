// FILE PATH: libs/witnessrotation/rebuild_test.go
//
// Tests for the scan-rebuild engine (rebuild.go) — the component that rebuilds a
// PROVEN witness-rotation chain from the LOG (never gossip). REAL cryptographic
// artifacts: real ECDSA witness sets, real dual-signed rotations, a real RFC
// 6962 tree (core/smt.StubMerkleTree) fed EntryIdentity leaves, real inclusion
// proofs against a real cosigned horizon. The LogSource seam is backed by a fake
// that serves from the real tree — so the proofs are genuine, only transport is
// faked.
package witnessrotation

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

var rebuildNetID = func() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 7)
	}
	return n
}()

const rbLogDID = "did:web:court.rebuild.test"

type setKit struct {
	set   *cosign.WitnessKeySet
	keys  []types.WitnessPublicKey
	privs []*ecdsa.PrivateKey
}

func newKit(t *testing.T, n, k int) setKit {
	t.Helper()
	keys := make([]types.WitnessPublicKey, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		p, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pub := signatures.PubKeyBytes(&p.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
		privs[i] = p
	}
	set, err := cosign.NewWitnessKeySet(keys, rebuildNetID, k, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	return setKit{set, keys, privs}
}

func rotation(t *testing.T, old, nw setKit, sig int) []byte {
	t.Helper()
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(nw.keys))
	sign := func(k setKit) []types.WitnessSignature {
		out := make([]types.WitnessSignature, sig)
		for i := 0; i < sig; i++ {
			sb, err := cosign.SignECDSA(payload, rebuildNetID, cosign.HashAlgoSHA256, k.privs[i])
			if err != nil {
				t.Fatalf("SignECDSA: %v", err)
			}
			out[i] = types.WitnessSignature{PubKeyID: k.keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
		}
		return out
	}
	rot := types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(old.keys),
		NewSet:            nw.keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		SchemeTagNew:      signatures.SchemeECDSA,
		CurrentSignatures: sign(old),
		NewSignatures:     sign(nw),
	}
	payloadBytes, err := witness.EncodeWitnessRotationPayload(rot)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	entry, err := envelope.NewEntry(
		envelope.ControlHeader{SignerDID: "did:web:ledger", Destination: "did:web:ledger"},
		payloadBytes,
		[]envelope.Signature{{SignerDID: "did:web:ledger", AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}},
	)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	canon, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return canon
}

// fakeLog is a LogSource backed by a REAL StubMerkleTree + a real cosigned
// horizon. Proofs are genuine; only the HTTP transport is replaced.
type fakeLog struct {
	tree      *smt.StubMerkleTree
	canonical map[uint64][]byte // seq -> rotation entry canonical (filler omitted)
	horizon   types.CosignedTreeHead
	// horizonSizeOverride, when nonzero, makes InclusionProofAt build proofs at a
	// DIFFERENT size than the horizon (to exercise the alignment guard).
	proofSizeOverride uint64
}

func (f *fakeLog) ScanRange(_ context.Context, start uint64, count int) ([]ScannedEntry, error) {
	var out []ScannedEntry
	for seq := start; seq < start+uint64(count) && seq < f.horizon.TreeSize; seq++ {
		c, ok := f.canonical[seq]
		if !ok {
			// filler entry: a non-rotation blob (the scanner must skip it)
			c = []byte(fmt.Sprintf("filler-%d", seq))
		}
		out = append(out, ScannedEntry{Sequence: seq, Canonical: c})
	}
	return out, nil
}

func (f *fakeLog) InclusionProofAtSize(_ context.Context, seq, treeSize uint64) (*types.MerkleProof, error) {
	size := treeSize
	if f.proofSizeOverride != 0 {
		size = f.proofSizeOverride
	}
	return f.tree.InclusionProof(nil, seq, size)
}

func (f *fakeLog) CosignedHorizon(_ context.Context) (types.CosignedTreeHead, error) {
	return f.horizon, nil
}

// buildFakeLog constructs a real tree with `rotations` dual-signed rotation
// entries at given filler gaps, and a horizon cosigned by `horizonKit`.
func buildFakeLog(t *testing.T, kits []setKit, fillBefore int, horizonKit setKit) *fakeLog {
	t.Helper()
	tree := smt.NewStubMerkleTree()
	canon := map[uint64][]byte{}
	leafID := func(b []byte) [32]byte { return sha256.Sum256(b) }
	appendBlob := func(b []byte) uint64 {
		id := leafID(b)
		pos, err := tree.AppendLeaf(id[:])
		if err != nil {
			t.Fatalf("AppendLeaf: %v", err)
		}
		return pos
	}
	for i := 0; i+1 < len(kits); i++ {
		for j := 0; j < fillBefore; j++ {
			appendBlob([]byte(fmt.Sprintf("filler-%d-%d", i, j)))
		}
		c := rotation(t, kits[i], kits[i+1], kits[i].set.Quorum())
		pos := appendBlob(c)
		canon[pos] = c
	}
	for j := 0; j < fillBefore; j++ {
		appendBlob([]byte(fmt.Sprintf("tail-%d", j)))
	}
	head, _ := tree.Head()
	th := types.TreeHead{RootHash: head.RootHash, SMTRoot: fill(0x5A), ReceiptRoot: fill(0x4C), TreeSize: head.TreeSize}
	horizon := cosignHead(t, th, horizonKit, horizonKit.set.Quorum())
	// Rewrite canonical-map keys to use sequences NOT shifted: AppendLeaf already
	// returns the true positions, so canon is correct as-is.
	return &fakeLog{tree: tree, canonical: canon, horizon: horizon}
}

func cosignHead(t *testing.T, th types.TreeHead, k setKit, sig int) types.CosignedTreeHead {
	t.Helper()
	payload := cosign.NewTreeHeadPayload(th)
	sigs := make([]types.WitnessSignature, sig)
	for i := 0; i < sig; i++ {
		sb, err := cosign.SignECDSA(payload, rebuildNetID, cosign.HashAlgoSHA256, k.privs[i])
		if err != nil {
			t.Fatalf("SignECDSA head: %v", err)
		}
		sigs[i] = types.WitnessSignature{PubKeyID: k.keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	return types.CosignedTreeHead{TreeHead: th, Signatures: sigs}
}

func fill(b byte) [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = b
	}
	return r
}

// TestRebuild_HappyPath_ProvenChainFeedsHistory: a real 2-rotation log rebuilds
// into proven records that NewVerifiedWitnessSetHistory accepts, and the history
// resolves the right set across the rotations.
func TestRebuild_HappyPath_ProvenChainFeedsHistory(t *testing.T) {
	const n, k = 5, 3
	s0, s1, s2 := newKit(t, n, k), newKit(t, n, k), newKit(t, n, k)
	// Horizon cosigned by s2 (the current set) — the realistic case.
	fl := buildFakeLog(t, []setKit{s0, s1, s2}, 200, s2)

	// The auditor anchors the rebuild on the set that cosigned the horizon (its
	// current trusted set, s2): the Rebuild's anchor check re-verifies the
	// horizon's K-of-N under that set, then every rotation's POSITION is proven
	// against the horizon. AUTHENTICITY from genesis is proven later by
	// WitnessSetAtHorizon's inductive walk.
	rb, err := NewRebuilder(Config{Src: fl, LogDID: rbLogDID, AnchorSet: s2.set})
	if err != nil {
		t.Fatalf("NewRebuilder: %v", err)
	}
	records, horizon, err := rb.Rebuild(context.Background())
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("rebuilt %d records, want 2 rotations", len(records))
	}
	if horizon.TreeSize == 0 {
		t.Fatal("horizon TreeSize zero")
	}
	if !records[0].EffectivePos.Less(records[1].EffectivePos) {
		t.Error("records not ascending by EffectivePos")
	}

	// The proven HORIZON records feed WitnessSetAtHorizon (genesis = s0): the
	// positions are proven against the shared horizon, authenticity inductively
	// from genesis. It must reconstruct s0 -> s1 -> s2 across the asOf boundary.
	s1Set, _ := cosign.NewWitnessKeySet(s1.keys, s0.set.NetworkID(), s0.set.Quorum(), s0.set.BLSVerifier())
	s2Set, _ := cosign.NewWitnessKeySet(s2.keys, s0.set.NetworkID(), s0.set.Quorum(), s0.set.BLSVerifier())
	at := func(seq uint64) *cosign.WitnessKeySet {
		set, aerr := witness.WitnessSetAtHorizon(s0.set, records, horizon.TreeHead,
			types.LogPosition{LogDID: rbLogDID, Sequence: seq})
		if aerr != nil {
			t.Fatalf("WitnessSetAtHorizon(%d): %v", seq, aerr)
		}
		return set
	}
	r0, r1 := records[0].EffectivePos.Sequence, records[1].EffectivePos.Sequence
	if at(r0-1).SetHash() != s0.set.SetHash() {
		t.Error("before R1 must be genesis s0")
	}
	if at(r0).SetHash() != s1Set.SetHash() {
		t.Error("at R1 must be s1")
	}
	if at(r1).SetHash() != s2Set.SetHash() {
		t.Error("at R2 must be s2")
	}
}

// TestRebuild_SkipsNonRotationEntries: filler entries must be skipped (only
// rotation-kind entries become records).
func TestRebuild_SkipsNonRotationEntries(t *testing.T) {
	const n, k = 5, 3
	s0, s1 := newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1}, 300, s1) // 300 filler + 1 rotation + 300 tail
	rb, _ := NewRebuilder(Config{Src: fl, LogDID: rbLogDID, AnchorSet: s1.set})
	records, _, err := rb.Rebuild(context.Background())
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records over a log of ~601 entries; want exactly 1 rotation", len(records))
	}
}

// TestRebuild_UncosignedHorizonRejected: a horizon NOT cosigned by the anchor
// set fails closed (ErrHorizonNotCosigned) — the trust anchor is unauthenticated.
func TestRebuild_UncosignedHorizonRejected(t *testing.T) {
	const n, k = 5, 3
	s0, s1 := newKit(t, n, k), newKit(t, n, k)
	alien := newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1}, 100, alien) // horizon cosigned by an unrelated set
	rb, _ := NewRebuilder(Config{Src: fl, LogDID: rbLogDID, AnchorSet: s0.set})
	_, _, err := rb.Rebuild(context.Background())
	if !errors.Is(err, ErrHorizonNotCosigned) {
		t.Fatalf("err = %v, want ErrHorizonNotCosigned", err)
	}
}

// TestRebuild_ProofTreeSizeMismatchRejected: if the ledger serves an inclusion
// proof at a size != the horizon, the rebuild fails closed
// (ErrRotationProofMismatch) rather than trust a non-horizon-aligned proof.
func TestRebuild_ProofTreeSizeMismatchRejected(t *testing.T) {
	const n, k = 5, 3
	s0, s1 := newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1}, 100, s1)
	fl.proofSizeOverride = fl.horizon.TreeSize - 1 // misaligned proof
	rb, _ := NewRebuilder(Config{Src: fl, LogDID: rbLogDID, AnchorSet: s1.set})
	_, _, err := rb.Rebuild(context.Background())
	if !errors.Is(err, ErrRotationProofMismatch) {
		t.Fatalf("err = %v, want ErrRotationProofMismatch", err)
	}
}

// TestNewRebuilder_Validation: nil src, empty logDID, nil/empty genesis rejected.
func TestNewRebuilder_Validation(t *testing.T) {
	s0 := newKit(t, 3, 2)
	fl := &fakeLog{}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil src", Config{LogDID: rbLogDID, AnchorSet: s0.set}},
		{"empty logDID", Config{Src: fl, AnchorSet: s0.set}},
		{"nil genesis", Config{Src: fl, LogDID: rbLogDID}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewRebuilder(c.cfg); err == nil {
				t.Errorf("%s accepted; want error", c.name)
			}
		})
	}
}

// TestRebuildWindow_IncrementalSuffix: a window scan starting past R1 finds
// ONLY R2 — the bounded [cursor, target) pass the scan reconciler drives.
func TestRebuildWindow_IncrementalSuffix(t *testing.T) {
	const n, k = 5, 3
	s0, s1, s2 := newKit(t, n, k), newKit(t, n, k), newKit(t, n, k)
	fl := buildFakeLog(t, []setKit{s0, s1, s2}, 50, s2)
	rb, err := NewRebuilder(Config{Src: fl, LogDID: rbLogDID, AnchorSet: s2.set})
	if err != nil {
		t.Fatalf("NewRebuilder: %v", err)
	}
	full, _, err := rb.Rebuild(context.Background())
	if err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	if len(full) != 2 {
		t.Fatalf("full scan found %d rotations, want 2", len(full))
	}
	// Start just past R1: only R2 is in the window.
	window, err := rb.RebuildWindow(context.Background(), full[0].EffectivePos.Sequence+1, fl.horizon)
	if err != nil {
		t.Fatalf("RebuildWindow: %v", err)
	}
	if len(window) != 1 || window[0].EffectivePos != full[1].EffectivePos {
		t.Fatalf("window = %+v, want exactly R2 at %v", window, full[1].EffectivePos)
	}
}
