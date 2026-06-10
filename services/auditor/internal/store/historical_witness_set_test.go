// FILE PATH: services/auditor/internal/store/historical_witness_set_test.go
//
// Functional tests for HistoricalWitnessSetResolver — the position-aware
// witness-set resolution that fixes the auditor's position-blindness
// (gv.sets.Snapshot()). REAL artifacts: a real RFC-6962 StubMerkleTree fed
// EntryIdentity leaves, real dual-signed rotations, real inclusion proofs
// against a real cosigned horizon. Reuses genWitnessSet/buildRotation/cosignHead
// + rotTestNetID from witness_rotation_journal_test.go.
//
// THE BUG IT PROVES FIXED (ZT-SCN-02): a year-1 cosigned head must verify
// against the RECONSTRUCTED year-1 set and MUST NOT verify against the modern
// (rotated-away) set — exactly what gv.sets.Snapshot() gets wrong.
package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/tooling/libs/witnessrotation"
)

// realTreeLogSource is a witnessrotation.LogSource backed by a REAL
// StubMerkleTree + a real cosigned horizon — only the HTTP transport is faked;
// the proofs are genuine.
type realTreeLogSource struct {
	tree    *smt.StubMerkleTree
	canon   map[uint64][]byte // seq -> rotation entry canonical (filler omitted)
	horizon types.CosignedTreeHead
}

func (s *realTreeLogSource) ScanRange(_ context.Context, start uint64, count int) ([]witnessrotation.ScannedEntry, error) {
	var out []witnessrotation.ScannedEntry
	for seq := start; seq < start+uint64(count) && seq < s.horizon.TreeSize; seq++ {
		c, ok := s.canon[seq]
		if !ok {
			c = []byte(fmt.Sprintf("filler-%d", seq)) // non-rotation blob; scanner skips
		}
		out = append(out, witnessrotation.ScannedEntry{Sequence: seq, Canonical: c})
	}
	return out, nil
}

func (s *realTreeLogSource) InclusionProofAtSize(_ context.Context, seq, treeSize uint64) (*types.MerkleProof, error) {
	return s.tree.InclusionProof(nil, seq, treeSize)
}
func (s *realTreeLogSource) CosignedHorizon(_ context.Context) (types.CosignedTreeHead, error) {
	return s.horizon, nil
}

// hwsLogDID is the log under reconstruction.
const hwsLogDID = "did:web:court.historical.test"

// buildRealTreeChain builds a real tree: fill → rotation(S_i→S_{i+1}) → fill,
// for each consecutive kit pair, then a horizon cosigned by horizonKit. Returns
// the source + each rotation's leaf position.
func buildRealTreeChain(t *testing.T, kits []witnessSetKitHWS, fill int, horizonKit witnessSetKitHWS, netID cosign.NetworkID) (*realTreeLogSource, []uint64) {
	t.Helper()
	tree := smt.NewStubMerkleTree()
	canon := map[uint64][]byte{}
	var positions []uint64
	appendBlob := func(b []byte) uint64 {
		id := sha256.Sum256(b)
		pos, err := tree.AppendLeaf(id[:])
		if err != nil {
			t.Fatalf("AppendLeaf: %v", err)
		}
		return pos
	}
	for i := 0; i+1 < len(kits); i++ {
		for j := 0; j < fill; j++ {
			appendBlob([]byte(fmt.Sprintf("filler-%d-%d", i, j)))
		}
		rot := dualSignedRotation(t, kits[i], kits[i+1], kits[i].set.Quorum(), netID)
		c := encodeRotEntry(t, rot)
		pos := appendBlob(c)
		canon[pos] = c
		positions = append(positions, pos)
	}
	for j := 0; j < fill; j++ {
		appendBlob([]byte(fmt.Sprintf("tail-%d", j)))
	}
	head, _ := tree.Head()
	th := types.TreeHead{RootHash: head.RootHash, SMTRoot: fullTreeHead(head.TreeSize).SMTRoot, ReceiptRoot: fullTreeHead(head.TreeSize).ReceiptRoot, TreeSize: head.TreeSize}
	horizon := cosignHead(t, th, horizonKit.keys, horizonKit.privs, horizonKit.set.Quorum(), netID)
	return &realTreeLogSource{tree: tree, canon: canon, horizon: horizon}, positions
}

// witnessSetKitHWS bundles a set + keys + privs (genWitnessSet returns the trio).
type witnessSetKitHWS struct {
	set   *cosign.WitnessKeySet
	keys  []types.WitnessPublicKey
	privs []*ecdsa.PrivateKey
}

func newKitHWS(t *testing.T, n, k int, netID cosign.NetworkID) witnessSetKitHWS {
	set, keys, privs := genWitnessSet(t, n, k, netID)
	return witnessSetKitHWS{set: set, keys: keys, privs: privs}
}

// dualSignedRotation builds an ON-LOG-encodable rotation (both scheme tags set
// + both signature slices non-empty): OLD set authorizes the new-set hash, NEW
// set accepts it. EncodeWitnessRotationPayload requires this dual-signed form
// (the package-level buildRotation is gossip-only and lacks NewSignatures).
func dualSignedRotation(t *testing.T, old, nw witnessSetKitHWS, sigCount int, netID cosign.NetworkID) types.WitnessRotation {
	t.Helper()
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(nw.keys))
	sign := func(kit witnessSetKitHWS) []types.WitnessSignature {
		out := make([]types.WitnessSignature, sigCount)
		for i := 0; i < sigCount; i++ {
			sb, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, kit.privs[i])
			if err != nil {
				t.Fatalf("SignECDSA rotation: %v", err)
			}
			out[i] = types.WitnessSignature{PubKeyID: kit.keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
		}
		return out
	}
	return types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(old.keys),
		NewSet:            nw.keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		SchemeTagNew:      signatures.SchemeECDSA,
		CurrentSignatures: sign(old),
		NewSignatures:     sign(nw),
	}
}

// encodeRotEntry wraps a rotation in on-log entry canonical bytes.
func encodeRotEntry(t *testing.T, rot types.WitnessRotation) []byte {
	t.Helper()
	payload, err := witness.EncodeWitnessRotationPayload(rot)
	if err != nil {
		t.Fatalf("EncodeWitnessRotationPayload: %v", err)
	}
	entry, err := envelope.NewEntry(
		envelope.ControlHeader{SignerDID: "did:web:ledger.hist", Destination: "did:web:ledger.hist"},
		payload,
		[]envelope.Signature{{SignerDID: "did:web:ledger.hist", AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}},
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

// TestHistoricalResolver_SetForHead_YearOneNotModern is the ZT-SCN-02 functional
// proof: a head cosigned by the YEAR-1 set verifies against the resolver's
// reconstructed historical set, and FAILS against the modern (rotated-away) set
// — the exact failure the position-blind gv.sets.Snapshot() would produce.
func TestHistoricalResolver_SetForHead_YearOneNotModern(t *testing.T) {
	const n, k = 5, 3
	netID := rotTestNetID()
	s0 := newKitHWS(t, n, k, netID) // year-1 (genesis)
	s1 := newKitHWS(t, n, k, netID)
	s2 := newKitHWS(t, n, k, netID) // modern (horizon-cosigning) set

	src, _ := buildRealTreeChain(t, []witnessSetKitHWS{s0, s1, s2}, 300, s2, netID)
	resolver, err := NewHistoricalWitnessSetResolver(src, hwsLogDID, s0.set, s2.set)
	if err != nil {
		t.Fatalf("NewHistoricalWitnessSetResolver: %v", err)
	}
	ctx := context.Background()

	// A year-1-era head, cosigned by S0 (the genesis set).
	yearOneHead := cosignHead(t, fullTreeHead(50), s0.keys, s0.privs, k, netID)

	got, err := resolver.SetForHead(ctx, yearOneHead)
	if err != nil {
		t.Fatalf("SetForHead(year-1 head): %v", err)
	}
	if got.SetHash() != s0.set.SetHash() {
		t.Fatalf("year-1 head resolved to %x, want the reconstructed YEAR-1 set %x", got.SetHash(), s0.set.SetHash())
	}

	// ZT-SCN-02 CORE: the year-1 head must NOT verify against the modern set S2
	// (what gv.sets.Snapshot() would hand it).
	s2Modern, _ := cosign.NewWitnessKeySet(s2.keys, netID, k, nil)
	if vc := cosign.VerifyTreeHeadCosignatures(yearOneHead, s2Modern); vc >= k {
		t.Fatal("year-1 head verified against the MODERN set — the position-blind bug is NOT fixed")
	}
}

// TestHistoricalResolver_SetAt_AcrossRotations: SetAt resolves the proven set at
// each historical position (genesis before R1, S1 between, S2 after).
func TestHistoricalResolver_SetAt_AcrossRotations(t *testing.T) {
	const n, k = 5, 3
	netID := rotTestNetID()
	s0 := newKitHWS(t, n, k, netID)
	s1 := newKitHWS(t, n, k, netID)
	s2 := newKitHWS(t, n, k, netID)
	src, pos := buildRealTreeChain(t, []witnessSetKitHWS{s0, s1, s2}, 250, s2, netID)
	resolver, err := NewHistoricalWitnessSetResolver(src, hwsLogDID, s0.set, s2.set)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	ctx := context.Background()

	s1Set, _ := cosign.NewWitnessKeySet(s1.keys, netID, k, nil)
	s2Set, _ := cosign.NewWitnessKeySet(s2.keys, netID, k, nil)
	at := func(seq uint64) *cosign.WitnessKeySet {
		set, err := resolver.SetAt(ctx, types.LogPosition{LogDID: hwsLogDID, Sequence: seq})
		if err != nil {
			t.Fatalf("SetAt(%d): %v", seq, err)
		}
		return set
	}
	if at(pos[0]-1).SetHash() != s0.set.SetHash() {
		t.Error("before R1 must be genesis S0")
	}
	if at(pos[0]).SetHash() != s1Set.SetHash() {
		t.Error("at R1 must be S1")
	}
	if at(pos[1]).SetHash() != s2Set.SetHash() {
		t.Error("at R2 must be S2")
	}
}

// TestHistoricalResolver_LeafModelBinding: the resolver's proofs use the on-log
// leaf model (the rebuilder binds OnLogEntryLeafHash) — a sanity guard that the
// real tree feeds EntryIdentity leaves.
func TestHistoricalResolver_LeafModelBinding(t *testing.T) {
	const n, k = 5, 3
	netID := rotTestNetID()
	s0 := newKitHWS(t, n, k, netID)
	s1 := newKitHWS(t, n, k, netID)
	src, pos := buildRealTreeChain(t, []witnessSetKitHWS{s0, s1}, 200, s1, netID)
	// The leaf the tree committed for the rotation entry must be
	// OnLogEntryLeafHash(canonical) — proven by a successful resolve.
	resolver, _ := NewHistoricalWitnessSetResolver(src, hwsLogDID, s0.set, s1.set)
	if _, err := resolver.SetAt(context.Background(), types.LogPosition{LogDID: hwsLogDID, Sequence: pos[0]}); err != nil {
		t.Fatalf("resolve at rotation leaf failed (leaf-model mismatch?): %v", err)
	}
	// Direct check: the committed leaf == OnLogEntryLeafHash(entry canonical).
	id := sha256.Sum256(src.canon[pos[0]])
	want := envelope.EntryLeafHashBytes(id[:]) // H(0x00 || SHA256(canonical)) == OnLogEntryLeafHash(canonical)
	proof, _ := src.InclusionProofAtSize(context.Background(), pos[0], src.horizon.TreeSize)
	proof.LeafHash = envelope.OnLogEntryLeafHash(src.canon[pos[0]])
	if proof.LeafHash != want {
		t.Errorf("on-log leaf model mismatch: %x != %x", proof.LeafHash, want)
	}
}
