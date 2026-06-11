package cli

// realproof_test.go — the REAL-crypto positive round-trip. Unlike the fake-gather
// tests (which prove wiring + fail-closed), this builds a genuinely verifiable v2
// proof: real secp256k1 did:key witnesses cosigning a real RFC-6962 tree head + a
// real Jellyfish SMT root. It drives the ACTUAL CLI code paths — generateProof
// (BuildStandalone) and verifyProofFile (VerifyStandalone) — and asserts every
// element: the proof generates, verifies Valid=true, round-trips through the
// file, and a single tampered byte is rejected fail-closed.

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"
	"errors"
)

// realGather returns REAL proof sections (no canned hashes), so BuildStandalone
// assembles a proof VerifyStandalone fully accepts.
type realGather struct {
	bdoc    *network.BootstrapDocument
	k       int
	entry   []byte
	logTime time.Time
	head    types.CosignedTreeHead
	inc     types.MerkleProof
	smt     types.SMTProof
}

func (g *realGather) FetchGenesisBootstrap(context.Context) (*network.BootstrapDocument, int, error) {
	return g.bdoc, g.k, nil
}
func (g *realGather) FetchEntry(context.Context, uint64) ([]byte, time.Time, error) {
	return g.entry, g.logTime, nil
}
func (g *realGather) FetchCosignedHead(context.Context, uint64) (types.CosignedTreeHead, error) {
	return g.head, nil
}
func (g *realGather) FetchInclusionProof(context.Context, uint64, uint64) (types.MerkleProof, error) {
	return g.inc, nil
}
func (g *realGather) FetchSMTProof(context.Context, uint64, [32]byte) (types.SMTProof, error) {
	return g.smt, nil
}
func (g *realGather) FetchWitnessRotationChain(context.Context, uint64) ([]sdkbundle.RotationElement, error) {
	return nil, nil
}

// realFixture is a complete genesis-only network fixture built from real crypto:
// the bootstrap doc + its derived ids, the n genesis witnesses, a real signed entry
// committed in a real RFC-6962 tree + a real Jellyfish SMT, and the cosigned head
// over both roots. It backs BOTH the offline fake-gather test (mustRealGather) and
// the live-HTTP e2e (live_http_test.go serves these exact artifacts over the real
// ledger read endpoints, so the libs HTTP gather is exercised end to end).
type realFixture struct {
	bdoc          *network.BootstrapDocument
	canonical     []byte // bdoc.CanonicalBytes — what /v1/network/bootstrap serves
	nid           cosign.NetworkID
	networkDID    string // ids.DID — a non-empty log DID for the fetcher
	bootstrapHash [32]byte
	dids          []string // genesis witness DIDs
	k             int      // quorum
	entryBytes    []byte   // canonical wire bytes of the target entry
	seq           uint64   // the entry's chronological position
	smtKey        [32]byte // the entry's SMT key (the witnessed presence key)
	smtRoot       [32]byte
	smtTree       *smt.Tree // the live tree, to serve membership/non-membership for ANY key
	head          types.CosignedTreeHead // cosigned by all n witnesses
	inc           *types.MerkleProof
	smtProof      *types.SMTProof
	logTime       time.Time
	trustRoots    map[cosign.NetworkID]protocol.GenesisTrustRoot
}

// mustRealGather assembles a genesis-only fixture with n witnesses and quorum k
// (all n cosign), returning the gather, the genesis trust root, and the target
// entry's sequence. It mirrors the SDK's own v2 fixture, using only public APIs.
func mustRealGather(t *testing.T, n, k int) (*realGather, map[cosign.NetworkID]protocol.GenesisTrustRoot, uint64) {
	fx := buildRealFixture(t, n, k)
	g := &realGather{
		bdoc: fx.bdoc, k: fx.k, entry: fx.entryBytes, logTime: fx.logTime,
		head: fx.head, inc: *fx.inc, smt: *fx.smtProof,
	}
	return g, fx.trustRoots, fx.seq
}

// buildRealFixture assembles the genesis-only real-crypto fixture (n witnesses,
// quorum k). Extracted from mustRealGather so the live-HTTP e2e can serve the same
// artifacts; mirrors the SDK's own v2 fixture, using only public APIs.
func buildRealFixture(t *testing.T, n, k int) *realFixture {
	t.Helper()
	ctx := context.Background()

	// 1. Genesis witnesses (real secp256k1 did:key) + their signers.
	dids := make([]string, n)
	signers := make([]cosign.WitnessSigner, n)
	for i := 0; i < n; i++ {
		kp, err := sdkdid.GenerateDIDKeySecp256k1()
		if err != nil {
			t.Fatalf("witness keygen: %v", err)
		}
		dids[i] = kp.DID
		signers[i] = cosign.NewECDSAWitnessSigner(kp.PrivateKey)
	}

	// 2. Bootstrap → canonical → network id.
	bdoc := &network.BootstrapDocument{
		ProtocolVersion:             "1",
		ExchangeDID:                 "did:web:exchange.example",
		NetworkName:                 "real-fixture-net",
		GenesisWitnessSet:           dids,
		GenesisQuorumK:              len(dids)/2 + 1, // REQUIRED since rc4; majority always satisfies 2K>N
		GenesisTreeHead:             network.GenesisTreeHead{RootHash: strings.Repeat("0", 64), TreeSize: 0},
		GenesisAdmissionAuthorities: []string{"0123456789abcdef0123456789abcdef01234567"},
		GenesisAdmissionPolicy:      network.GenesisAdmissionPolicy{GatingRequired: true, CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
	ids, err := bdoc.IDs()
	if err != nil {
		t.Fatalf("bootstrap IDs: %v", err)
	}
	canonical, err := bdoc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	nid := ids.NetworkID
	bootstrapHash := sha256.Sum256(canonical)

	// 3. Target entry: a real signed did:key envelope, committed in a real tree.
	authorKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("author keygen: %v", err)
	}
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID: authorKP.DID, Destination: "did:web:exchange.example", EventTime: 1700000000,
	}, []byte("real v2 target payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	signHash := sha256.Sum256(envelope.SigningPayload(unsigned))
	authorSig, err := signatures.SignEntry(signHash, authorKP.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	unsigned.Signatures = []envelope.Signature{{SignerDID: authorKP.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: authorSig}}
	if err := unsigned.Validate(); err != nil {
		t.Fatalf("entry Validate: %v", err)
	}
	entryBytes, err := envelope.Serialize(unsigned)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	entryIdentity := sha256.Sum256(entryBytes)

	tree := smt.NewStubMerkleTree()
	pos, err := tree.AppendLeaf(entryIdentity[:])
	if err != nil {
		t.Fatalf("AppendLeaf: %v", err)
	}
	if _, err := tree.AppendLeaf([]byte("padding-leaf")); err != nil { // a real co-path
		t.Fatalf("AppendLeaf padding: %v", err)
	}
	chronHead, err := tree.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	merkleProof, err := tree.InclusionProof(ctx, pos, chronHead.TreeSize)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}

	// 4. Real SMT with the entry's key (+ a co-path sibling) → membership proof.
	smtTree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	leafKey := sha256.Sum256([]byte("real-fixture-entry-key"))
	if err := smtTree.SetLeaf(ctx, leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: types.LogPosition{LogDID: ids.DID, Sequence: pos}, AuthorityTip: types.LogPosition{LogDID: ids.DID, Sequence: pos},
	}); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	otherKey := sha256.Sum256([]byte("real-fixture-other-key"))
	if err := smtTree.SetLeaf(ctx, otherKey, types.SMTLeaf{
		Key: otherKey, OriginTip: types.LogPosition{LogDID: ids.DID, Sequence: 1}, AuthorityTip: types.LogPosition{LogDID: ids.DID, Sequence: 1},
	}); err != nil {
		t.Fatalf("SetLeaf other: %v", err)
	}
	smtRoot, err := smtTree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	smtProof, err := smtTree.GenerateMembershipProof(ctx, leafKey)
	if err != nil {
		t.Fatalf("GenerateMembershipProof: %v", err)
	}

	// 5. Cosigned head, signed by all n genesis witnesses (covers RootHash + SMTRoot).
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{RootHash: chronHead.RootHash, SMTRoot: smtRoot, TreeSize: chronHead.TreeSize},
	}
	payload := cosign.NewTreeHeadPayload(head.TreeHead)
	for _, s := range signers {
		wsig, err := s.Sign(ctx, payload, nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("witness Sign: %v", err)
		}
		head.Signatures = append(head.Signatures, wsig)
	}

	trustRoots := map[cosign.NetworkID]protocol.GenesisTrustRoot{
		nid: {NetworkID: nid, GenesisWitnessDIDs: append([]string(nil), dids...), QuorumK: k, BootstrapDocumentHash: bootstrapHash},
	}
	return &realFixture{
		bdoc: bdoc, canonical: canonical, nid: nid, networkDID: ids.DID, bootstrapHash: bootstrapHash,
		dids: dids, k: k, entryBytes: entryBytes, seq: pos, smtKey: leafKey, smtRoot: smtRoot,
		smtTree: smtTree, head: head, inc: merkleProof, smtProof: smtProof,
		logTime: time.Unix(1700000000, 0).UTC(), trustRoots: trustRoots,
	}
}

// TestProofVerify_RealCryptoPositive proves the happy path end to end: a real
// proof GENERATES, VERIFIES Valid=true (both directly and via the verify command
// off a file), round-trips losslessly, and a tampered byte is rejected.
func TestProofVerify_RealCryptoPositive(t *testing.T) {
	ctx := context.Background()
	g, trustRoots, seq := mustRealGather(t, 3, 2) // 3 witnesses, quorum 2

	// PROOF command path: generate a v2 proof from the real-section gather.
	proof, err := generateProof(ctx, g, seq)
	if err != nil {
		t.Fatalf("generateProof: %v", err)
	}
	if proof.Format != sdkbundle.FormatV2 {
		t.Fatalf("format = %q, want v2", proof.Format)
	}

	// POSITIVE: the generated proof verifies Valid=true against the genesis trust root.
	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil || res == nil || !res.Valid {
		var cov []string
		if res != nil {
			cov = res.Coverage.Verified
		}
		t.Fatalf("a REAL proof failed to verify: err=%v valid=%v verified=%v", err, res != nil && res.Valid, cov)
	}
	t.Logf("verified sections: %v   quorum %d-of-%d", res.Coverage.Verified, res.WitnessQuorum.Have, res.WitnessQuorum.Need)

	// VERIFY command path: write to a file, verify offline (self-anchored TOFU off
	// the real embedded bootstrap) — must accept the valid proof.
	path := filepath.Join(t.TempDir(), "real.proof")
	if err := writeProofFile(proof, path); err != nil {
		t.Fatalf("writeProofFile: %v", err)
	}
	_, vres, err := verifyProofFile(ctx, path, "")
	if err != nil {
		t.Fatalf("verifyProofFile REJECTED a valid proof (false negative): %v", err)
	}
	if !vres.Valid {
		t.Fatal("verifyProofFile returned not-valid for a valid proof")
	}

	// ROUND-TRIP: encode → decode → still Valid (JCS-canonical, lossless).
	raw, err := sdkbundle.EncodeStandalone(proof)
	if err != nil {
		t.Fatalf("EncodeStandalone: %v", err)
	}
	dec, err := sdkbundle.DecodeStandalone(raw)
	if err != nil {
		t.Fatalf("DecodeStandalone: %v", err)
	}
	if r, _ := sdkbundle.VerifyStandalone(ctx, dec, trustRoots); r == nil || !r.Valid {
		t.Fatal("decoded proof failed to verify (round-trip not lossless)")
	}

	// TAMPER (Zero-Trust even on a real proof): a single flipped entry byte ⇒ rejected.
	bad := *proof
	bad.Entry.WireBytes = append([]byte(nil), proof.Entry.WireBytes...)
	bad.Entry.WireBytes[0] ^= 0xFF
	if r, err := sdkbundle.VerifyStandalone(ctx, &bad, trustRoots); err == nil && r != nil && r.Valid {
		t.Fatal("a tampered entry verified — fail-closed broken")
	}

	// Confirm the file we wrote is non-empty JCS bytes (the portable artifact).
	if fi, _ := os.Stat(path); fi == nil || fi.Size() == 0 {
		t.Fatal("proof file is empty")
	}
}

// TestProofVerify_TrustRootKMismatch [E2]: the rc4+ constitution cross-check,
// proven through a REAL generated proof rather than asserted at the SDK alone.
// A trust root whose QuorumK disagrees with the constitution's NetworkID-bound
// genesis_quorum_k must refuse verification with ErrGenesisBindFailed — a stale
// or hostile trust root cannot lower (or raise) the quorum the proof verifies
// under, because K's single source is the verified constitution.
func TestProofVerify_TrustRootKMismatch(t *testing.T) {
	ctx := context.Background()
	g, trustRoots, seq := mustRealGather(t, 3, 2)

	proof, err := generateProof(ctx, g, seq)
	if err != nil {
		t.Fatalf("generateProof: %v", err)
	}
	for nid, tr := range trustRoots {
		tr.QuorumK++ // disagree with the constitutional K
		trustRoots[nid] = tr
	}
	_, err = sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if !errors.Is(err, sdkbundle.ErrGenesisBindFailed) {
		t.Fatalf("tampered trust-root K: want ErrGenesisBindFailed, got %v", err)
	}
}
