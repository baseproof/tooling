package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/protocol"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

// fakeLedgerReader returns consistent crypto DIRECTLY — no HTTP entry-fetch
// protocol. This is the seam (LedgerReader) that lets a single-network integration
// test drive the gather end-to-end without reimplementing HTTPEntryFetcher.
type fakeLedgerReader struct {
	head      types.CosignedTreeHead
	entryHex  string
	inclusion types.MerkleProof
}

func (f *fakeLedgerReader) Horizon() (types.CosignedTreeHead, error) { return f.head, nil }
func (f *fakeLedgerReader) FetchEntry(_ context.Context, seq uint64) (*clitools.RawEntry, error) {
	return &clitools.RawEntry{Sequence: seq, CanonicalHex: f.entryHex}, nil
}
func (f *fakeLedgerReader) InclusionProofAtSize(_, _ uint64) (*types.MerkleProof, error) {
	p := f.inclusion
	return &p, nil
}
func (f *fakeLedgerReader) ScanFrom(context.Context, uint64, int) ([]clitools.RawEntry, error) {
	return nil, nil // no anchors — non-federated
}

// cosignTreeHead cosigns a specific TreeHead with the given signers under nid.
func cosignTreeHead(t *testing.T, th types.TreeHead, signers []cosign.WitnessSigner, nid cosign.NetworkID) types.CosignedTreeHead {
	t.Helper()
	head := types.CosignedTreeHead{TreeHead: th}
	payload := cosign.NewTreeHeadPayload(th)
	for _, s := range signers {
		sig, err := s.Sign(context.Background(), payload, nid, cosign.HashAlgoSHA256)
		if err != nil {
			t.Fatalf("cosign: %v", err)
		}
		head.Signatures = append(head.Signatures, sig)
	}
	return head
}

// TestGather_SingleNetwork_EndToEnd drives the BUNDLE-DRIVEN gather over a live
// (httptest) read API + a faked LedgerReader returning consistent crypto, builds a
// complete single-network proof, and verifies it FULLY OFFLINE with only the
// genesis trust root — then confirms the tamper matrix fails closed. This is the
// runnable proof of the whole gather→BuildStandalone→VerifyStandalone loop.
func TestGather_SingleNetwork_EndToEnd(t *testing.T) {
	ctx := context.Background()
	const n, k = 3, 2
	dids, signers := witnessKit(t, n)
	bdoc := witnessTestBootstrap(dids)
	ids, err := bdoc.IDs()
	if err != nil {
		t.Fatalf("IDs: %v", err)
	}
	nid := cosign.NetworkID(ids.NetworkID)
	logDID := ids.DID

	// Target entry (a real SchemaRef-less envelope) committed at seq 0.
	entryBytes := mkEntry(t, "did:web:member.example", []byte("member-payload"))
	leafHash := envelope.OnLogEntryLeafHash(entryBytes)

	// A member SMT key present at the entry's position.
	var key [32]byte
	key[0], key[31] = 0x5A, 0xA5
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeStore())
	pos := types.LogPosition{LogDID: logDID, Sequence: 0}
	if err := tree.SetLeaf(ctx, key, types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos}); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	smtRoot, err := tree.Root(ctx)
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	smtProof, err := tree.GenerateMembershipProof(ctx, key)
	if err != nil {
		t.Fatalf("GenerateMembershipProof: %v", err)
	}

	// A single-leaf receipt tree at the entry position (the third cosigned root).
	receiptCommit := smt.ReceiptCommitment{Position: pos, ReceiptHash: sha256.Sum256([]byte("receipt"))}
	receiptRoot := smt.ReceiptRoot([]smt.ReceiptCommitment{receiptCommit})
	receiptSection, err := sdkbundle.EncodeReceiptProof(&smt.ReceiptInclusionProof{
		Commitment: receiptCommit, LeafIndex: 0, LeafCount: 1, AuditPath: nil,
	})
	if err != nil {
		t.Fatalf("EncodeReceiptProof: %v", err)
	}

	// One cosigned checkpoint over all three roots. TreeSize 1 ⇒ RootHash == leaf,
	// inclusion is the empty co-path.
	head := cosignTreeHead(t, types.TreeHead{
		RootHash: leafHash, SMTRoot: smtRoot, ReceiptRoot: receiptRoot, TreeSize: 1,
	}, signers, nid)
	inclusion := types.MerkleProof{LeafPosition: 0, LeafHash: leafHash, TreeSize: 1}
	reader := &fakeLedgerReader{head: head, entryHex: hex.EncodeToString(entryBytes), inclusion: inclusion}

	canonical, err := bdoc.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	// The raw (non-client) read endpoints the gather drives over HTTP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/network/bootstrap":
			_, _ = w.Write(canonical)
		case strings.HasPrefix(r.URL.Path, "/v1/smt/proof/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "membership", "proof": smtProof})
		case strings.HasPrefix(r.URL.Path, "/v1/receipt/proof/"):
			_ = json.NewEncoder(w).Encode(map[string]json.RawMessage{"receipt_proof": receiptSection})
		case r.URL.Path == "/v1/burn":
			_ = json.NewEncoder(w).Encode(map[string]any{"is_burned": false})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	bundle := &protocol.NetworkBundle{
		TrustRoot: protocol.GenesisTrustRoot{
			NetworkID: nid, GenesisWitnessDIDs: dids, QuorumK: k,
			BootstrapDocumentHash: sha256.Sum256(canonical),
		},
		Endpoint:       srv.URL,
		CitedMemberKey: key,
	}

	// GATHER via the bundle, BUILD, then VERIFY offline.
	g, err := NewBundleGather(ctx, bundle, reader, srv.Client(), 0, key)
	if err != nil {
		t.Fatalf("NewBundleGather: %v", err)
	}
	proof, err := sdkbundle.BuildStandalone(ctx, g, 0)
	if err != nil {
		t.Fatalf("BuildStandalone: %v", err)
	}
	roots := map[cosign.NetworkID]protocol.GenesisTrustRoot{nid: bundle.TrustRoot}
	res, err := sdkbundle.VerifyStandalone(ctx, proof, roots)
	if err != nil || res == nil || !res.Valid {
		t.Fatalf("offline verify FAILED: err=%v res=%+v", err, res)
	}
	for _, want := range []string{"entry_inclusion", "entry_smt_membership", "checkpoint_quorum", "receipt_proof"} {
		if !containsStr(res.Coverage.Verified, want) {
			t.Errorf("coverage missing %q: %v", want, res.Coverage.Verified)
		}
	}

	// Tamper matrix: each forgery fails closed (err==nil ⟺ Valid).
	for name, mut := range map[string]func(*sdkbundle.StandaloneProof){
		"forged root_hash": func(p *sdkbundle.StandaloneProof) { p.CosignedHead.RootHash[0] ^= 0xFF },
		"forged smt_root":  func(p *sdkbundle.StandaloneProof) { p.CosignedHead.SMTRoot[0] ^= 0xFF },
		"tampered entry":   func(p *sdkbundle.StandaloneProof) { p.Entry.WireBytes[0] ^= 0xFF },
	} {
		bad := *proof
		bad.Entry.WireBytes = append([]byte(nil), proof.Entry.WireBytes...)
		mut(&bad)
		if r, e := sdkbundle.VerifyStandalone(ctx, &bad, roots); e == nil || (r != nil && r.Valid) {
			t.Errorf("tamper %q ACCEPTED — fail-closed contract broken", name)
		}
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
