/*
FILE PATH: cmd/ledger/boot/genesis/genesis_test.go

#76 D-matrix, T0 tier — the producer rule against narrow fakes (no Postgres,
no tessera). These pin the fail-closed contract and the commentary
classification at the rule's own altitude:

  - D3  RefusesUnendorsedRequire: a require-policy constitution missing its
    endorsements cannot reach the log (the encoder owns that rule; the boot
    producer must surface it, not swallow it).
  - D2' RefusesWrongNetworkAtSeqZero: a sequence-0 entry that is not THIS
    network's constitution (wrong log / tampered root) fails the restart
    verification — boot must refuse.
  - Commentary pin: the genesis entry classifies as Commentary (one Merkle
    leaf, zero SMT impact). The checkpoint loop's genesis-disambiguation
    depends on exactly this shape.

The real-sequencer "lands at sequence 0 / idempotent" proof is the T2
integration test (tests/genesis_record_test.go), which drives this same
EnsureRecord through the production WAL→sequencer→entry_index path.
*/
package genesis_test

import (
	"context"
	"crypto/ecdsa"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/genesis"
)

// ─────────────────────────────────────────────────────────────────
// fakes — the three narrow seams EnsureRecord drives
// ─────────────────────────────────────────────────────────────────

type fakeSubmitter struct {
	called bool
	wire   []byte
}

func (f *fakeSubmitter) Submit(_ context.Context, _ [32]byte, wire []byte, _ int64, _ []types.Web3VerificationReceipt) error {
	f.called = true
	f.wire = append([]byte(nil), wire...)
	return nil
}

// fakeSeqIndex reports sequence-0 presence and the seq a hash was assigned.
type fakeSeqIndex struct {
	present bool   // FetchHashBySeq(0) presence (true → restart/verify path)
	seq     uint64 // the seq FetchPrimarySeqByHash returns for the appended entry
}

func (f *fakeSeqIndex) FetchHashBySeq(context.Context, uint64) ([32]byte, time.Time, bool, bool, error) {
	return [32]byte{}, time.Time{}, false, f.present, nil
}

func (f *fakeSeqIndex) FetchPrimarySeqByHash(context.Context, [32]byte) (uint64, bool, error) {
	return f.seq, true, nil
}

type fakeFetcher struct{ bytes []byte }

func (f *fakeFetcher) Fetch(context.Context, types.LogPosition) (*types.EntryWithMetadata, error) {
	return &types.EntryWithMetadata{CanonicalBytes: f.bytes}, nil
}

// ─────────────────────────────────────────────────────────────────
// fixtures
// ─────────────────────────────────────────────────────────────────

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// keyDID generates a fresh secp256k1 key and its did:key (the witness/ledger
// curve did:key resolution understands).
func keyDID(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	return priv, sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
}

// legacyDoc builds a valid, ceremony-free (no endorsement policy) constitution
// with a single witness — it encodes without endorsements.
func legacyDoc(t *testing.T, name, witnessDID string) network.BootstrapDocument {
	t.Helper()
	return network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:" + name + ".example",
		NetworkName:       name,
		GenesisWitnessSet: []string{witnessDID},
		GenesisQuorumK:    1, // N=1 ⇒ K=1 (2K>N)
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{GatingRequired: false, CostMode: "uncharged"},
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001},
			AllowedCosignSchemeTags: []uint8{0x01},
			MinSignaturesPerEntry:   1,
		},
	}
}

func pinOf(t *testing.T, doc network.BootstrapDocument) [32]byte {
	t.Helper()
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs(): %v", err)
	}
	return [32]byte(ids.NetworkID)
}

func configFor(t *testing.T, doc network.BootstrapDocument) genesis.Config {
	t.Helper()
	priv, did := keyDID(t)
	return genesis.Config{
		Doc:       doc,
		LogDID:    "did:web:" + doc.NetworkName + ".log",
		SignerDID: did,
		Priv:      priv,
		Pin:       pinOf(t, doc),
		Poll:      time.Millisecond,
		Timeout:   2 * time.Second,
		Logger:    discardLogger(),
	}
}

// ─────────────────────────────────────────────────────────────────
// D3 — a require constitution missing endorsements cannot reach the log
// ─────────────────────────────────────────────────────────────────

func TestEnsureRecord_RefusesUnendorsedRequire(t *testing.T) {
	_, witnessDID := keyDID(t)
	doc := legacyDoc(t, "phaseb-require", witnessDID)
	doc.GenesisEndorsementPolicy = network.GenesisEndorsementRequire // require, but NO endorsements attached

	sub := &fakeSubmitter{}
	_, err := genesis.EnsureRecord(context.Background(), sub, &fakeSeqIndex{present: false}, nil, configFor(t, doc))
	if err == nil {
		t.Fatal("EnsureRecord accepted an unendorsed require constitution — it must refuse to put one on the log")
	}
	if !strings.Contains(err.Error(), "encode network genesis record") {
		t.Fatalf("error did not surface the encoder's refusal: %v", err)
	}
	if sub.called {
		t.Fatal("an unendorsed require constitution was submitted to the WAL — the refusal must precede any write")
	}
}

// ─────────────────────────────────────────────────────────────────
// D2' — a wrong-network seq-0 fails restart verification (fail-closed)
// ─────────────────────────────────────────────────────────────────

func TestEnsureRecord_RefusesWrongNetworkAtSeqZero(t *testing.T) {
	ctx := context.Background()

	// Network A: produce a real genesis entry through the append path and
	// capture its canonical bytes from the submitter.
	_, wDIDA := keyDID(t)
	docA := legacyDoc(t, "network-a", wDIDA)
	subA := &fakeSubmitter{}
	if _, err := genesis.EnsureRecord(ctx, subA, &fakeSeqIndex{present: false, seq: 0}, nil, configFor(t, docA)); err != nil {
		t.Fatalf("append network-A genesis: %v", err)
	}
	if !subA.called || len(subA.wire) == 0 {
		t.Fatal("network-A genesis entry was not produced")
	}

	// Network B boots and finds a sequence-0 entry that is network-A's
	// constitution. Decoding it under B's pin must fail — wrong log.
	_, wDIDB := keyDID(t)
	docB := legacyDoc(t, "network-b", wDIDB)
	cfgB := configFor(t, docB)
	_, err := genesis.EnsureRecord(ctx, &fakeSubmitter{}, &fakeSeqIndex{present: true}, &fakeFetcher{bytes: subA.wire}, cfgB)
	if err == nil {
		t.Fatal("EnsureRecord accepted a foreign network's constitution at sequence 0 — a wrong/tampered log must refuse boot")
	}
	if !strings.Contains(err.Error(), "not this network's verified constitution") {
		t.Fatalf("error did not surface the wrong-log refusal: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Commentary pin — the genesis entry is zero-SMT-impact commentary
// ─────────────────────────────────────────────────────────────────

func TestGenesisEntry_ClassifiesAsCommentary(t *testing.T) {
	_, witnessDID := keyDID(t)
	doc := legacyDoc(t, "commentary-pin", witnessDID)

	entry, err := genesis.BuildEntry(configFor(t, doc))
	if err != nil {
		t.Fatalf("BuildEntry: %v", err)
	}
	c, err := builder.ClassifyEntry(context.Background(), builder.ClassifyParams{Entry: entry})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if c.Path != builder.PathResultCommentary || !c.Details.IsCommentary {
		t.Fatalf("genesis entry classified as %v (commentary=%v), want Commentary — the checkpoint loop's "+
			"genesis-disambiguation depends on the seq-0 record advancing tree_size without mutating the SMT root",
			c.Path, c.Details.IsCommentary)
	}
}
