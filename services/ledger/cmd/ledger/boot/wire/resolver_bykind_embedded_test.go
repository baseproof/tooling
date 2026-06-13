package wire

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/internal/embeddedpg"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/store/indexes"
)

const byKindResolverPGPort = 54341

// canonBytesReader returns the canonical entry bytes for a minted entry, keyed
// by sequence — the by-kind source deserializes these to decode the payload.
type canonBytesReader struct{ bySeq map[uint64][]byte }

func (r canonBytesReader) ReadEntry(_ context.Context, seq uint64, _ [32]byte) ([]byte, error) {
	return r.bySeq[seq], nil
}

func (r canonBytesReader) ReadEntryBatch(_ context.Context, refs []bytestore.EntryRef) ([][]byte, error) {
	out := make([][]byte, len(refs))
	for i, ref := range refs {
		out[i] = r.bySeq[ref.Seq]
	}
	return out, nil
}

// TestBuildWitnessEndpointDeclarationSource_ByKind_NoEnv_Embedded is the by-kind
// resolver integration test (PRE-11 Phase B, default-ON). With NO LEDGER_*_SCHEMA
// position proxy in play, the witness-endpoint source resolves a minted, signed
// WitnessEndpointDeclaration purely BY KIND (idx_entry_kind → QueryByKind →
// decode) — proving default-ON resolution is real end-to-end, not transitive.
// The source builder takes no env at all, so resolution is env-independent by
// construction; this drives it against a REAL Postgres + a real canonical entry.
// (The empty → fail-closed half is pinned by witnessclient/head_sync_resolver_test.go.)
func TestBuildWitnessEndpointDeclarationSource_ByKind_NoEnv_Embedded(t *testing.T) {
	pool := embeddedpg.Start(t, byKindResolverPGPort) // t.Skip without a real PG
	ctx := context.Background()
	es := store.NewEntryStore(pool)

	// Mint a real, signed WitnessEndpointDeclaration entry.
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	keys, err := witness.KeysFromDIDs([]string{kp.DID})
	if err != nil || len(keys) != 1 {
		t.Fatalf("KeysFromDIDs: keys=%d err=%v", len(keys), err)
	}
	pubKeyID := keys[0].ID
	payload, err := network.EncodeWitnessEndpointDeclarationPayload(network.WitnessEndpointDeclaration{
		PubKeyID:  pubKeyID,
		Endpoints: map[string]string{"BaseproofWitness": "https://w1.example.com"},
	})
	if err != nil {
		t.Fatalf("EncodeWitnessEndpointDeclarationPayload: %v", err)
	}
	// Build through the real constructor (NewUnsignedEntry stamps the active
	// protocol version) so the serialized canonical bytes survive the
	// production resolver's envelope.Deserialize — a raw &envelope.Entry{}
	// literal serializes as protocol version 0, which Deserialize rejects.
	header := envelope.ControlHeader{
		SignerDID:   kp.DID,
		Destination: "did:baseproof:log:test",
		EventTime:   time.Unix(1_700_000_000, 0).UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	sigHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := sdksigs.SignEntry(sigHash, kp.PrivateKey)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: kp.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Insert the entry_index row; Kind derived THROUGH the production projection
	// so it lands as the real witness-endpoint kind (by-kind findable).
	row := store.EntryRow{
		SequenceNumber: 0,
		CanonicalHash:  sha256.Sum256(canonical),
		LogTime:        time.Unix(1_700_000_000, 0).UTC(),
		SignerDID:      kp.DID,
		Kind:           store.EntryKindProjection(entry),
		Status:         store.StatusLive,
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := es.Insert(ctx, tx, row); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Build the query API over a reader returning the canonical bytes, then run
	// the by-kind source — no schema env. It must resolve the declaration.
	api := indexes.NewPostgresQueryAPI(ctx, pool, canonBytesReader{bySeq: map[uint64][]byte{0: canonical}}, "did:baseproof:log:test")

	recs, err := buildWitnessEndpointDeclarationSource(api)(ctx)
	if err != nil {
		t.Fatalf("by-kind witness-endpoint source: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Payload.PubKeyID == pubKeyID {
			found = true
		}
	}
	if !found {
		t.Fatalf("default-ON by-kind resolution must find the minted declaration with no schema env; got %d records", len(recs))
	}
}
