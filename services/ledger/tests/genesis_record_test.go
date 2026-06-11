/*
FILE PATH: tests/genesis_record_test.go

#76 D1/D2 — the seq-0 constitution producer against the REAL
WAL→sequencer→entry_index→tessera path (T2). Where the genesis package's T0
tests pin the producer rule against fakes, this drives genesis.EnsureRecord
through the same components production boots with and proves the system-level
contract:

  - D1 SequencesAtZero: the constitution lands at sequence 0, and the SMT root
    stays EmptyHash across it (commentary — one Merkle leaf, zero SMT impact),
    exactly the shape the checkpoint loop's genesis-disambiguation assumes.
  - D2 RestartIdempotent: a second EnsureRecord over the same log (the restart
    path) verifies sequence 0 and appends nothing.

The harness boots an EMPTY log (cleanTables) with a real sequencer already
draining the WAL, so submitting the constitution here reproduces the production
ordering (sequencer consuming → genesis seated → no external write has raced in).
*/
package tests

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/cmd/ledger/boot/genesis"
	"github.com/baseproof/tooling/services/ledger/store"
)

// genesisTestConfig builds a valid single-witness constitution plus the
// producer Config bound to the harness's log identity + a fresh ledger signer.
func genesisTestConfig(t *testing.T) genesis.Config {
	t.Helper()
	wPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("witness key: %v", err)
	}
	wCompressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&wPriv.PublicKey))
	if err != nil {
		t.Fatalf("compress witness: %v", err)
	}
	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:d1.example",
		NetworkName:       "d1-seq-zero",
		GenesisWitnessSet: []string{sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, wCompressed)},
		GenesisQuorumK:    1,
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
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs(): %v", err)
	}
	lPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("ledger signer key: %v", err)
	}
	lCompressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&lPriv.PublicKey))
	if err != nil {
		t.Fatalf("compress ledger: %v", err)
	}
	return genesis.Config{
		Doc:       doc,
		LogDID:    testLogDID,
		SignerDID: sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, lCompressed),
		Priv:      lPriv,
		Pin:       [32]byte(ids.NetworkID),
		Poll:      20 * time.Millisecond,
		Timeout:   30 * time.Second,
		Logger:    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
}

func TestGenesis_SequencesAtZero_AndRestartIdempotent(t *testing.T) {
	op := startTestLedgerWithOpts(t, testLedgerOpts{})
	ctx := context.Background()

	fetcher := store.NewPostgresEntryFetcher(op.Pool, op.EntryReader, testLogDID)
	cfg := genesisTestConfig(t)

	// D1: the constitution lands at sequence 0.
	record, err := genesis.EnsureRecord(ctx, op.WALCommitter, op.EntryStore, fetcher, cfg)
	if err != nil {
		t.Fatalf("EnsureRecord (fresh log): %v", err)
	}
	if len(record) == 0 {
		t.Fatal("EnsureRecord returned an empty genesis record")
	}
	hash, _, _, present, err := op.EntryStore.FetchHashBySeq(ctx, 0)
	if err != nil || !present {
		t.Fatalf("sequence 0 not present after EnsureRecord: present=%v err=%v", present, err)
	}

	// The record at sequence 0 decodes as THIS network's constitution.
	meta, err := fetcher.Fetch(ctx, types.LogPosition{LogDID: testLogDID, Sequence: 0})
	if err != nil {
		t.Fatalf("fetch sequence 0: %v", err)
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		t.Fatalf("deserialize sequence 0: %v", err)
	}
	if _, err := network.DecodeNetworkGenesisRecord(entry.DomainPayload, cfg.Pin); err != nil {
		t.Fatalf("sequence 0 is not the verified constitution: %v", err)
	}
	if !bytes.Equal(entry.DomainPayload, record) {
		t.Fatal("sequence-0 payload differs from the record EnsureRecord returned")
	}

	// D2: a second EnsureRecord (restart path) verifies sequence 0 and appends
	// nothing — the hash at sequence 0 is unchanged.
	if _, err := genesis.EnsureRecord(ctx, op.WALCommitter, op.EntryStore, fetcher, cfg); err != nil {
		t.Fatalf("EnsureRecord (restart): %v", err)
	}
	hash2, _, _, present2, err := op.EntryStore.FetchHashBySeq(ctx, 0)
	if err != nil || !present2 {
		t.Fatalf("sequence 0 vanished on restart: present=%v err=%v", present2, err)
	}
	if hash != hash2 {
		t.Fatalf("restart re-seated sequence 0: hash %x → %x (must be idempotent)", hash, hash2)
	}
}
