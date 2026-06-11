/*
FILE PATH: witnessclient/genesis_rebuild_test.go

#76 D4 — the projection-re-root parity proof. RebuildGenesisBaselineFromLog
derives the witness_sets genesis baseline from the log's seq-0 constitution
record; the config path (gossip.go, pre-#76) derived the same row from the
mounted document. This pins that the two derivations produce a BYTE-IDENTICAL
set_hash — the witness_sets table is a rebuildable cache of the log, not an
independent seed that could silently diverge.

  - SetHashParityWithConfig: pure (T0) — verifier.GenesisSetFromRecord and
    quorum.NewKeySet hash to the same content-addressable identity.
  - SeedsByteIdenticalRow: DB (T2) — the re-root writes that identity as the
    ACTIVE genesis row, resolvable through LoadCurrentSetRow.
*/
package witnessclient_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/verifier"

	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// genesisDocWithWitnesses builds a valid constitution with n freshly-generated
// secp256k1 witnesses and quorum k, plus the encoded seq-0 record and its TOFU
// pin — everything D4 needs to compare the log-derived and config-derived sets.
func genesisDocWithWitnesses(t *testing.T, n, k int) (doc network.BootstrapDocument, record []byte, pin [32]byte) {
	t.Helper()
	dids := make([]string, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
		if err != nil {
			t.Fatalf("compress: %v", err)
		}
		dids[i] = sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed)
	}
	doc = network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       "did:web:d4.example",
		NetworkName:       "d4-parity",
		GenesisWitnessSet: dids,
		GenesisQuorumK:    k,
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
	var err error
	record, err = network.EncodeNetworkGenesisRecord(doc)
	if err != nil {
		t.Fatalf("EncodeNetworkGenesisRecord: %v", err)
	}
	ids, err := doc.IDs()
	if err != nil {
		t.Fatalf("doc.IDs(): %v", err)
	}
	return doc, record, [32]byte(ids.NetworkID)
}

func TestRebuildGenesisBaseline_SetHashParityWithConfig(t *testing.T) {
	doc, record, pin := genesisDocWithWitnesses(t, 3, 2)

	// Log-derived: decode + verify the seq-0 record → genesis set.
	logSet, err := verifier.GenesisSetFromRecord(record, pin, nil)
	if err != nil {
		t.Fatalf("GenesisSetFromRecord: %v", err)
	}

	// Config-derived: resolve the mounted DIDs directly (the pre-#76 path).
	cfgKeys, err := quorum.LoadWitnessKeys(doc.GenesisWitnessSet)
	if err != nil {
		t.Fatalf("LoadWitnessKeys: %v", err)
	}
	cfgSet, err := quorum.NewKeySet(cfgKeys, cosign.NetworkID(pin), doc.GenesisQuorumK,
		doc.GenesisSignaturePolicy.AllowedCosignSchemeTags)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	logHash, cfgHash := logSet.SetHash(), cfgSet.SetHash()
	if !bytes.Equal(logHash[:], cfgHash[:]) {
		t.Fatalf("set_hash divergence: log-derived %x != config-derived %x — the witness_sets "+
			"projection is NOT a faithful cache of the log", logHash, cfgHash)
	}
}

func TestRebuildGenesisBaselineFromLog_SeedsByteIdenticalRow(t *testing.T) {
	ctx := context.Background()
	pool := requireWitnessDSN(t)

	_, record, pin := genesisDocWithWitnesses(t, 3, 2)
	logSet, err := verifier.GenesisSetFromRecord(record, pin, nil)
	if err != nil {
		t.Fatalf("GenesisSetFromRecord: %v", err)
	}
	want := logSet.SetHash()

	recorded, err := witnessclient.RebuildGenesisBaselineFromLog(ctx, pool, record, pin)
	if err != nil {
		t.Fatalf("RebuildGenesisBaselineFromLog: %v", err)
	}
	if !recorded {
		t.Fatal("expected the log-derived genesis baseline to be recorded on an empty table")
	}

	cur, err := witnessclient.LoadCurrentSetRow(ctx, pool)
	if err != nil {
		t.Fatalf("LoadCurrentSetRow: %v", err)
	}
	if !bytes.Equal(cur.SetHash[:], want[:]) {
		t.Fatalf("seeded set_hash = %x, want the log-derived genesis identity %x", cur.SetHash, want)
	}
	if cur.EffectiveSeq != 0 || cur.RetiredSeq != nil {
		t.Fatalf("genesis row classification: effective_seq=%d retired=%v, want 0/NULL", cur.EffectiveSeq, cur.RetiredSeq)
	}

	// Idempotent: a second re-root (e.g. a re-run rebuild) records nothing.
	again, err := witnessclient.RebuildGenesisBaselineFromLog(ctx, pool, record, pin)
	if err != nil {
		t.Fatalf("second RebuildGenesisBaselineFromLog: %v", err)
	}
	if again {
		t.Fatal("second re-root reported recorded=true; want no-op")
	}
}
