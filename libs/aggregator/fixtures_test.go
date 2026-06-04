package aggregator

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"

	"github.com/baseproof/tooling/libs/clitools"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// signEntry attaches a primary ECDSA-secp256k1 signature to an unsigned builder
// entry. v7.75 forbids serializing an unsigned entry, so the round-trip the
// engine decodes must first carry a signature. The key need not be bound to the
// SignerDID — Decode never verifies (DID resolution is off-log).
func signEntry(t *testing.T, entry *envelope.Entry, priv *ecdsa.PrivateKey) *envelope.Entry {
	t.Helper()
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sigBytes, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	signed, err := envelope.NewEntry(entry.Header, entry.DomainPayload, []envelope.Signature{
		{SignerDID: entry.Header.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sigBytes},
	})
	if err != nil {
		t.Fatalf("new signed entry: %v", err)
	}
	return signed
}

// rawFrom signs + serializes an entry into a clitools.RawEntry at the given seq.
func rawFrom(t *testing.T, seq uint64, entry *envelope.Entry) clitools.RawEntry {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b, err := envelope.Serialize(signEntry(t, entry, priv))
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return clitools.RawEntry{Sequence: seq, CanonicalHex: hex.EncodeToString(b)}
}

// mustRoot builds a minimal signed-able root entity for engine tests.
func mustRoot(t *testing.T) *envelope.Entry {
	t.Helper()
	e, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:test",
		Payload:     mustJSON(t, map[string]any{"k": "v"}),
	})
	if err != nil {
		t.Fatalf("build root: %v", err)
	}
	return e
}
