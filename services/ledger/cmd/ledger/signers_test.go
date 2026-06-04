package main

import (
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkcryptosigs "github.com/baseproof/baseproof/crypto/signatures"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// hexScalar renders a secp256k1 private key as the 32-byte big-endian hex
// scalar the ledger signer-key file format uses.
func hexScalar(t *testing.T) (scalarHex, wantDID string) {
	t.Helper()
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var b [32]byte
	priv.D.FillBytes(b[:])
	did, err := didKeyFromSecp256k1Priv(priv)
	if err != nil {
		t.Fatalf("didKeyFromSecp256k1Priv: %v", err)
	}
	return hex.EncodeToString(b[:]), did
}

func writeKey(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ledger-signer.key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return p
}

// TestLoadLedgerSigner_HexRoundTrip pins the format contract: a raw 32-byte
// secp256k1 hex scalar loads and derives the SAME did:key the file encodes.
func TestLoadLedgerSigner_HexRoundTrip(t *testing.T) {
	scalarHex, wantDID := hexScalar(t)
	path := writeKey(t, scalarHex+"\n") // trailing newline must be tolerated

	priv, gotDID, err := loadOrGenerateLedgerSigner(path, quietLogger())
	if err != nil {
		t.Fatalf("loadOrGenerateLedgerSigner: %v", err)
	}
	if gotDID != wantDID {
		t.Errorf("did = %q, want %q", gotDID, wantDID)
	}
	// Re-derive from the loaded key to prove it is the same private key.
	if reDID, _ := didKeyFromSecp256k1Priv(priv); reDID != wantDID {
		t.Errorf("loaded key derives did %q, want %q", reDID, wantDID)
	}
}

// TestLoadLedgerSigner_RejectsPEM is the regression for the P-256/secp256k1
// catastrophe: a PEM (the old x509 path) must be rejected with a clear message,
// never mis-parsed into an off-curve identity.
func TestLoadLedgerSigner_RejectsPEM(t *testing.T) {
	pem := "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----\n"
	path := writeKey(t, pem)
	_, _, err := loadOrGenerateLedgerSigner(path, quietLogger())
	if err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("want PEM-rejection error, got %v", err)
	}
}

func TestLoadLedgerSigner_RejectsBadHexAndLength(t *testing.T) {
	// not hex
	if _, _, err := loadOrGenerateLedgerSigner(writeKey(t, "nothex!!"), quietLogger()); err == nil {
		t.Error("non-hex key must fail")
	}
	// valid hex, wrong length (16 bytes, not 32)
	if _, _, err := loadOrGenerateLedgerSigner(writeKey(t, hex.EncodeToString(make([]byte, 16))), quietLogger()); err == nil {
		t.Error("16-byte scalar must fail (secp256k1 needs 32)")
	}
}

// TestLoadLedgerSigner_EphemeralWhenEmpty: empty keyFile mints an ephemeral key
// (local-dev path) and still returns a valid secp256k1 did:key.
func TestLoadLedgerSigner_EphemeralWhenEmpty(t *testing.T) {
	priv, did, err := loadOrGenerateLedgerSigner("", quietLogger())
	if err != nil {
		t.Fatalf("ephemeral load: %v", err)
	}
	if priv == nil || !strings.HasPrefix(did, "did:key:z") {
		t.Fatalf("ephemeral key invalid: priv=%v did=%q", priv != nil, did)
	}
}
