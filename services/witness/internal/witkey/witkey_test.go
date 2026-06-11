package witkey

/*
witkey_test.go — the key-material fail-closed contracts.

LoadPEM/DecodePEM is the witness daemon's ONLY door from on-disk bytes to a
signing key. Its happy path is covered transitively (the daemon e2e + main_test
round-trip a generated key), but key-material handling earns its NEGATIVES: a
wrong-curve key, a truncated scalar, or an empty file must fail loudly here —
never parse as the wrong curve and cosign with it. T0; no daemon, no network.
*/

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestDecodePEM_RoundTrip(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	got, err := DecodePEM(EncodePEM(priv))
	if err != nil {
		t.Fatalf("DecodePEM(EncodePEM): %v", err)
	}
	if got.D.Cmp(priv.D) != 0 {
		t.Fatal("round-trip changed the scalar — EncodePEM/DecodePEM are not inverses")
	}
	// The derived did:key is stable across the round-trip (the identity the
	// ledger/JN bind witness sets to).
	d1, _ := DID(priv)
	d2, _ := DID(got)
	if d1 == "" || d1 != d2 {
		t.Fatalf("DID drift across round-trip: %q vs %q", d1, d2)
	}
}

func TestDecodePEM_EmptyOrMalformed_NoBlock(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":     {},
		"garbage":   []byte("not a pem file at all"),
		"truncated": []byte("-----BEGIN BASEPROOF SECP256K1 PRIVATE KEY-----\nnope"),
	} {
		if _, err := DecodePEM(data); err == nil {
			t.Errorf("%s: DecodePEM accepted non-PEM bytes", name)
		} else if !strings.Contains(err.Error(), "no PEM block") {
			t.Errorf("%s: error %q, want the no-PEM-block refusal", name, err)
		}
	}
}

// TestDecodePEM_WrongType_RefusesSEC1 is the load-bearing negative: a stdlib
// "EC PRIVATE KEY" block (the SEC1 type a legacy P-256 key is written under)
// must be refused BY TYPE before any scalar parse — the exact wrong-curve
// confusion PEMType exists to prevent. The bytes are irrelevant; the type gate
// fires first.
func TestDecodePEM_WrongType_RefusesSEC1(t *testing.T) {
	wrong := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: make([]byte, scalarLen)})

	_, err := DecodePEM(wrong)
	if err == nil {
		t.Fatal("DecodePEM accepted an 'EC PRIVATE KEY' block — a wrong-curve key would cosign")
	}
	if !strings.Contains(err.Error(), "PEM type") || !strings.Contains(err.Error(), PEMType) {
		t.Fatalf("error %q must name the type mismatch and the expected %q", err, PEMType)
	}
}

func TestDecodePEM_WrongScalarLength_Refused(t *testing.T) {
	for name, n := range map[string]int{"short": 31, "long": 33, "zero": 0} {
		blk := pem.EncodeToMemory(&pem.Block{Type: PEMType, Bytes: make([]byte, n)})
		if _, err := DecodePEM(blk); err == nil {
			t.Errorf("%s (%d bytes): accepted a wrong-length scalar", name, n)
		} else if !strings.Contains(err.Error(), "scalar is") {
			t.Errorf("%s: error %q, want the scalar-length refusal", name, err)
		}
	}
}

func TestLoadPEM_MissingFile(t *testing.T) {
	if _, err := LoadPEM("/no/such/witkey.pem"); err == nil {
		t.Fatal("LoadPEM accepted a missing file")
	}
}
