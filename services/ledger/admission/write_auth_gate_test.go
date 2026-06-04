package admission

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/crypto/signatures"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type stubKeyset struct {
	set [][20]byte
	err error
}

func (s stubKeyset) Current(context.Context) ([][20]byte, error) { return s.set, s.err }

func newGateAuthority(t *testing.T) (sk *secp256k1.PrivateKey, addr [20]byte) {
	t.Helper()
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	a, err := signatures.AddressFromPubkey(k.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	return k, a
}

func encodedAuth(t *testing.T, sk *secp256k1.PrivateKey, logDID string, id, anchor [32]byte) string {
	t.Helper()
	wa, err := authz.SignWriteAuthorization(sk.ToECDSA(), logDID, id, anchor)
	if err != nil {
		t.Fatal(err)
	}
	b, err := wa.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestVerifyWriteAuthorization_Gate(t *testing.T) {
	ctx := context.Background()
	logDID := "did:web:court.example"
	var id, anchor [32]byte
	id[0] = 1
	sk, addr := newGateAuthority(t)
	enc := encodedAuth(t, sk, logDID, id, anchor)

	// Success.
	if err := VerifyWriteAuthorization(ctx, enc, id, logDID, stubKeyset{set: [][20]byte{addr}}); err != nil {
		t.Fatalf("valid: %v", err)
	}
	// Missing.
	if err := VerifyWriteAuthorization(ctx, "", id, logDID, stubKeyset{set: [][20]byte{addr}}); !errors.Is(err, ErrWriteAuthMissing) {
		t.Errorf("missing: %v", err)
	}
	// Malformed base64.
	if err := VerifyWriteAuthorization(ctx, "!!!not-base64!!!", id, logDID, stubKeyset{set: [][20]byte{addr}}); !errors.Is(err, ErrWriteAuthMalformed) {
		t.Errorf("bad base64: %v", err)
	}
	// Valid base64, malformed authorization.
	if err := VerifyWriteAuthorization(ctx, base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), id, logDID, stubKeyset{set: [][20]byte{addr}}); !errors.Is(err, ErrWriteAuthMalformed) {
		t.Errorf("bad decode: %v", err)
	}
	// Unauthorized (signer not in set).
	_, other := newGateAuthority(t)
	if err := VerifyWriteAuthorization(ctx, enc, id, logDID, stubKeyset{set: [][20]byte{other}}); !errors.Is(err, authz.ErrUnauthorizedWriter) {
		t.Errorf("unauthorized: %v", err)
	}
	// Empty authorized set → fail-closed.
	if err := VerifyWriteAuthorization(ctx, enc, id, logDID, stubKeyset{set: nil}); !errors.Is(err, authz.ErrEmptyAuthoritySet) {
		t.Errorf("empty set: %v", err)
	}
	// Nil keyset → fail-closed.
	if err := VerifyWriteAuthorization(ctx, enc, id, logDID, nil); !errors.Is(err, authz.ErrEmptyAuthoritySet) {
		t.Errorf("nil keyset: %v", err)
	}
	// Keyset source error propagates (not unauthorized).
	boom := errors.New("db down")
	if err := VerifyWriteAuthorization(ctx, enc, id, logDID, stubKeyset{err: boom}); !errors.Is(err, boom) {
		t.Errorf("source error: %v", err)
	}
	// Wrong entry identity → recovers a different address → unauthorized.
	var id2 [32]byte
	id2[0] = 99
	if err := VerifyWriteAuthorization(ctx, enc, id2, logDID, stubKeyset{set: [][20]byte{addr}}); !errors.Is(err, authz.ErrUnauthorizedWriter) {
		t.Errorf("rebind entry: %v", err)
	}
}
