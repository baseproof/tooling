package crosslog

import (
	"context"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
)

// fakeRotations is a RotationResolver returning a fixed record slice / error.
type fakeRotations struct {
	recs []verifier.RotationRecord
	err  error
}

func (f fakeRotations) Build(_ context.Context, _ string, _ []byte) ([]verifier.RotationRecord, error) {
	return f.recs, f.err
}

func hopAt(seq uint64, e *envelope.Entry) *verifier.EvidenceHop {
	return &verifier.EvidenceHop{
		Position: types.LogPosition{LogDID: "did:web:onlog", Sequence: seq},
		Entry:    e,
	}
}

// keyRegistry returns a did:key-only SignatureVerifier registry.
func keyRegistry(t *testing.T) *did.VerifierRegistry {
	t.Helper()
	reg := did.NewVerifierRegistry()
	if err := reg.Register("key", did.NewKeyVerifier()); err != nil {
		t.Fatalf("register key verifier: %v", err)
	}
	return reg
}

// ── nil guards ────────────────────────────────────────────────────────────

func TestVerifyHop_NilHop(t *testing.T) {
	d := &HopDispatcher{Registry: keyRegistry(t)}
	if err := d.VerifyHop(context.Background(), nil); !errors.Is(err, ErrNilHop) {
		t.Fatalf("nil hop err = %v, want ErrNilHop", err)
	}
	if err := d.VerifyHop(context.Background(), &verifier.EvidenceHop{}); !errors.Is(err, ErrNilHop) {
		t.Fatalf("nil entry err = %v, want ErrNilHop", err)
	}
}

// ── registry (off-log) path ───────────────────────────────────────────────

func TestVerifyHop_Registry_DIDKeyValid(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	e := signedEntry(t, kp.DID, kp.PrivateKey)
	d := &HopDispatcher{Registry: keyRegistry(t)} // GovernsOnLog nil → registry path
	if err := d.VerifyHop(context.Background(), hopAt(5, e)); err != nil {
		t.Fatalf("VerifyHop: %v", err)
	}
}

func TestVerifyHop_Registry_TamperedSig(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("GenerateDIDKeySecp256k1: %v", err)
	}
	e := signedEntry(t, kp.DID, kp.PrivateKey)
	e.Signatures[0].Bytes[0] ^= 0xFF // corrupt R

	d := &HopDispatcher{Registry: keyRegistry(t)}
	err = d.VerifyHop(context.Background(), hopAt(5, e))
	if !errors.Is(err, ErrHopSignatureInvalid) {
		t.Fatalf("err = %v, want ErrHopSignatureInvalid", err)
	}
}

func TestVerifyHop_Registry_Nil(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	e := signedEntry(t, kp.DID, kp.PrivateKey)
	d := &HopDispatcher{} // no Registry, no GovernsOnLog
	if err := d.VerifyHop(context.Background(), hopAt(5, e)); !errors.Is(err, ErrHopMisconfigured) {
		t.Fatalf("err = %v, want ErrHopMisconfigured", err)
	}
}

// ── on-log (rotation) path ────────────────────────────────────────────────

const onLogSigner = "did:web:example:exchange-a#signer-1"

func onLogDispatcher(initial []byte, recs []verifier.RotationRecord) *HopDispatcher {
	return &HopDispatcher{
		Rotations:    fakeRotations{recs: recs},
		InitialKey:   func(_ context.Context, _ string) ([]byte, error) { return initial, nil },
		GovernsOnLog: func(s string) bool { return s == onLogSigner },
	}
}

func TestVerifyHop_OnLog_InitialKeyValid(t *testing.T) {
	priv, pub := secpKey(t)
	e := signedEntry(t, onLogSigner, priv)
	d := onLogDispatcher(pub, nil) // no rotations → initial key is active
	if err := d.VerifyHop(context.Background(), hopAt(7, e)); err != nil {
		t.Fatalf("VerifyHop: %v", err)
	}
}

func TestVerifyHop_OnLog_RotatedKeyValid(t *testing.T) {
	_, k0pub := secpKey(t)
	k1priv, k1pub := secpKey(t)
	// Rotation at seq 3 installs k1; hop at seq 7 → k1 is the active key.
	recs := []verifier.RotationRecord{{
		EffectivePos: types.LogPosition{LogDID: "did:web:onlog", Sequence: 3},
		NewPublicKey: k1pub,
	}}
	e := signedEntry(t, onLogSigner, k1priv)
	d := onLogDispatcher(k0pub, recs)
	if err := d.VerifyHop(context.Background(), hopAt(7, e)); err != nil {
		t.Fatalf("VerifyHop (rotated): %v", err)
	}
}

// Position binding: the SAME rotation history resolves DIFFERENT active keys
// either side of the rotation's effective position.
func TestVerifyHop_OnLog_PositionBinding(t *testing.T) {
	k0priv, k0pub := secpKey(t)
	k1priv, k1pub := secpKey(t)
	recs := []verifier.RotationRecord{{
		EffectivePos: types.LogPosition{LogDID: "did:web:onlog", Sequence: 3},
		NewPublicKey: k1pub,
	}}
	d := onLogDispatcher(k0pub, recs)
	ctx := context.Background()

	// Before the rotation (seq 2): k0 active.
	if err := d.VerifyHop(ctx, hopAt(2, signedEntry(t, onLogSigner, k0priv))); err != nil {
		t.Errorf("seq 2 signed by k0 should pass: %v", err)
	}
	if err := d.VerifyHop(ctx, hopAt(2, signedEntry(t, onLogSigner, k1priv))); !errors.Is(err, ErrHopSignatureInvalid) {
		t.Errorf("seq 2 signed by k1 should fail: %v", err)
	}
	// After the rotation (seq 7): k1 active.
	if err := d.VerifyHop(ctx, hopAt(7, signedEntry(t, onLogSigner, k1priv))); err != nil {
		t.Errorf("seq 7 signed by k1 should pass: %v", err)
	}
	if err := d.VerifyHop(ctx, hopAt(7, signedEntry(t, onLogSigner, k0priv))); !errors.Is(err, ErrHopSignatureInvalid) {
		t.Errorf("seq 7 signed by k0 should fail: %v", err)
	}
}

func TestVerifyHop_OnLog_WrongKeyInvalid(t *testing.T) {
	_, pub := secpKey(t)
	wrongPriv, _ := secpKey(t)
	e := signedEntry(t, onLogSigner, wrongPriv) // signed by a key that is not active
	d := onLogDispatcher(pub, nil)
	if err := d.VerifyHop(context.Background(), hopAt(7, e)); !errors.Is(err, ErrHopSignatureInvalid) {
		t.Fatalf("err = %v, want ErrHopSignatureInvalid", err)
	}
}

func TestVerifyHop_OnLog_Misconfigured(t *testing.T) {
	priv, pub := secpKey(t)
	e := signedEntry(t, onLogSigner, priv)
	ctx := context.Background()

	noRot := &HopDispatcher{
		InitialKey:   func(_ context.Context, _ string) ([]byte, error) { return pub, nil },
		GovernsOnLog: func(s string) bool { return s == onLogSigner },
	}
	if err := noRot.VerifyHop(ctx, hopAt(7, e)); !errors.Is(err, ErrHopMisconfigured) {
		t.Errorf("nil Rotations err = %v, want ErrHopMisconfigured", err)
	}

	noInit := &HopDispatcher{
		Rotations:    fakeRotations{},
		GovernsOnLog: func(s string) bool { return s == onLogSigner },
	}
	if err := noInit.VerifyHop(ctx, hopAt(7, e)); !errors.Is(err, ErrHopMisconfigured) {
		t.Errorf("nil InitialKey err = %v, want ErrHopMisconfigured", err)
	}
}

func TestVerifyHop_OnLog_Unsigned(t *testing.T) {
	_, pub := secpKey(t)
	d := onLogDispatcher(pub, nil)
	ctx := context.Background()

	noSig := &envelope.Entry{Header: envelope.ControlHeader{SignerDID: onLogSigner}}
	if err := d.VerifyHop(ctx, hopAt(7, noSig)); !errors.Is(err, ErrHopUnsigned) {
		t.Errorf("no-sig err = %v, want ErrHopUnsigned", err)
	}

	wrongAlgo := &envelope.Entry{
		Header:     envelope.ControlHeader{SignerDID: onLogSigner},
		Signatures: []envelope.Signature{{SignerDID: onLogSigner, AlgoID: envelope.SigAlgoEd25519, Bytes: []byte{0x01}}},
	}
	if err := d.VerifyHop(ctx, hopAt(7, wrongAlgo)); !errors.Is(err, ErrHopUnsigned) {
		t.Errorf("wrong-algo err = %v, want ErrHopUnsigned", err)
	}
}

func TestVerifyHop_OnLog_InitialKeyError(t *testing.T) {
	priv, _ := secpKey(t)
	e := signedEntry(t, onLogSigner, priv)
	boom := errors.New("boom")
	d := &HopDispatcher{
		Rotations:    fakeRotations{},
		InitialKey:   func(_ context.Context, _ string) ([]byte, error) { return nil, boom },
		GovernsOnLog: func(s string) bool { return s == onLogSigner },
	}
	if err := d.VerifyHop(context.Background(), hopAt(7, e)); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestVerifyHop_OnLog_RotationsError(t *testing.T) {
	priv, pub := secpKey(t)
	e := signedEntry(t, onLogSigner, priv)
	boom := errors.New("boom")
	d := &HopDispatcher{
		Rotations:    fakeRotations{err: boom},
		InitialKey:   func(_ context.Context, _ string) ([]byte, error) { return pub, nil },
		GovernsOnLog: func(s string) bool { return s == onLogSigner },
	}
	if err := d.VerifyHop(context.Background(), hopAt(7, e)); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

// A signer that GovernsOnLog rejects must take the registry path even when
// the rotation deps are present.
func TestVerifyHop_GovernsOnLogFalse_UsesRegistry(t *testing.T) {
	kp, _ := did.GenerateDIDKeySecp256k1()
	e := signedEntry(t, kp.DID, kp.PrivateKey)
	_, pub := secpKey(t)
	d := &HopDispatcher{
		Registry:     keyRegistry(t),
		Rotations:    fakeRotations{},
		InitialKey:   func(_ context.Context, _ string) ([]byte, error) { return pub, nil },
		GovernsOnLog: func(string) bool { return false },
	}
	if err := d.VerifyHop(context.Background(), hopAt(5, e)); err != nil {
		t.Fatalf("VerifyHop via registry: %v", err)
	}
}
