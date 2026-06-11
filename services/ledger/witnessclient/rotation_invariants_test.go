/*
FILE PATH: witnessclient/rotation_invariants_test.go

The C-series (tier T2 — Ledger + Postgres): the witness-set capture
defenses, proven at the LEDGER boundary (ProcessRotation), not just in the
SDK. rc4 added two rules to witness.VerifyRotation that ProcessRotation
inherits with ZERO ledger code change — exactly why they need ledger-level
tests:

  - the quorum-intersection invariant 2K>N (a compromised quorum must not be
    able to grow N past 2K and seat members in the disjoint slots, because
    two disjoint K-quorums make a fork unprovable equivocation), and
  - Step-6 per-joiner consent (every joining witness must countersign).

A rejection that HALF-APPLIED would be worse than acceptance, so the reject
cases assert BOTH the sentinel error AND the absence of every side effect:
no witness_sets row, no in-memory swap, no gossip emit. Verify runs before
persist runs before emit (rotation_handler.go), so a Verify failure must
leave the world untouched.

The diluting / unconsented rotations are hand-assembled (witnesstest /
RotationDraft REFUSE to build them) through the same ceremony→signature
adapter the production path uses — everything a pre-rc4 verifier demanded is
present; only the new rule is violated, so acceptance would prove the gate
is the thing rejecting it.
*/
package witnessclient_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	"github.com/baseproof/baseproof/witness/witnesstest"
)

// witnessSetRowCount returns (active, total) witness_sets rows.
func witnessSetRowCount(t *testing.T, pool *pgxpool.Pool) (active, total int) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM witness_sets WHERE retired_seq IS NULL").Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM witness_sets").Scan(&total); err != nil {
		t.Fatalf("count total: %v", err)
	}
	return active, total
}

// signAll routes member endorsements through the production
// ceremony→signature adapter — the same path RotationDraft uses — so the
// hand-built rotations below are signature-complete, isolating the rule under
// test as the lone reason for rejection.
func signAll(t *testing.T, set *witnesstest.Set, payload cosign.CosignPayload, count int) []types.WitnessSignature {
	t.Helper()
	sigs := make([]types.WitnessSignature, count)
	for i := 0; i < count; i++ {
		sig, err := witness.SignatureFromEndorsement(set.Endorse(t, historyNetID(), payload, i))
		if err != nil {
			t.Fatalf("SignatureFromEndorsement[%d]: %v", i, err)
		}
		sigs[i] = sig
	}
	return sigs
}

// TestProcessRotation_RejectsDilution [C]: a FULLY-SIGNED rotation that grows N
// past 2K (predecessor quorum complete, every joiner consenting) is refused at
// the ledger boundary with ErrQuorumRatioViolated — and leaves no row, no swap,
// no emit. The #74 DoD: the capture fix proven where the ledger applies it.
func TestProcessRotation_RejectsDilution(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)

	rh, old := withHandler(t, pool, 2, 3) // K=2
	emit := &countingEmitter{}
	rh.WithEmitter(emit)
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 1})

	// N' = 2K = 4: 2K <= N' — two disjoint K-quorums. Fully signed anyway.
	next := witnesstest.NewSet(t, historyNetID(), 4, 1)
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(next.Keys))
	rot := types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(old.Keys),
		NewSet:            next.Keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		SchemeTagNew:      signatures.SchemeECDSA,
		CurrentSignatures: signAll(t, old, payload, old.KeySet.Quorum()),
		NewSignatures:     signAll(t, next, payload, len(next.Keys)),
	}

	out, err := rh.ProcessRotation(context.Background(), rot)
	if !errors.Is(err, witness.ErrQuorumRatioViolated) {
		t.Fatalf("want ErrQuorumRatioViolated, got %v", err)
	}
	if out != nil {
		t.Errorf("returned keys on rejection = %v, want nil (no in-memory swap)", out)
	}
	if active, total := witnessSetRowCount(t, pool); active != 0 || total != 0 {
		t.Errorf("rejected dilution left rows (active=%d total=%d); Verify must precede persist", active, total)
	}
	if emit.calls != 0 {
		t.Errorf("emitter fired %d times on a rejected rotation; want 0 (verify-before-emit)", emit.calls)
	}
}

// TestProcessRotation_RejectsJoinerWithoutConsent [C]: a member-add rotation
// with a complete predecessor quorum but NO joiner countersignature is refused
// with ErrJoinerConsentMissing — state untouched. Everything the pre-rc4
// verifier demanded is present; only Step-6 consent is missing.
func TestProcessRotation_RejectsJoinerWithoutConsent(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)

	rh, old := withHandler(t, pool, 2, 3)
	emit := &countingEmitter{}
	rh.WithEmitter(emit)
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 1})

	// Same-size next set (2K>N holds), predecessor quorum signs, but the
	// joining witnesses do NOT countersign — a single placeholder satisfies
	// Validate's non-empty NewSignatures without being real consent.
	next := witnesstest.NewSet(t, historyNetID(), 3, 2)
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(next.Keys))
	var placeholderID [32]byte
	for i := range placeholderID {
		placeholderID[i] = 0xEE
	}
	rot := types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(old.Keys),
		NewSet:            next.Keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		SchemeTagNew:      signatures.SchemeECDSA,
		CurrentSignatures: signAll(t, old, payload, old.KeySet.Quorum()),
		NewSignatures: []types.WitnessSignature{
			{PubKeyID: placeholderID, SchemeTag: signatures.SchemeECDSA, SigBytes: []byte{0xAA}},
		},
	}

	out, err := rh.ProcessRotation(context.Background(), rot)
	if !errors.Is(err, witness.ErrJoinerConsentMissing) {
		t.Fatalf("want ErrJoinerConsentMissing, got %v", err)
	}
	if out != nil {
		t.Errorf("returned keys on rejection = %v, want nil", out)
	}
	if active, total := witnessSetRowCount(t, pool); active != 0 || total != 0 {
		t.Errorf("unconsented rotation left rows (active=%d total=%d)", active, total)
	}
	if emit.calls != 0 {
		t.Errorf("emitter fired %d times on a rejected rotation; want 0", emit.calls)
	}
}

// TestProcessRotation_AcceptsKitMintedRotation [C]: a witnesstest.MintRotation
// product — valid by construction — flows the whole hot path: verify → on-log
// append → witness_sets insert → in-memory swap → gossip emit. The
// Draft→ProcessRotation composition proof: valid-by-construction reaches the
// ledger.
func TestProcessRotation_AcceptsKitMintedRotation(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)

	rh, old := withHandler(t, pool, 2, 3)
	emit := &countingEmitter{}
	rh.WithEmitter(emit)
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 7})

	next := witnesstest.NewSet(t, historyNetID(), 3, 2)
	rot := witnesstest.MintRotation(t, historyNetID(), old, next, 2)

	out, err := rh.ProcessRotation(context.Background(), rot)
	if err != nil {
		t.Fatalf("kit-minted rotation must flow end-to-end: %v", err)
	}
	if len(out) != len(next.Keys) {
		t.Errorf("returned %d keys, want %d (the new set)", len(out), len(next.Keys))
	}
	if active, total := witnessSetRowCount(t, pool); active != 1 || total != 1 {
		t.Errorf("accepted rotation rows: active=%d total=%d, want 1/1", active, total)
	}
	if emit.calls != 1 {
		t.Errorf("emitter fired %d times on an accepted rotation; want exactly 1", emit.calls)
	}
}

// NOTE on the dual-sign × ratio case: the worry that a scheme transition
// (ECDSA→BLS) could launder a dilution past the 2K>N gate is a property of
// witness.VerifyRotation — the ratio check (Step 1.5) runs before the dual-sign
// branch (Step 5). The ledger has NO independent ratio logic; ProcessRotation
// delegates to VerifyRotation, so it inherits that ordering. It is locked
// directly by the SDK's TestQuorumRatio_DualSign_DiluteRejected (over real BLS
// keys). Re-proving it here would mean fabricating a BLS new-set purely to
// drive an SDK-internal branch the ledger does not reimplement — an isolated
// technical test, not a systemic one — and at this boundary ProcessRotation's
// encode step (which requires signatures) precedes the ratio gate anyway. The
// systemic ledger-boundary guarantee is "dilution is rejected with no side
// effects", proven above by TestProcessRotation_RejectsDilution.

// TestProcessRotation_BenignShapes [C]: shapes that satisfy 2K>N and Step-6 are
// NOT false-rejected — a same-size re-key and a removal-only rotation (the
// holdover-acknowledgment shape) both flow to a persisted active set.
func TestProcessRotation_BenignShapes(t *testing.T) {
	for _, c := range []struct {
		name    string
		newN, k int
	}{
		{"same-size re-key 3->3 (K=2: 4>3)", 3, 2},
		{"removal 3->2 (K=2: 4>2)", 2, 2},
	} {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			pool := requireWitnessDSN(t)
			rh, old := withHandler(t, pool, c.k, 3)
			rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: 3})

			next := witnesstest.NewSet(t, historyNetID(), c.newN, c.k)
			rot := witnesstest.MintRotation(t, historyNetID(), old, next, c.k)
			if _, err := rh.ProcessRotation(context.Background(), rot); err != nil {
				t.Fatalf("%s must be accepted: %v", c.name, err)
			}
			if active, _ := witnessSetRowCount(t, pool); active != 1 {
				t.Errorf("%s: active rows = %d, want 1", c.name, active)
			}
		})
	}
}
