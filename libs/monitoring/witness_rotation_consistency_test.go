// FILE PATH: libs/monitoring/witness_rotation_consistency_test.go
//
// Tests for the witness-rotation consistency audit: the SAFETY half (chain
// integrity, on-chain head) must alert Critical at any instant it is violated;
// the LIVENESS half (adoption) must stay silent inside the async grace window
// and warn only after it — real ECDSA sets, rotations, and cosigned heads.
package monitoring

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkmon "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

var wrcNetID = func() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(i + 3)
	}
	return n
}()

const wrcLogDID = "did:web:rotation.audit.test"

type wrcKit struct {
	set   *cosign.WitnessKeySet
	keys  []types.WitnessPublicKey
	privs []*ecdsa.PrivateKey
}

func newWRCKit(t *testing.T, n, k int) wrcKit {
	t.Helper()
	keys := make([]types.WitnessPublicKey, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		p, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pub := signatures.PubKeyBytes(&p.PublicKey)
		keys[i] = types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA}
		privs[i] = p
	}
	set, err := cosign.NewWitnessKeySet(keys, wrcNetID, k, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	return wrcKit{set: set, keys: keys, privs: privs}
}

func (w wrcKit) rotationTo(t *testing.T, next wrcKit) types.WitnessRotation {
	t.Helper()
	payload := cosign.NewRotationPayloadSHA256(witness.ComputeSetHash(next.keys))
	sigs := make([]types.WitnessSignature, w.set.Quorum())
	for i := 0; i < w.set.Quorum(); i++ {
		sb, err := cosign.SignECDSA(payload, wrcNetID, cosign.HashAlgoSHA256, w.privs[i])
		if err != nil {
			t.Fatalf("SignECDSA: %v", err)
		}
		sigs[i] = types.WitnessSignature{PubKeyID: w.keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	return types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(w.keys),
		NewSet:            next.keys,
		SchemeTagOld:      signatures.SchemeECDSA,
		SchemeTagNew:      signatures.SchemeECDSA,
		CurrentSignatures: sigs,
	}
}

func (w wrcKit) cosign(t *testing.T, size uint64, root byte) types.CosignedTreeHead {
	t.Helper()
	th := types.TreeHead{TreeSize: size, RootHash: [32]byte{root}, SMTRoot: [32]byte{0xBB}, ReceiptRoot: [32]byte{0xCC}}
	payload := cosign.NewTreeHeadPayload(th)
	sigs := make([]types.WitnessSignature, w.set.Quorum())
	for i := 0; i < w.set.Quorum(); i++ {
		sb, err := cosign.SignECDSA(payload, wrcNetID, cosign.HashAlgoSHA256, w.privs[i])
		if err != nil {
			t.Fatalf("SignECDSA head: %v", err)
		}
		sigs[i] = types.WitnessSignature{PubKeyID: w.keys[i].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sb}
	}
	return types.CosignedTreeHead{TreeHead: th, Signatures: sigs}
}

func runWRC(t *testing.T, lg RotationLogState, grace time.Duration, now time.Time) []sdkmon.Alert {
	t.Helper()
	alerts, err := CheckWitnessRotationConsistency(context.Background(),
		WitnessRotationConsistencyConfig{Logs: []RotationLogState{lg}, Grace: grace}, now)
	if err != nil {
		t.Fatalf("CheckWitnessRotationConsistency: %v", err)
	}
	return alerts
}

func TestWitnessRotationConsistency_AdoptedNewSet_Healthy(t *testing.T) {
	s0, s1 := newWRCKit(t, 3, 2), newWRCKit(t, 3, 2)
	now := time.Now()
	head := s1.cosign(t, 200, 0x01) // new set adopted
	alerts := runWRC(t, RotationLogState{
		LogDID:  wrcLogDID,
		Genesis: s0.set,
		Records: []types.WitnessRotationRecord{{
			Rotation:     s0.rotationTo(t, s1),
			EffectivePos: types.LogPosition{LogDID: wrcLogDID, Sequence: 100},
		}},
		LatestRotationRecordedAt: now.Add(-24 * time.Hour), // far past grace
		LatestHead:               &head,
	}, time.Hour, now)
	if len(alerts) != 0 {
		t.Fatalf("adopted rotation must be silent, got %v", alerts)
	}
}

func TestWitnessRotationConsistency_OffChainHead_Critical(t *testing.T) {
	s0, rogue := newWRCKit(t, 3, 2), newWRCKit(t, 3, 2)
	head := rogue.cosign(t, 50, 0x02) // cosigned by keys on NO chain
	alerts := runWRC(t, RotationLogState{
		LogDID: wrcLogDID, Genesis: s0.set, LatestHead: &head,
	}, time.Hour, time.Now())
	if len(alerts) != 1 || alerts[0].Severity != sdkmon.Critical {
		t.Fatalf("off-chain head must be one Critical alert, got %v", alerts)
	}
}

func TestWitnessRotationConsistency_NotAdopted_WarnsOnlyAfterGrace(t *testing.T) {
	s0, s1 := newWRCKit(t, 3, 2), newWRCKit(t, 3, 2)
	now := time.Now()
	oldSetHead := s0.cosign(t, 200, 0x03) // post-rotation head STILL old-set-cosigned
	state := func(recordedAt time.Time) RotationLogState {
		return RotationLogState{
			LogDID:  wrcLogDID,
			Genesis: s0.set,
			Records: []types.WitnessRotationRecord{{
				Rotation:     s0.rotationTo(t, s1),
				EffectivePos: types.LogPosition{LogDID: wrcLogDID, Sequence: 100},
			}},
			LatestRotationRecordedAt: recordedAt,
			LatestHead:               &oldSetHead,
		}
	}

	// INSIDE the grace window: the fuzzy cosign switch is expected — silent.
	if alerts := runWRC(t, state(now.Add(-10*time.Minute)), time.Hour, now); len(alerts) != 0 {
		t.Fatalf("inside grace must be silent (async adoption window), got %v", alerts)
	}
	// PAST the grace window: Warning (liveness), never Critical (not fraud).
	alerts := runWRC(t, state(now.Add(-2*time.Hour)), time.Hour, now)
	if len(alerts) != 1 || alerts[0].Severity != sdkmon.Warning {
		t.Fatalf("past grace must be one Warning, got %v", alerts)
	}
}

func TestWitnessRotationConsistency_NoPostRotationHead_WarnsAfterGrace(t *testing.T) {
	s0, s1 := newWRCKit(t, 3, 2), newWRCKit(t, 3, 2)
	now := time.Now()
	preHead := s0.cosign(t, 80, 0x04) // head PREDATES the rotation at 100
	alerts := runWRC(t, RotationLogState{
		LogDID:  wrcLogDID,
		Genesis: s0.set,
		Records: []types.WitnessRotationRecord{{
			Rotation:     s0.rotationTo(t, s1),
			EffectivePos: types.LogPosition{LogDID: wrcLogDID, Sequence: 100},
		}},
		LatestRotationRecordedAt: now.Add(-2 * time.Hour),
		LatestHead:               &preHead,
	}, time.Hour, now)
	if len(alerts) != 1 || alerts[0].Severity != sdkmon.Warning {
		t.Fatalf("stalled post-rotation head must be one Warning, got %v", alerts)
	}
}

func TestWitnessRotationConsistency_BrokenChain_Critical(t *testing.T) {
	s0, s1, s2 := newWRCKit(t, 3, 2), newWRCKit(t, 3, 2), newWRCKit(t, 3, 2)
	alerts := runWRC(t, RotationLogState{
		LogDID:  wrcLogDID,
		Genesis: s0.set,
		// s1→s2 cannot verify under genesis s0: the chain is broken.
		Records: []types.WitnessRotationRecord{{
			Rotation:     s1.rotationTo(t, s2),
			EffectivePos: types.LogPosition{LogDID: wrcLogDID, Sequence: 10},
		}},
	}, time.Hour, time.Now())
	if len(alerts) != 1 || alerts[0].Severity != sdkmon.Critical {
		t.Fatalf("broken chain must be one Critical alert, got %v", alerts)
	}
}

func TestWitnessRotationConsistency_NeverRotated_NoHead_Silent(t *testing.T) {
	s0 := newWRCKit(t, 3, 2)
	if alerts := runWRC(t, RotationLogState{LogDID: wrcLogDID, Genesis: s0.set}, time.Hour, time.Now()); len(alerts) != 0 {
		t.Fatalf("never-rotated log with no head must be silent, got %v", alerts)
	}
}
