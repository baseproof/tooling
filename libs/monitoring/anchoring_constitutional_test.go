package monitoring

// anchoring_constitutional_test.go — the two-reasons contract:
//
//   reason 1 (the SDK ladder): under-quota/absent → Critical with the SDK's
//   Reason verbatim; stale (legacy path) → Warning;
//   reason 2 (cannot-corroborate): unreachable parents → their OWN Warning
//   alert + counter, NEVER synthesized into evidence — and when nothing was
//   collected, reason 1 INDEPENDENTLY goes Critical (the fail-closed
//   compound).
//
// Per-target ages ride in Details/scan as counters; a healthy scan emits no
// alerts. Evidence here is REAL: a one-witness set whose key cosigns the
// heads, so the SDK reduction's lineage binding genuinely runs.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/did"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
	"github.com/baseproof/baseproof/witness"
)

// anchoringFixture: a real 1-of-1 witness set + a head it cosigned.
type anchoringFixture struct {
	set *cosign.WitnessKeySet
	pin [32]byte
	t1  string
	t2  string
}

func newAnchoringFixture(t *testing.T) (*anchoringFixture, types.CosignedTreeHead) {
	t.Helper()
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var pin [32]byte
	pin[0] = 0x5E
	keys, err := witness.KeysFromDIDs([]string{kp.DID})
	if err != nil {
		t.Fatalf("KeysFromDIDs: %v", err)
	}
	set, err := cosign.NewWitnessKeySet(keys, cosign.NetworkID(pin), 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xBB}, TreeSize: 1000,
		},
	}
	signer := cosign.NewECDSAWitnessSigner(kp.PrivateKey)
	sig, err := signer.Sign(context.Background(), cosign.NewTreeHeadPayload(head.TreeHead), cosign.NetworkID(pin), cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatalf("cosign: %v", err)
	}
	head.Signatures = []types.WitnessSignature{sig}
	return &anchoringFixture{
		set: set,
		pin: pin,
		t1:  strings.Repeat("1", 64),
		t2:  strings.Repeat("2", 64),
	}, head
}

func (f *anchoringFixture) targetsPolicy(minDistinct uint) *network.GenesisAnchoringPolicy {
	return &network.GenesisAnchoringPolicy{
		Mode:               network.GenesisEndorsementRequire,
		MaxIntervalSeconds: 3600,
		Targets:            []network.AnchorTarget{{NetworkID: f.t1}, {NetworkID: f.t2}},
		MinDistinctTargets: minDistinct,
	}
}

func targetBytes(t *testing.T, h string) [32]byte {
	t.Helper()
	b, err := network.AnchorTarget{NetworkID: h}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func collectOf(ev ...verifier.AnchorEvidence) func(context.Context) ([]verifier.AnchorEvidence, []error) {
	return func(context.Context) ([]verifier.AnchorEvidence, []error) { return ev, nil }
}

func TestConstitutionalAnchoring_QuotaMet_NoAlerts(t *testing.T) {
	f, head := newAnchoringFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	fresh := now.Add(-10 * time.Minute)
	ev := func(target [32]byte) verifier.AnchorEvidence {
		return verifier.AnchorEvidence{Head: head, AnchorNetworkID: target, AnchoredAt: fresh, VerifiedAt: fresh}
	}
	res, alerts := CheckConstitutionalAnchoring(context.Background(), ConstitutionalAnchoringConfig{
		Policy: f.targetsPolicy(2), Pin: f.pin, CurrentSet: f.set,
		Parents: []AnchoringParent{
			{LogDID: "did:p1", Collect: collectOf(ev(targetBytes(t, f.t1)))},
			{LogDID: "did:p2", Collect: collectOf(ev(targetBytes(t, f.t2)))},
		},
	}, now)
	if len(alerts) != 0 {
		t.Fatalf("healthy scan emitted alerts: %+v", alerts)
	}
	if !res.Finding.OK || res.Finding.DistinctFreshTargets != 2 {
		t.Fatalf("finding = %+v, want OK with 2 distinct fresh", res.Finding)
	}
	if len(res.PerTargetAge) != 2 {
		t.Fatalf("per-target ages = %v, want both targets", res.PerTargetAge)
	}
	if age := res.PerTargetAge[f.t1]; age != 10*time.Minute {
		t.Fatalf("t1 age = %v, want 10m", age)
	}
}

func TestConstitutionalAnchoring_UnderQuota_CriticalWithSDKReason(t *testing.T) {
	f, head := newAnchoringFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	fresh := now.Add(-10 * time.Minute)
	res, alerts := CheckConstitutionalAnchoring(context.Background(), ConstitutionalAnchoringConfig{
		Policy: f.targetsPolicy(2), Pin: f.pin, CurrentSet: f.set,
		Parents: []AnchoringParent{
			{LogDID: "did:p1", Collect: collectOf(verifier.AnchorEvidence{
				Head: head, AnchorNetworkID: targetBytes(t, f.t1), AnchoredAt: fresh, VerifiedAt: fresh,
			})},
			{LogDID: "did:p2", Collect: collectOf()}, // reachable, simply no anchors
		},
	}, now)
	if res.Finding.OK {
		t.Fatal("one of two required targets fresh — must not be OK")
	}
	if len(alerts) != 1 || alerts[0].Severity != sdkmonitoring.Critical {
		t.Fatalf("want exactly the Critical ladder alert, got %+v", alerts)
	}
	if !strings.Contains(alerts[0].Message, "under quota") {
		t.Fatalf("ladder alert must carry the SDK reason verbatim, got %q", alerts[0].Message)
	}
	if res.CannotCorroborate != 0 {
		t.Fatal("an empty-but-successful collection is NOT cannot-corroborate")
	}
}

// TestConstitutionalAnchoring_TwoDistinctReasons is the load-bearing split:
// every parent unreachable ⇒ BOTH the cannot-corroborate Warning (reason 2,
// a collection failure) AND the SDK Critical (reason 1 — with nothing
// collected, the commitment is unmet: fail-closed). Two alerts, two
// vocabularies, never folded.
func TestConstitutionalAnchoring_TwoDistinctReasons(t *testing.T) {
	f, _ := newAnchoringFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	failing := func(context.Context) ([]verifier.AnchorEvidence, []error) {
		return nil, []error{context.DeadlineExceeded}
	}
	res, alerts := CheckConstitutionalAnchoring(context.Background(), ConstitutionalAnchoringConfig{
		Policy: f.targetsPolicy(2), Pin: f.pin, CurrentSet: f.set,
		Parents: []AnchoringParent{
			{LogDID: "did:p1", Collect: failing},
			{LogDID: "did:p2", Collect: failing},
		},
	}, now)
	if res.CannotCorroborate != 2 {
		t.Fatalf("CannotCorroborate = %d, want 2", res.CannotCorroborate)
	}
	if len(alerts) != 2 {
		t.Fatalf("want the ladder Critical AND the cannot-corroborate Warning, got %+v", alerts)
	}
	var sawCritical, sawCannot bool
	for _, a := range alerts {
		switch {
		case a.Severity == sdkmonitoring.Critical:
			sawCritical = true
		case a.Severity == sdkmonitoring.Warning && strings.Contains(a.Message, "cannot corroborate"):
			sawCannot = true
		}
	}
	if !sawCritical || !sawCannot {
		t.Fatalf("the two reasons were folded: %+v", alerts)
	}
}

func TestConstitutionalAnchoring_LegacyNoTargets_StaleWarns(t *testing.T) {
	f, head := newAnchoringFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	stale := now.Add(-2 * time.Hour) // bound 1h
	var extParent [32]byte
	extParent[0] = 0xEE
	policy := &network.GenesisAnchoringPolicy{Mode: network.GenesisEndorsementRequire, MaxIntervalSeconds: 3600}
	_, alerts := CheckConstitutionalAnchoring(context.Background(), ConstitutionalAnchoringConfig{
		Policy: policy, Pin: f.pin, CurrentSet: f.set,
		Parents: []AnchoringParent{{LogDID: "did:legacy-parent", Collect: collectOf(
			verifier.AnchorEvidence{Head: head, AnchorNetworkID: extParent, AnchoredAt: stale, VerifiedAt: stale},
		)}},
	}, now)
	if len(alerts) != 1 || alerts[0].Severity != sdkmonitoring.Warning {
		t.Fatalf("legacy stale must be the ladder Warning, got %+v", alerts)
	}
}

func TestConstitutionalAnchoring_NoCommitment_Silent(t *testing.T) {
	res, alerts := CheckConstitutionalAnchoring(context.Background(), ConstitutionalAnchoringConfig{}, time.Unix(1_700_000_000, 0))
	if len(alerts) != 0 || !res.Finding.OK {
		t.Fatalf("no commitment must be silent/OK: %+v %+v", res.Finding, alerts)
	}
}
