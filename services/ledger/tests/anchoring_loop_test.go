/*
FILE PATH: tests/anchoring_loop_test.go

THE PR-4 CLOSURE LOOP, composed from the real pieces end to end (in-process —
the HTTP seams it elides each carry their own contract tests: the by-source
handler, the anchorfeed pager, the confirmer):

	a require+targets CHILD's cosigned head
	  → the REAL anchor entry (sdk anchor.BuildCosignedAnchorEntry, signed)
	  → read back through the parent log handle (anchorfeed over MultiLog)
	  → the SDK reduction + constitutional monitor:
	      fresh under quota        ⇒ OK, no alerts, per-target ages counted
	      clock past the bound     ⇒ the ladder fires (under quota ⇒ Critical)
	      publisher "stopped"      ⇒ stays Critical (absent evidence)
	      self/fork evidence       ⇒ IGNORED (pin-equality; still Critical)
	      parent unreachable       ⇒ cannot-corroborate Warning + ladder
	                                 Critical (two reasons, never folded)

The remaining altitude — the docker fleet stage where a ceremony-built child
anchors into a real parent ledger over HTTP — is the shared #77/PR-4 fleet
deliverable and rides the e2e module's stack.
*/
package tests

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	sdkanchor "github.com/baseproof/baseproof/anchor"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/did"
	sdkmonitoring "github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/verifier"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/anchorfeed"
	libsmonitoring "github.com/baseproof/tooling/libs/monitoring"
)

// loopFetcher is the parent log's read backend (the trusted side of the
// MultiLog registration).
type loopFetcher struct{ entries map[uint64][]byte }

func (f *loopFetcher) Fetch(_ context.Context, pos types.LogPosition) (*types.EntryWithMetadata, error) {
	raw, ok := f.entries[pos.Sequence]
	if !ok {
		return nil, fmt.Errorf("no entry at %d", pos.Sequence)
	}
	return &types.EntryWithMetadata{CanonicalBytes: raw, Position: pos}, nil
}

func TestAnchoringLoop_EndToEnd(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	// ── The CHILD: a 1-of-1 witness set under its pin, with a cosigned head
	// (the publisher's input).
	wkp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	var childPin [32]byte
	childPin[0] = 0xC4
	childLogDID := "did:baseproof:network:child"
	wkeys, err := witness.KeysFromDIDs([]string{wkp.DID})
	if err != nil {
		t.Fatal(err)
	}
	childSet, err := cosign.NewWitnessKeySet(wkeys, cosign.NetworkID(childPin), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{
		RootHash: [32]byte{0xA1}, SMTRoot: [32]byte{0xB2}, TreeSize: 500,
	}}
	signer := cosign.NewECDSAWitnessSigner(wkp.PrivateKey)
	sig, err := signer.Sign(ctx, cosign.NewTreeHeadPayload(head.TreeHead), cosign.NetworkID(childPin), cosign.HashAlgoSHA256)
	if err != nil {
		t.Fatal(err)
	}
	head.Signatures = []types.WitnessSignature{sig}

	// ── The constitutional commitment: one target, quota 1, 1h bound.
	targetHex := strings.Repeat("7", 64)
	targetID, err := network.AnchorTarget{NetworkID: targetHex}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	policy := &network.GenesisAnchoringPolicy{
		Mode:               network.GenesisEndorsementRequire,
		MaxIntervalSeconds: 3600,
		Targets:            []network.AnchorTarget{{NetworkID: targetHex}},
		MinDistinctTargets: 1,
	}

	// ── The PUBLISHER's real artifact: the anchor entry as it lands on the
	// parent (BuildCosignedAnchorEntry + author signature), exactly what the
	// fan-out submits.
	parentLogDID := "did:baseproof:network:parent"
	entry, err := sdkanchor.BuildCosignedAnchorEntry(sdkanchor.CosignedAnchorParams{
		SignerDID:    wkp.DID,
		Destination:  parentLogDID,
		SourceLogDID: childLogDID,
		Head:         head,
		NetworkID:    cosign.NetworkID(childPin),
		EventTime:    now.UnixMicro(),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(envelope.SigningPayload(entry))
	asig, err := signatures.SignEntry(h, wkp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: wkp.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: asig}}
	wire, err := envelope.Serialize(entry)
	if err != nil {
		t.Fatal(err)
	}

	// ── The PARENT serves it at seq 12; the feed reads it back through the
	// parent log handle and attributes it to the constitutional target.
	parentML := sdkanchor.NewMultiLog(map[string]sdkanchor.LogConfig{
		parentLogDID: {Fetcher: &loopFetcher{entries: map[uint64][]byte{12: wire}}},
	})
	collect := func(cctx context.Context) ([]verifier.AnchorEvidence, []error) {
		items, errs := anchorfeed.CollectEvidence(cctx, parentML, parentLogDID, targetID,
			[]uint64{12}, nil, func() time.Time { return now })
		return anchorfeed.Evidence(items), errs
	}
	check := func(parents []libsmonitoring.AnchoringParent, at time.Time) (libsmonitoring.AnchoringScanResult, []sdkmonitoring.Alert) {
		return libsmonitoring.CheckConstitutionalAnchoring(ctx, libsmonitoring.ConstitutionalAnchoringConfig{
			Policy: policy, Pin: childPin, CurrentSet: childSet,
			Parents: parents,
		}, at)
	}

	// 1. FRESH: the loop closes — monitor OK, the target's age counted.
	res, alerts := check([]libsmonitoring.AnchoringParent{{LogDID: parentLogDID, Collect: collect}}, now.Add(10*time.Minute))
	if len(alerts) != 0 || !res.Finding.OK || res.Finding.DistinctFreshTargets != 1 {
		t.Fatalf("fresh loop must be OK: finding=%+v alerts=%+v", res.Finding, alerts)
	}
	if _, ok := res.PerTargetAge[targetHex]; !ok {
		t.Fatal("the target's age was not counted")
	}

	// 2. PUBLISHER STOPPED: the clock passes the bound with no new anchor —
	// the ladder fires (targets path: under quota ⇒ Critical).
	res, alerts = check([]libsmonitoring.AnchoringParent{{LogDID: parentLogDID, Collect: collect}}, now.Add(2*time.Hour))
	if res.Finding.OK || len(alerts) != 1 || alerts[0].Severity != sdkmonitoring.Critical {
		t.Fatalf("stopped publisher must go Critical under quota: %+v %+v", res.Finding, alerts)
	}

	// 3. SELF/FORK INJECTION: fresh evidence attributed to the CHILD's OWN pin
	// (a fork shares the NetworkID) is ignored by pin-equality — the posture
	// stays Critical despite the "fresh" forgery.
	forkCollect := func(cctx context.Context) ([]verifier.AnchorEvidence, []error) {
		fresh := now.Add(2*time.Hour - time.Minute)
		return []verifier.AnchorEvidence{{
			Head: head, AnchorNetworkID: childPin, AnchoredAt: fresh, VerifiedAt: fresh,
		}}, nil
	}
	res, alerts = check([]libsmonitoring.AnchoringParent{{LogDID: "did:fork-of-child", Collect: forkCollect}}, now.Add(2*time.Hour))
	if res.Finding.OK {
		t.Fatal("self/fork evidence corroborated the child — pin-equality failed")
	}
	if len(alerts) != 1 || alerts[0].Severity != sdkmonitoring.Critical {
		t.Fatalf("self/fork injection must leave the ladder Critical: %+v", alerts)
	}

	// 4. PARENT UNREACHABLE: cannot-corroborate Warning AND ladder Critical —
	// the two reasons, distinct, in one scan.
	dead := func(context.Context) ([]verifier.AnchorEvidence, []error) {
		return nil, []error{context.DeadlineExceeded}
	}
	res, alerts = check([]libsmonitoring.AnchoringParent{{LogDID: parentLogDID, Collect: dead}}, now.Add(10*time.Minute))
	if res.CannotCorroborate != 1 || len(alerts) != 2 {
		t.Fatalf("unreachable parent must produce both reasons: cannot=%d alerts=%+v", res.CannotCorroborate, alerts)
	}
}
