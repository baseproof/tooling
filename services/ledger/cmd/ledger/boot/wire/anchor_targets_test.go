package wire

// anchor_targets_test.go — the 4d derivation chain's law, pinned:
//
//   WHICH from the constitution; WHERE from declarations; env canary only
//   pre-first-declaration; boot-fatal = a constitutional target with no
//   endpoint anywhere; declaration-vs-env disagreement fatal (the demotion);
//   #94's closure: a declaration makes ResolvePeer's on-log branch live and
//   the env value is IGNORED for that parent.

import (
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

func targetsDoc(t1, t2 string) network.BootstrapDocument {
	return network.BootstrapDocument{
		GenesisAnchoring: &network.GenesisAnchoringPolicy{
			Mode:               network.GenesisEndorsementRequire,
			MaxIntervalSeconds: 3600,
			Targets:            []network.AnchorTarget{{NetworkID: t1}, {NetworkID: t2}},
			MinDistinctTargets: 1,
		},
	}
}

func declRecord(t *testing.T, targetHex, logDID, admissionURL string, seq uint64) network.AnchorTargetDeclarationRecord {
	t.Helper()
	tb, err := network.AnchorTarget{NetworkID: targetHex}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return network.AnchorTargetDeclarationRecord{
		EffectivePos: types.LogPosition{LogDID: "did:self", Sequence: seq},
		Payload: network.AnchorTargetDeclaration{
			TargetNetworkID: tb,
			LogDID:          logDID,
			Endpoints: map[string]string{
				network.AnchorTargetAdmissionService: admissionURL,
				network.AnchorTargetReadService:      "https://" + logDID + ".example/read",
			},
		},
	}
}

func TestProjectAnchorTargetGraph(t *testing.T) {
	t1, t2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	doc := targetsDoc(t1, t2)
	asOf := types.LogPosition{LogDID: "did:self", Sequence: 100}

	// t1 declared (and later superseded — the walker must pick the newer);
	// t2 undeclared.
	recs := []network.AnchorTargetDeclarationRecord{
		declRecord(t, t1, "did:parent-one", "https://p1.example/v1/entries", 5),
		declRecord(t, t1, "did:parent-one", "https://p1-new.example/v1/entries", 20),
	}
	graph, declared, undeclared := projectAnchorTargetGraph(doc, "did:self", recs, asOf)
	if graph == nil || len(graph.Siblings) != 1 {
		t.Fatalf("graph = %+v, want one projected sibling", graph)
	}
	if graph.Siblings[0].AdmissionURL != "https://p1-new.example/v1/entries" {
		t.Fatalf("supersession not honored: %q", graph.Siblings[0].AdmissionURL)
	}
	if graph.ThisLog.LogDID != "did:self" {
		t.Fatal("graph lost its own log identity")
	}
	if len(declared) != 1 || len(undeclared) != 1 || undeclared[0] != t2 {
		t.Fatalf("declared=%d undeclared=%v", len(declared), undeclared)
	}

	// No targets ⇒ no graph (legacy constitutions are untouched).
	g2, _, _ := projectAnchorTargetGraph(network.BootstrapDocument{}, "did:self", recs, asOf)
	if g2 != nil {
		t.Fatal("a targets-less constitution projected a graph")
	}
}

func TestDeriveParentEndpoints_Chain(t *testing.T) {
	t1, t2 := strings.Repeat("1", 64), strings.Repeat("2", 64)
	doc := targetsDoc(t1, t2)
	declOnly := map[string]network.AnchorTargetDeclaration{
		t1: {
			LogDID: "did:parent-one",
			Endpoints: map[string]string{
				network.AnchorTargetAdmissionService: "https://p1.example/v1/entries",
			},
		},
	}

	t.Run("declaration + canary cover both → boot", func(t *testing.T) {
		eps, err := deriveParentEndpoints(doc, declOnly, "did:parent-two", "https://p2.example/v1/entries")
		if err != nil {
			t.Fatalf("derivation failed: %v", err)
		}
		if len(eps) != 2 {
			t.Fatalf("eps = %+v", eps)
		}
		if !eps[0].FromDeclaration || eps[0].AdmissionURL != "https://p1.example/v1/entries" {
			t.Fatalf("t1 must come from its declaration: %+v", eps[0])
		}
		if eps[1].FromDeclaration || eps[1].LogDID != "did:parent-two" {
			t.Fatalf("t2 must ride the pre-declaration canary: %+v", eps[1])
		}
	})

	t.Run("uncovered constitutional target → boot-fatal", func(t *testing.T) {
		if _, err := deriveParentEndpoints(doc, declOnly, "", ""); err == nil ||
			!strings.Contains(err.Error(), "NO resolvable endpoint") {
			t.Fatalf("an unfulfillable commitment booted: %v", err)
		}
	})

	t.Run("env disagreeing with the declaration → fatal (the demotion)", func(t *testing.T) {
		_, err := deriveParentEndpoints(doc, declOnly, "did:parent-one", "https://rogue.example/v1/entries")
		if err == nil || !strings.Contains(err.Error(), "declaration is authoritative") {
			t.Fatalf("a disagreeing env canary was tolerated: %v", err)
		}
	})

	t.Run("env agreeing with the declaration → fine (cross-check passes)", func(t *testing.T) {
		// t2 needs the canary; for t1 the env names the SAME URL the
		// declaration does — a passing cross-check, not a conflict. The env
		// DID matches t1's parent here, so t2 is uncovered → expect the
		// boot-fatal for t2, proving the env was consumed as t1's
		// cross-check, not as t2's canary.
		_, err := deriveParentEndpoints(doc, declOnly, "did:parent-one", "https://p1.example/v1/entries")
		if err == nil || !strings.Contains(err.Error(), t2[:16]) {
			t.Fatalf("want t2's no-endpoint fatal, got: %v", err)
		}
	})

	t.Run("no targets → nothing derived (legacy path untouched)", func(t *testing.T) {
		eps, err := deriveParentEndpoints(network.BootstrapDocument{}, nil, "did:p", "https://p.example/v1/entries")
		if err != nil || eps != nil {
			t.Fatalf("legacy constitution must derive nothing: %v %v", eps, err)
		}
	})
}
