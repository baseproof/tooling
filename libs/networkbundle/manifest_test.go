/*
FILE PATH: libs/networkbundle/manifest_test.go

DESCRIPTION:

	Pins the manifest's wire contract and graph mechanics:

	  - WIRE COMPATIBILITY: a golden document carrying ONLY the original
	    field set (as published before the schema moved into libs) decodes
	    and validates — the relocation changed the package, never the wire;
	  - canonical bytes are deterministic and ContentHash is their sha256;
	  - DecodeManifest is strict (unknown fields refused) and Validate
	    rejects every malformed shape with an error naming the defect;
	  - the additive fields (NetworkRef.LogDID, Endpoint.Auth,
	    Admission.EpochWindowSec, Federation) round-trip, and Auth is a
	    closed enum;
	  - graph mechanics: OperationKind/NewOperation classification, the
	    hard-cycle check (single-ancestor edges only — OR alternatives
	    never false-positive), deterministic TopoOrder incl. the cycle
	    residue path, and transitive DependentsOf incl. OR edges.

	Fixtures use a neutral vocabulary (record_opened / amendment /
	decision / publication; operator / approver) — the schema owns no
	domain.
*/
package networkbundle

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/baseproof/tooling/libs/policy"
	"github.com/baseproof/tooling/libs/prereq"
)

// hardReq returns a Hard ancestor rule (single or OR list).
func hardReq(ancestors ...string) prereq.Prereq {
	return prereq.Prereq{Mode: prereq.PrereqModeHard, RequiredAncestor: ancestors, Reason: "test edge"}
}

func advisoryReq(ancestors ...string) prereq.Prereq {
	return prereq.Prereq{Mode: prereq.PrereqModeAdvisory, RequiredAncestor: ancestors, Reason: "advisory edge"}
}

// refManifest is a representative, fully-valid document exercising every
// section, in the neutral vocabulary.
func refManifest() *Manifest {
	return &Manifest{
		Format:   ManifestFormat,
		Network:  NetworkRef{NetworkID: strings.Repeat("ab", 32), Name: "testnet", BootstrapEndpoint: "https://ledger.example", QuorumK: 2, LogDID: "did:web:ledger.example"},
		Exchange: "did:web:exchange.example",
		Endpoints: []Endpoint{
			{ID: "ledger", URL: "https://ledger.example", Protocol: "baseproof-ledger/v1", Transport: Transport{TLS: "server-verify"}},
			{ID: "gate", URL: "https://gate.example", Transport: Transport{TLS: "mtls", CAPin: strings.Repeat("cd", 32)}, Auth: AuthMTLS, DependsOn: []string{"ledger"}},
		},
		Admission: Admission{Payment: []string{"pow"}, Gating: "write-authorization", WriteVia: "gate", EpochWindowSec: 300},
		Submit:    Submit{Endpoint: "gate", Path: "/v1/entries/submit"},
		Status:    StatusProbes{Protocol: "ledger:/v1/entries-hash/{hash}", Finality: "ledger:/v1/tree/horizon", Domain: "closed_by chain"},
		Roles: []policy.Role{{
			Name: "approver", Actor: policy.ActorSigner,
			MaxDuration: 720, DefaultDuration: 168,
			AllowedScope: []string{"approve:record"}, DefaultScope: []string{"approve:record"},
		}},
		Datatypes: []Datatype{{Name: "record/v1", URI: "https://schemas.example/record-v1", LogDID: "did:web:ledger.example", Sequence: 7, ContentHash: strings.Repeat("ef", 32)}},
		Operations: []Operation{
			NewOperation("record_opened", nil, nil, OpOverlay{PrimaryRole: "approver", Datatype: "record/v1", Mints: []string{"record_id"}}),
			NewOperation("amendment",
				&policy.CosignatureRule{EventType: "amendment", AllowedFilerRoles: []policy.FilerRole{"operator"}, RequiredSignerRoles: []string{"approver"}, IntraExchangeOnly: true},
				[]prereq.Prereq{hardReq("record_opened")},
				OpOverlay{References: []string{"record_opened"}}),
			NewOperation("decision", nil, []prereq.Prereq{hardReq("record_opened")}, OpOverlay{ClosedBy: []string{"publication"}}),
			NewOperation("publication", nil, []prereq.Prereq{hardReq("decision")}, OpOverlay{}),
		},
		Federation: []FederatedNet{{Name: "peer", NetworkID: strings.Repeat("12", 32), Endpoint: "https://peer.example"}},
	}
}

// ─── wire compatibility ──────────────────────────────────────────────

// goldenPreMoveManifest is a document with ONLY the field set that existed
// before the schema moved into libs — no log_did, no auth, no
// epoch_window_sec, no federation. It must decode and validate untouched.
const goldenPreMoveManifest = `{
  "format": "baseproof-network-manifest/v1",
  "network": {"network_id": "` + "abababababababababababababababababababababababababababababababab" + `", "name": "legacy", "bootstrap_endpoint": "https://l.example", "quorum_k": 1},
  "exchange": "did:web:legacy.example",
  "endpoints": [{"id": "ledger", "url": "https://l.example", "transport": {"tls": "server-verify"}}],
  "admission": {"payment": ["pow"], "gating": "open", "write_via": "ledger"},
  "submit": {"endpoint": "ledger", "path": "/v1/entries"},
  "status": {"protocol": "ledger:/v1/entries-hash/{hash}", "finality": "ledger:/v1/tree/horizon", "domain": "closed_by chain"},
  "roles": [{"name": "approver", "actor": 1, "max_duration": 720, "default_duration": 168, "allowed_scope": ["approve:record"], "default_scope": ["approve:record"]}],
  "datatypes": [{"name": "record/v1", "uri": "https://schemas.example/record-v1"}],
  "operations": [
    {"event_type": "record_opened", "kind": "origin"},
    {"event_type": "amendment", "kind": "dependent",
     "signing": {"event_type": "amendment", "allowed_filer_roles": ["operator"], "required_signer_roles": ["approver"], "intra_exchange_only": true},
     "requires": [{"mode": 1, "required_ancestor": ["record_opened"], "reason": "needs an open record"}]}
  ]
}`

func TestDecodeManifest_GoldenPreMoveDocument(t *testing.T) {
	m, err := DecodeManifest([]byte(goldenPreMoveManifest))
	if err != nil {
		t.Fatalf("a pre-move manifest must decode unchanged: %v", err)
	}
	if m.Network.Name != "legacy" || len(m.Operations) != 2 {
		t.Fatalf("golden decode lost content: %+v", m)
	}
	op := m.Operations[1]
	if op.Signing == nil || !op.Signing.PermitsFilerRole("operator") {
		t.Error("embedded cosignature rule must survive decode with behavior intact")
	}
	if len(op.Requires) != 1 || !op.Requires[0].IsAncestorRule() {
		t.Error("embedded prerequisite must survive decode with behavior intact")
	}
}

// ─── canonical bytes + hash ──────────────────────────────────────────

func TestCanonicalBytes_DeterministicAndHashed(t *testing.T) {
	m := refManifest()
	b1, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := m.CanonicalBytes()
	if !bytes.Equal(b1, b2) {
		t.Fatal("canonical bytes must be deterministic across calls")
	}
	h, err := m.ContentHash()
	if err != nil {
		t.Fatal(err)
	}
	if h != sha256.Sum256(b1) {
		t.Fatal("ContentHash must be sha256(CanonicalBytes)")
	}

	// And the canonical bytes round-trip through the strict decoder.
	back, err := DecodeManifest(b1)
	if err != nil {
		t.Fatalf("canonical bytes must re-decode: %v", err)
	}
	b3, _ := back.CanonicalBytes()
	if !bytes.Equal(b1, b3) {
		t.Fatal("decode(canonical) must re-canonicalize to identical bytes")
	}
}

// ─── strictness + validation ─────────────────────────────────────────

func TestDecodeManifest_UnknownFieldRefused(t *testing.T) {
	doc := strings.Replace(goldenPreMoveManifest, `"exchange"`, `"surprise": 1, "exchange"`, 1)
	if _, err := DecodeManifest([]byte(doc)); err == nil {
		t.Fatal("strict decode must refuse unknown fields (future vintages are not silently misread)")
	}
}

func TestValidate_Rejections(t *testing.T) {
	mutate := func(f func(*Manifest)) *Manifest {
		m := refManifest()
		f(m)
		return m
	}
	cases := []struct {
		name string
		m    *Manifest
		want string
	}{
		{"wrong format", mutate(func(m *Manifest) { m.Format = "baseproof-network-manifest/v0" }), "format"},
		{"missing exchange", mutate(func(m *Manifest) { m.Exchange = "" }), "exchange is required"},
		{"empty event_type", mutate(func(m *Manifest) { m.Operations[0].EventType = "" }), "empty event_type"},
		{"duplicate operation", mutate(func(m *Manifest) { m.Operations[1].EventType = "record_opened" }), "duplicate operation"},
		{"closed_by to unknown", mutate(func(m *Manifest) { m.Operations[2].ClosedBy = []string{"ghost"} }), `closed_by "ghost"`},
		{"references unknown", mutate(func(m *Manifest) { m.Operations[1].References = []string{"ghost"} }), `references "ghost"`},
		{"endpoint without url", mutate(func(m *Manifest) { m.Endpoints[0].URL = "" }), "needs id + url"},
		{"duplicate endpoint", mutate(func(m *Manifest) { m.Endpoints[1].ID = "ledger" }), "duplicate endpoint"},
		{"depends_on unknown", mutate(func(m *Manifest) { m.Endpoints[1].DependsOn = []string{"ghost"} }), `depends_on unknown "ghost"`},
		{"submit to undeclared endpoint", mutate(func(m *Manifest) { m.Submit.Endpoint = "ghost" }), "not a declared endpoint"},
		{"bad auth posture", mutate(func(m *Manifest) { m.Endpoints[0].Auth = "password" }), "want none|mtls|signed-envelope"},
		{"federation without id", mutate(func(m *Manifest) { m.Federation = append(m.Federation, FederatedNet{Name: "anon"}) }), "needs network_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if err == nil {
				t.Fatal("must reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should contain %q", err, tc.want)
			}
		})
	}

	// Every Auth posture in the closed set is accepted (incl. empty).
	for _, auth := range []string{"", AuthNone, AuthMTLS, AuthSignedEnvelope} {
		m := refManifest()
		m.Endpoints[0].Auth = auth
		if err := m.Validate(); err != nil {
			t.Errorf("auth %q must validate: %v", auth, err)
		}
	}
}

func TestAdditiveFields_RoundTrip(t *testing.T) {
	b, err := refManifest().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	m, err := DecodeManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Network.LogDID != "did:web:ledger.example" {
		t.Error("NetworkRef.LogDID lost")
	}
	if m.Admission.EpochWindowSec != 300 {
		t.Error("Admission.EpochWindowSec lost")
	}
	if m.Endpoints[1].Auth != AuthMTLS {
		t.Error("Endpoint.Auth lost")
	}
	if len(m.Federation) != 1 || m.Federation[0].NetworkID != strings.Repeat("12", 32) {
		t.Error("Federation lost")
	}
}

// ─── graph mechanics ─────────────────────────────────────────────────

func TestOperationKindAndNewOperation(t *testing.T) {
	if k := OperationKind(nil); k != "origin" {
		t.Errorf("no rules ⇒ origin, got %s", k)
	}
	if k := OperationKind([]prereq.Prereq{advisoryReq("a")}); k != "origin" {
		t.Errorf("advisory-only ⇒ origin, got %s", k)
	}
	auth := []prereq.Prereq{{Mode: prereq.PrereqModeHard, RequiredAuthority: "approve:record", Reason: "authority only"}}
	if k := OperationKind(auth); k != "origin" {
		t.Errorf("authority-gated without ancestors ⇒ origin, got %s", k)
	}
	if k := OperationKind([]prereq.Prereq{hardReq("a")}); k != "dependent" {
		t.Errorf("hard ancestor ⇒ dependent, got %s", k)
	}

	// NewOperation copies the overlay slices — composers can reuse buffers.
	mints := []string{"record_id"}
	op := NewOperation("evt", nil, nil, OpOverlay{Mints: mints})
	mints[0] = "vandalized"
	if op.Mints[0] != "record_id" {
		t.Error("NewOperation must copy overlay slices, not alias them")
	}
}

func TestValidate_HardCycle(t *testing.T) {
	m := refManifest()
	// record_opened → decision → record_opened (via single-ancestor hard edges).
	m.Operations[0] = NewOperation("record_opened", nil, []prereq.Prereq{hardReq("decision")}, OpOverlay{})
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("a single-ancestor hard cycle must be rejected with a witness: %v", err)
	}

	// OR-alternative lists are NOT unconditional edges — no false positive.
	m2 := refManifest()
	m2.Operations[0] = NewOperation("record_opened", nil, []prereq.Prereq{hardReq("decision", "publication")}, OpOverlay{})
	if err := m2.Validate(); err != nil {
		t.Fatalf("an OR-alternative back-edge must not trip the cycle check: %v", err)
	}
}

func TestTopoOrder(t *testing.T) {
	m := refManifest()
	order := m.TopoOrder()
	pos := map[string]int{}
	for i, evt := range order {
		pos[evt] = i
	}
	if len(order) != len(m.Operations) {
		t.Fatalf("TopoOrder covered %d of %d operations", len(order), len(m.Operations))
	}
	for _, edge := range [][2]string{{"record_opened", "amendment"}, {"record_opened", "decision"}, {"decision", "publication"}} {
		if pos[edge[0]] > pos[edge[1]] {
			t.Errorf("TopoOrder violates %s → %s: %v", edge[0], edge[1], order)
		}
	}
	// Deterministic across calls.
	again := m.TopoOrder()
	for i := range order {
		if order[i] != again[i] {
			t.Fatalf("TopoOrder must be deterministic: %v vs %v", order, again)
		}
	}

	// Cycle residue: a cyclic pair still yields a complete, deterministic order.
	cyc := refManifest()
	cyc.Operations = []Operation{
		NewOperation("a", nil, []prereq.Prereq{hardReq("b")}, OpOverlay{}),
		NewOperation("b", nil, []prereq.Prereq{hardReq("a")}, OpOverlay{}),
	}
	if got := cyc.TopoOrder(); len(got) != 2 {
		t.Fatalf("cycle residue must still order every operation: %v", got)
	}
}

func TestDependentsOf(t *testing.T) {
	m := refManifest()
	got := m.DependentsOf("record_opened")
	want := []string{"amendment", "decision", "publication"} // publication transitively via decision
	if len(got) != len(want) {
		t.Fatalf("DependentsOf = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DependentsOf = %v, want %v (sorted)", got, want)
		}
	}

	// OR-alternatives count: any rule NAMING evt makes the dependent sensitive.
	m2 := refManifest()
	m2.Operations = append(m2.Operations,
		NewOperation("audit_note", nil, []prereq.Prereq{hardReq("decision", "publication")}, OpOverlay{}))
	deps := m2.DependentsOf("publication")
	found := false
	for _, d := range deps {
		if d == "audit_note" {
			found = true
		}
	}
	if !found {
		t.Errorf("an OR edge naming the event must appear in DependentsOf: %v", deps)
	}
}
