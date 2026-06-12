/*
FILE PATH: libs/networkbundle/verify_test.go

DESCRIPTION:

	Pins the verify door's three fail-closed rules:

	  WIRE      — non-canonical bytes refused (reformatting = tampering);
	  IDENTITY  — missing or mismatched network_id refused against the
	              hash-verified constitution;
	  QUORUM    — quorum_k present-and-disagreeing with GenesisQuorumK is
	              fatal (cache, never source); absent (0) is accepted.

	Plus: nil bootstrap refused with the discovery-never-authority message,
	and the happy path returns the decoded document.
*/
package networkbundle

import (
	"encoding/hex"
	"strings"
	"testing"
)

// verifiableManifest returns canonical bytes for a manifest bound to doc's
// identity, with quorum_k as given (0 ⇒ omitted from the wire).
func verifiableManifest(t *testing.T, networkIDHex string, quorumK int) []byte {
	t.Helper()
	m := refManifest()
	m.Network.NetworkID = networkIDHex
	m.Network.QuorumK = quorumK
	b, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyManifest_HappyPath(t *testing.T) {
	doc, _ := testBootstrap(t)
	ids, err := doc.IDs()
	if err != nil {
		t.Fatal(err)
	}
	idHex := hex.EncodeToString(ids.NetworkID[:])

	for _, k := range []int{0, doc.GenesisQuorumK} { // absent cache, and agreeing cache
		raw := verifiableManifest(t, idHex, k)
		m, err := VerifyManifest(raw, doc)
		if err != nil {
			t.Fatalf("quorum_k=%d must verify: %v", k, err)
		}
		if m.Network.NetworkID != idHex {
			t.Fatalf("verified manifest lost identity: %s", m.Network.NetworkID)
		}
	}
}

func TestVerifyManifest_NilBootstrapRefused(t *testing.T) {
	_, err := VerifyManifest([]byte("{}"), nil)
	if err == nil || !strings.Contains(err.Error(), "discovery, never authority") {
		t.Fatalf("nil bootstrap must refuse with the trust-flow rule: %v", err)
	}
}

func TestVerifyManifest_NonCanonicalBytesRefused(t *testing.T) {
	doc, _ := testBootstrap(t)
	ids, _ := doc.IDs()
	raw := verifiableManifest(t, hex.EncodeToString(ids.NetworkID[:]), 0)

	// Trailing whitespace still strict-decodes — but it is not the canonical
	// form, so the door refuses it.
	_, err := VerifyManifest(append(raw, ' '), doc)
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("reformatted bytes must be refused: %v", err)
	}
}

func TestVerifyManifest_IdentityRules(t *testing.T) {
	doc, _ := testBootstrap(t)

	// No network_id ⇒ unbindable.
	raw := verifiableManifest(t, "", 0)
	if _, err := VerifyManifest(raw, doc); err == nil || !strings.Contains(err.Error(), "no network_id") {
		t.Fatalf("a manifest naming no network must refuse: %v", err)
	}

	// A different network ⇒ refused, naming both ids.
	raw = verifiableManifest(t, strings.Repeat("ee", 32), 0)
	_, err := VerifyManifest(raw, doc)
	if err == nil || !strings.Contains(err.Error(), "names network") {
		t.Fatalf("a manifest naming another network must refuse: %v", err)
	}
}

func TestVerifyManifest_QuorumIsCacheNeverSource(t *testing.T) {
	doc, _ := testBootstrap(t) // GenesisQuorumK = 1
	ids, _ := doc.IDs()
	raw := verifiableManifest(t, hex.EncodeToString(ids.NetworkID[:]), doc.GenesisQuorumK+1)

	_, err := VerifyManifest(raw, doc)
	if err == nil || !strings.Contains(err.Error(), "single source of K") {
		t.Fatalf("a disagreeing quorum cache must be fatal: %v", err)
	}
}

// ─── PRE-3: the driveable-operation anchor rule ──────────────────────

func TestValidate_OperationDatatypeMustResolve(t *testing.T) {
	m := refManifest()
	m.Operations[0].Datatype = "ghost/v1"
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), `datatype "ghost/v1"`) {
		t.Fatalf("an operation naming an undeclared datatype is authoring drift: %v", err)
	}
}

func TestVerifyManifest_DriveableOpRequiresAnchoredDatatype(t *testing.T) {
	doc, _ := testBootstrap(t)
	ids, _ := doc.IDs()
	idHex := hex.EncodeToString(ids.NetworkID[:])

	// Anchored (the reference manifest's datatype carries the full anchor):
	// verifies.
	raw := verifiableManifest(t, idHex, 0)
	if _, err := VerifyManifest(raw, doc); err != nil {
		t.Fatalf("anchored driveable op must verify: %v", err)
	}

	// Strip the anchor: Validate still passes (structural name resolves),
	// but the DOOR refuses — materialization is fail-closed by construction.
	m := refManifest()
	m.Network.NetworkID = idHex
	m.Network.QuorumK = 0
	m.Datatypes[0].LogDID = ""
	m.Datatypes[0].Sequence = 0
	m.Datatypes[0].ContentHash = ""
	if vErr := m.Validate(); vErr != nil {
		t.Fatalf("unanchored datatype must still be structurally valid: %v", vErr)
	}
	b, _ := m.CanonicalBytes()
	_, err := VerifyManifest(b, doc)
	if err == nil || !strings.Contains(err.Error(), "without an on-log anchor") {
		t.Fatalf("the door must refuse a driveable op without an anchored datatype: %v", err)
	}
}
