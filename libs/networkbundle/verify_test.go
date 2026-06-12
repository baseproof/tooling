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
