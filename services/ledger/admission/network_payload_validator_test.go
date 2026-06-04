/*
FILE PATH: admission/network_payload_validator_test.go

v1.32.0 SDK adoption — Tier C tests for the L4 backdoor closure:
per-Kind structural validation of the three new on-log network
payload kinds at the admission front door.

# WHAT THIS LOCKS

VerifyNetworkPayloadEntry's dispatch over WitnessEndpointDeclarationV1,
WitnessIdentityLabelV1, and AuditorRegistrationV1. The gate must:

  - Run the SDK's Validate() on each typed payload.
  - Wrap structural failures in ErrNetworkPayloadInvalid so
    callers can errors.Is on the typed sentinel.
  - Pass through non-network payloads (other entry kinds, malformed
    JSON, empty DomainPayload) without rejection — those are the
    SDK's broader schema gate's responsibility.

Coverage:
  - nil entry → nil (defensive no-op).
  - Empty DomainPayload → nil.
  - Random non-network bytes → nil (no Validate called).
  - Valid AuditorRegistrationV1 payload → nil.
  - Invalid AuditorRegistrationV1 (empty DID) → ErrNetworkPayloadInvalid.
  - Invalid AuditorRegistrationV1 (zero scope) → ErrNetworkPayloadInvalid.
  - Invalid AuditorRegistrationV1 (non-https findings URL) →
    ErrNetworkPayloadInvalid.
  - Error message includes the SDK's structural failure text
    (so operators see WHICH field broke).

Pure unit tests; uses the SDK's real encoder + the live Validate
chain. No mocks for the SDK validators — the L4 contract IS
that the SDK runs.
*/
package admission_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/ledger/admission"
)

// validAuditorRegistration returns the smallest auditor record
// the SDK accepts: ECDSA scheme (no PoP), single scope bit,
// well-formed https URL.
func validAuditorRegistration() network.AuditorRegistration {
	pub := make([]byte, 33)
	pub[0] = 0x02
	return network.AuditorRegistration{
		AuditorDID:  "did:web:auditor.example.org",
		PublicKey:   pub,
		SchemeTag:   1, // ECDSA
		FindingsURL: "https://auditor.example.org/v1/findings",
		Scope:       network.ScopeEquivocation,
	}
}

// entryWithPayload wraps domain bytes into an envelope.Entry the
// way the admission pipeline sees them. No signature is
// required for the L4 path: VerifyNetworkPayloadEntry inspects
// only DomainPayload.
func entryWithPayload(t *testing.T, payload []byte) *envelope.Entry {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:web:test-signer",
		Destination: "did:test:log",
		EventTime:   1700000000,
	}
	e, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return e
}

// ── Pass-through paths ─────────────────────────────────────────────

func TestVerifyNetworkPayloadEntry_NilEntryIsNoop(t *testing.T) {
	if err := admission.VerifyNetworkPayloadEntry(nil); err != nil {
		t.Fatalf("nil entry must return nil; got %v", err)
	}
}

func TestVerifyNetworkPayloadEntry_EmptyDomainPayloadIsNoop(t *testing.T) {
	e := entryWithPayload(t, nil)
	if err := admission.VerifyNetworkPayloadEntry(e); err != nil {
		t.Fatalf("empty DomainPayload must return nil; got %v", err)
	}
}

// TestVerifyNetworkPayloadEntry_NonNetworkPayloadPassesThrough
// covers the dispatch's negative path: an entry whose payload is
// some OTHER kind (a finding, a tree-head publish, application
// data) MUST NOT trigger any of the three Validate paths. The
// gate returns nil and the entry continues through the rest of
// admission. A regression that rejected unknown kinds would
// break every non-network-payload entry on the log.
func TestVerifyNetworkPayloadEntry_NonNetworkPayloadPassesThrough(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"kind":"some_other_v1","field":"value"}`),
		[]byte(`{"not_even_json: ofc`),
		[]byte("raw binary bytes that aren't JSON at all"),
		[]byte(`{}`),
	}
	for _, payload := range cases {
		e := entryWithPayload(t, payload)
		if err := admission.VerifyNetworkPayloadEntry(e); err != nil {
			t.Errorf("non-network payload must pass through; got %v for %q",
				err, string(payload[:minInt(len(payload), 32)]))
		}
	}
}

// ── AuditorRegistrationV1 paths ────────────────────────────────────

// TestVerifyNetworkPayloadEntry_ValidAuditorRegistrationAccepted
// is the success-path lock: a payload encoded with the SDK's own
// EncodeAuditorRegistrationPayload (which runs Validate internally)
// MUST pass the gate. If this regresses, every valid auditor
// registration entry gets a 422 at the front door.
func TestVerifyNetworkPayloadEntry_ValidAuditorRegistrationAccepted(t *testing.T) {
	payload, err := network.EncodeAuditorRegistrationPayload(validAuditorRegistration())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	e := entryWithPayload(t, payload)
	if err := admission.VerifyNetworkPayloadEntry(e); err != nil {
		t.Fatalf("valid AuditorRegistration must pass; got %v", err)
	}
}

// TestVerifyNetworkPayloadEntry_InvalidAuditorRegistrationRejected
// is the load-bearing L4 invariant: a structurally malformed
// auditor registration MUST be rejected at the admission gate,
// wrapped in ErrNetworkPayloadInvalid. We construct the wire
// payload by hand (the SDK's encoder would refuse) so we
// exercise the decoder's Validate path.
func TestVerifyNetworkPayloadEntry_InvalidAuditorRegistrationRejected(t *testing.T) {
	cases := []struct {
		label  string
		wire   map[string]any
		expect string // substring of the structural failure
	}{
		{
			label: "empty auditor_did",
			wire: map[string]any{
				"kind":         network.AuditorRegistrationKindV1,
				"auditor_did":  "",
				"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
				"scheme_tag":   1,
				"findings_url": "https://auditor.example.org/v1/findings",
				"scope":        2,
			},
			expect: "auditor_did",
		},
		{
			label: "zero scope",
			wire: map[string]any{
				"kind":         network.AuditorRegistrationKindV1,
				"auditor_did":  "did:web:auditor.example.org",
				"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
				"scheme_tag":   1,
				"findings_url": "https://auditor.example.org/v1/findings",
				"scope":        0,
			},
			expect: "scope",
		},
		{
			label: "http (not https) findings_url",
			wire: map[string]any{
				"kind":         network.AuditorRegistrationKindV1,
				"auditor_did":  "did:web:auditor.example.org",
				"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
				"scheme_tag":   1,
				"findings_url": "http://auditor.example.org/v1/findings",
				"scope":        2,
			},
			expect: "https",
		},
		{
			label: "zero scheme tag",
			wire: map[string]any{
				"kind":         network.AuditorRegistrationKindV1,
				"auditor_did":  "did:web:auditor.example.org",
				"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
				"scheme_tag":   0,
				"findings_url": "https://auditor.example.org/v1/findings",
				"scope":        2,
			},
			expect: "scheme_tag",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.label, func(t *testing.T) {
			raw, err := json.Marshal(c.wire)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			e := entryWithPayload(t, raw)
			err = admission.VerifyNetworkPayloadEntry(e)
			if err == nil {
				t.Fatalf("malformed auditor registration (%s) must be rejected", c.label)
			}
			if !errors.Is(err, admission.ErrNetworkPayloadInvalid) {
				t.Errorf("expected ErrNetworkPayloadInvalid wrap; got %v", err)
			}
			if !strings.Contains(err.Error(), c.expect) {
				t.Errorf("error message %q should mention %q", err.Error(), c.expect)
			}
		})
	}
}

// TestVerifyNetworkPayloadEntry_BadDIDShapeRejected covers one of
// the structural rules that's easy to get wrong in operator
// tooling: a registration with an AuditorDID missing the "did:"
// prefix. The SDK's Validate rejects this; the gate must
// surface the rejection.
func TestVerifyNetworkPayloadEntry_BadDIDShapeRejected(t *testing.T) {
	wire := map[string]any{
		"kind":         network.AuditorRegistrationKindV1,
		"auditor_did":  "example.org:wrong-format",
		"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
		"scheme_tag":   1,
		"findings_url": "https://auditor.example.org/v1/findings",
		"scope":        2,
	}
	raw, _ := json.Marshal(wire)
	e := entryWithPayload(t, raw)
	err := admission.VerifyNetworkPayloadEntry(e)
	if err == nil {
		t.Fatal("non-DID auditor_did must be rejected")
	}
	if !errors.Is(err, admission.ErrNetworkPayloadInvalid) {
		t.Errorf("expected ErrNetworkPayloadInvalid wrap; got %v", err)
	}
}

// TestVerifyNetworkPayloadEntry_ErrorWraps verifies the sentinel
// chain: the gate's error must satisfy errors.Is for
// ErrNetworkPayloadInvalid even when the underlying SDK error
// is several layers deep. Callers (api/submission.go's error
// mapper) depend on this.
func TestVerifyNetworkPayloadEntry_ErrorWraps(t *testing.T) {
	wire := map[string]any{
		"kind":         network.AuditorRegistrationKindV1,
		"auditor_did":  "",
		"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
		"scheme_tag":   1,
		"findings_url": "https://auditor.example.org/v1/findings",
		"scope":        2,
	}
	raw, _ := json.Marshal(wire)
	e := entryWithPayload(t, raw)
	err := admission.VerifyNetworkPayloadEntry(e)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, admission.ErrNetworkPayloadInvalid) {
		t.Errorf("errors.Is must reach ErrNetworkPayloadInvalid; got %v", err)
	}
}

// minInt is a local helper avoiding the stdlib min import to keep
// the test file portable across Go versions.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
