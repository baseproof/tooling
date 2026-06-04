/*
FILE PATH: libs/crosslog/decode_network_test.go

T8 unit tests — DecodeNetworkEntry + IsNetworkKind.

The fallthrough chain in DecodeNetworkEntry is the highest-risk
untested code path in the v1.32.0 adoption: three independent
SDK decoders, each returning its own ErrXxxKindMismatch sentinel
when the wire "kind" doesn't match. A regression that mishandles
ANY of those sentinels — e.g., returning early instead of trying
the next decoder, or surfacing the sentinel as an error instead
of "not this kind" — silently breaks the dispatch.

# COVERAGE MATRIX (locked here so a future change sees all paths)

## DecodeNetworkEntry

  - Empty / nil payload                                  → (nil, nil)
  - Wire kind = endpoint  + Validate passes              → endpoint set
  - Wire kind = label     + Validate passes              → label set
  - Wire kind = auditor   + Validate passes              → auditor set
  - Wire kind = endpoint  + Validate FAILS               → (nil, non-nil-err)
  - Wire kind = label     + Validate FAILS               → (nil, non-nil-err)
  - Wire kind = auditor   + Validate FAILS               → (nil, non-nil-err)
  - Wire kind = unknown ("rotation_v1" etc.)             → (nil, nil)
  - Malformed JSON                                       → (nil, non-nil-err)
    (kind decoder gets bytes,
    tries to unmarshal, surfaces
    the unmarshal failure — NOT
    ErrXxxKindMismatch)

## IsNetworkKind

  - All three v1.32.0 kind constants                     → true
  - Other gossip/admission kinds                         → false
  - Empty string                                         → false
  - Made-up kind                                         → false

# WHY WHITE-BOX (package crosslog, not crosslog_test)

The test is in the same package so it shares the import graph
with the production file. A regression that breaks the SDK
sentinel imports would surface here at compile time. Black-box
positioning (crosslog_test) would mask that.
*/
package crosslog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/network"
)

// ─────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────

// validEndpointDeclaration returns a syntactically-valid
// WitnessEndpointDeclaration. The pubkey is non-zero (the SDK
// rejects zero), endpoints map has one entry under the
// BaseproofWitness service-type, and there's no RetiredAt so the
// payload is the "currently in effect" shape.
func validEndpointDeclaration(t *testing.T) network.WitnessEndpointDeclaration {
	t.Helper()
	var pk [32]byte
	pk[0] = 0x01
	d := network.WitnessEndpointDeclaration{
		PubKeyID: pk,
		Endpoints: map[string]string{
			"BaseproofWitness": "https://witness.example.org/v1/cosign",
		},
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("fixture validEndpointDeclaration is itself invalid: %v", err)
	}
	return d
}

// validIdentityLabel returns a syntactically-valid
// WitnessIdentityLabel. Non-zero PubKeyID, non-empty Label
// (empty Label is the SDK's retirement signal — exercised
// elsewhere; not here).
func validIdentityLabel(t *testing.T) network.WitnessIdentityLabel {
	t.Helper()
	var pk [32]byte
	pk[0] = 0x02
	l := network.WitnessIdentityLabel{
		PubKeyID: pk,
		Label:    "Test Witness",
		DIDHint:  "did:web:witness.example.org",
	}
	if err := l.Validate(); err != nil {
		t.Fatalf("fixture validIdentityLabel is itself invalid: %v", err)
	}
	return l
}

// validAuditorRegistration returns the smallest auditor
// registration the SDK accepts: ECDSA scheme (no PoP), one
// scope bit, well-formed https URL.
func validAuditorRegistration(t *testing.T) network.AuditorRegistration {
	t.Helper()
	pub := make([]byte, 33)
	pub[0] = 0x02
	r := network.AuditorRegistration{
		AuditorDID:  "did:web:auditor.example.org",
		PublicKey:   pub,
		SchemeTag:   1, // ECDSA
		FindingsURL: "https://auditor.example.org/v1/findings",
		Scope:       network.ScopeEquivocation,
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("fixture validAuditorRegistration is itself invalid: %v", err)
	}
	return r
}

// encodeOrFatal wraps a SDK Encode closure so the test stops on
// fixture-construction failures (which are bugs in the test, not
// in the SUT). Closure shape avoids the Go tuple-unpack restriction
// — Go does not flatten a (T, error) return into the trailing
// positional args of an enclosing call.
func encodeOrFatal(t *testing.T, fn func() ([]byte, error)) []byte {
	t.Helper()
	payload, err := fn()
	if err != nil {
		t.Fatalf("fixture encode failed: %v", err)
	}
	return payload
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — happy paths
// ─────────────────────────────────────────────────────────────

func TestDecodeNetworkEntry_Endpoint(t *testing.T) {
	payload := encodeOrFatal(t, func() ([]byte, error) {
		return network.EncodeWitnessEndpointDeclarationPayload(validEndpointDeclaration(t))
	})
	got, err := DecodeNetworkEntry(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DecodedNetworkEntry")
	}
	if got.Kind != network.WitnessEndpointDeclarationKindV1 {
		t.Errorf("Kind: got %q, want %q", got.Kind, network.WitnessEndpointDeclarationKindV1)
	}
	if got.Endpoint == nil {
		t.Error("Endpoint: got nil, want non-nil")
	}
	if got.Label != nil || got.Auditor != nil {
		t.Errorf("Label/Auditor: must be nil for endpoint kind; got Label=%v Auditor=%v",
			got.Label, got.Auditor)
	}
}

func TestDecodeNetworkEntry_Label(t *testing.T) {
	payload := encodeOrFatal(t, func() ([]byte, error) {
		return network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))
	})
	got, err := DecodeNetworkEntry(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DecodedNetworkEntry")
	}
	if got.Kind != network.WitnessIdentityLabelKindV1 {
		t.Errorf("Kind: got %q, want %q", got.Kind, network.WitnessIdentityLabelKindV1)
	}
	if got.Label == nil {
		t.Error("Label: got nil, want non-nil")
	}
	if got.Endpoint != nil || got.Auditor != nil {
		t.Errorf("Endpoint/Auditor: must be nil for label kind; got Endpoint=%v Auditor=%v",
			got.Endpoint, got.Auditor)
	}
}

func TestDecodeNetworkEntry_Auditor(t *testing.T) {
	payload := encodeOrFatal(t, func() ([]byte, error) {
		return network.EncodeAuditorRegistrationPayload(validAuditorRegistration(t))
	})
	got, err := DecodeNetworkEntry(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DecodedNetworkEntry")
	}
	if got.Kind != network.AuditorRegistrationKindV1 {
		t.Errorf("Kind: got %q, want %q", got.Kind, network.AuditorRegistrationKindV1)
	}
	if got.Auditor == nil {
		t.Error("Auditor: got nil, want non-nil")
	}
	if got.Endpoint != nil || got.Label != nil {
		t.Errorf("Endpoint/Label: must be nil for auditor kind; got Endpoint=%v Label=%v",
			got.Endpoint, got.Label)
	}
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — Amendment arm (Ladder 2 D3, v1.33.x Gap 2)
// ─────────────────────────────────────────────────────────────

// validAuditorScopeAmendment returns the smallest amendment payload
// the SDK Validate accepts.
func validAuditorScopeAmendment(t *testing.T) network.AuditorScopeAmendment {
	t.Helper()
	a := network.AuditorScopeAmendment{
		AuditorDID: "did:web:auditor.example.org",
		NewScope:   network.ScopeEquivocation,
		Reason:     "Gap 2 amendment test fixture",
	}
	if err := a.Validate(); err != nil {
		t.Fatalf("fixture validAuditorScopeAmendment is itself invalid: %v", err)
	}
	return a
}

// TestDecodeNetworkEntry_Amendment pins the v1.33.x Gap 2 dispatch arm
// — a wire payload with the amendment kind decodes into the Amendment
// sum-type slot and leaves the other three pointers nil.
func TestDecodeNetworkEntry_Amendment(t *testing.T) {
	payload := encodeOrFatal(t, func() ([]byte, error) {
		return network.EncodeAuditorScopeAmendmentPayload(validAuditorScopeAmendment(t))
	})
	got, err := DecodeNetworkEntry(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil DecodedNetworkEntry")
	}
	if got.Kind != network.AuditorScopeAmendmentKindV1 {
		t.Errorf("Kind: got %q, want %q", got.Kind, network.AuditorScopeAmendmentKindV1)
	}
	if got.Amendment == nil {
		t.Error("Amendment: got nil, want non-nil")
	}
	if got.Endpoint != nil || got.Label != nil || got.Auditor != nil {
		t.Errorf("non-amendment fields must be nil; got Endpoint=%v Label=%v Auditor=%v",
			got.Endpoint, got.Label, got.Auditor)
	}
	if got.Amendment != nil && got.Amendment.AuditorDID != "did:web:auditor.example.org" {
		t.Errorf("Amendment.AuditorDID round-trip: got %q", got.Amendment.AuditorDID)
	}
}

// TestIsNetworkKind_Amendment pins that the helper recognizes the
// v1.33.x amendment kind discriminator.
func TestIsNetworkKind_Amendment(t *testing.T) {
	if !IsNetworkKind(network.AuditorScopeAmendmentKindV1) {
		t.Errorf("IsNetworkKind(%q) = false, want true",
			network.AuditorScopeAmendmentKindV1)
	}
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — ErrMalformedNetworkPayload sentinel (D3)
// ─────────────────────────────────────────────────────────────

// TestDecodeNetworkEntry_MalformedJSONErrSentinel pins that payload
// bytes that don't parse as JSON return the
// ErrMalformedNetworkPayload sentinel — distinguishable from "kind
// matched but SDK Validate rejected" via errors.Is. Callers branch on
// this to log "broken bytes survived envelope decode" vs the more
// common "SDK validate rejected" path.
func TestDecodeNetworkEntry_MalformedJSONErrSentinel(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"trailing-garbage", []byte(`{"kind":"BP-ENTRY-AUDITOR-REGISTRATION-V1"`)}, // missing close-brace
		{"random-bytes", []byte{0xff, 0xfe, 0xfd}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeNetworkEntry(tc.payload)
			if err == nil {
				t.Fatal("expected error; got nil")
			}
			if !errors.Is(err, ErrMalformedNetworkPayload) {
				t.Errorf("errors.Is(err, ErrMalformedNetworkPayload) = false; got err=%v", err)
			}
			if got != nil {
				t.Errorf("expected nil DecodedNetworkEntry; got %+v", got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — empty / nil
// ─────────────────────────────────────────────────────────────

func TestDecodeNetworkEntry_NilOrEmpty(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"nil-payload", nil},
		{"empty-payload", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeNetworkEntry(tc.payload)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if got != nil {
				t.Errorf("expected nil; got %+v", got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — Validate failures (kind matches but
// payload structurally invalid)
// ─────────────────────────────────────────────────────────────

func TestDecodeNetworkEntry_InvalidEndpoint(t *testing.T) {
	// Wire kind matches witness_endpoint_declaration_v1 but
	// endpoints map is empty (SDK requires non-empty).
	wire := map[string]any{
		"kind":       network.WitnessEndpointDeclarationKindV1,
		"pub_key_id": "0100000000000000000000000000000000000000000000000000000000000000",
		"endpoints":  map[string]string{},
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	got, err := DecodeNetworkEntry(raw)
	if err == nil {
		t.Fatal("expected error for empty endpoints map; got nil")
	}
	if got != nil {
		t.Errorf("expected nil DecodedNetworkEntry; got %+v", got)
	}
	// The SDK error should bubble up; we don't pin the exact text
	// (that's the SDK's concern), but we DO require it to NOT be
	// the kind-mismatch sentinel (we MATCHED the kind, so we want
	// the SDK's structural error, not a fallthrough).
	if errors.Is(err, network.ErrWitnessEndpointKindMismatch) {
		t.Errorf("err must NOT be ErrWitnessEndpointKindMismatch (kind matched); got %v", err)
	}
}

func TestDecodeNetworkEntry_InvalidLabel(t *testing.T) {
	// Wire kind matches witness_identity_label_v1 but PubKeyID is
	// zero (SDK rejects).
	wire := map[string]any{
		"kind":       network.WitnessIdentityLabelKindV1,
		"pub_key_id": "0000000000000000000000000000000000000000000000000000000000000000",
		"label":      "Zero PubKey Witness",
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeNetworkEntry(raw)
	if err == nil {
		t.Fatal("expected error for zero pub_key_id")
	}
	if got != nil {
		t.Errorf("expected nil; got %+v", got)
	}
	if errors.Is(err, network.ErrWitnessLabelKindMismatch) {
		t.Errorf("err must NOT be ErrWitnessLabelKindMismatch; got %v", err)
	}
}

func TestDecodeNetworkEntry_InvalidAuditor(t *testing.T) {
	// Wire kind matches auditor_registration_v1 but DID is empty
	// (SDK rejects).
	wire := map[string]any{
		"kind":         network.AuditorRegistrationKindV1,
		"auditor_did":  "",
		"public_key":   "020000000000000000000000000000000000000000000000000000000000000000",
		"scheme_tag":   1,
		"findings_url": "https://auditor.example.org/v1/findings",
		"scope":        2,
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := DecodeNetworkEntry(raw)
	if err == nil {
		t.Fatal("expected error for empty auditor_did")
	}
	if got != nil {
		t.Errorf("expected nil; got %+v", got)
	}
	if errors.Is(err, network.ErrAuditorKindMismatch) {
		t.Errorf("err must NOT be ErrAuditorKindMismatch; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — non-network kinds (the fallthrough that
// returns (nil, nil) without erroring)
// ─────────────────────────────────────────────────────────────

func TestDecodeNetworkEntry_UnknownKind(t *testing.T) {
	// A wire payload whose "kind" matches NONE of the three v1.32.0
	// network kinds. All three SDK decoders return their respective
	// ErrXxxKindMismatch sentinel; the function MUST return (nil,
	// nil) so the caller can pass-through to non-network handlers.
	cases := []struct {
		name string
		wire map[string]any
	}{
		{
			name: "rotation-kind",
			wire: map[string]any{"kind": "entry_signer_rotation_v1"},
		},
		{
			name: "application-kind",
			wire: map[string]any{"kind": "some_application_payload_v3", "data": "x"},
		},
		{
			name: "empty-kind-string",
			wire: map[string]any{"kind": ""},
		},
		{
			name: "no-kind-field-at-all",
			wire: map[string]any{"field": "value"},
		},
		{
			name: "empty-json-object",
			wire: map[string]any{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.wire)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got, err := DecodeNetworkEntry(raw)
			if err != nil {
				t.Errorf("non-network kind must NOT error; got %v", err)
			}
			if got != nil {
				t.Errorf("non-network kind must return nil; got %+v", got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────
// DecodeNetworkEntry — malformed JSON
// ─────────────────────────────────────────────────────────────

func TestDecodeNetworkEntry_MalformedJSON(t *testing.T) {
	// The first decoder (witness_endpoint_declaration) tries
	// json.Unmarshal first; a malformed JSON payload surfaces as a
	// non-kind-mismatch error from that decoder, the cascade
	// short-circuits, and the caller gets a non-nil error.
	cases := [][]byte{
		[]byte(`{"kind": "witness_endpoint_declaration_v1"`), // missing closing brace
		[]byte(`{"kind":}`),                                 // syntax error
		[]byte(`not-json-at-all`),                           // not even close
		[]byte(`{kind: "witness_endpoint_declaration_v1"}`), // unquoted key
	}
	for i, payload := range cases {
		got, err := DecodeNetworkEntry(payload)
		if err == nil {
			t.Errorf("case %d: malformed JSON must error; got nil err", i)
		}
		if got != nil {
			t.Errorf("case %d: malformed JSON must return nil entry; got %+v", i, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// IsNetworkKind
// ─────────────────────────────────────────────────────────────

func TestIsNetworkKind_RecognizedKinds(t *testing.T) {
	known := []string{
		network.WitnessEndpointDeclarationKindV1,
		network.WitnessIdentityLabelKindV1,
		network.AuditorRegistrationKindV1,
	}
	for _, k := range known {
		if !IsNetworkKind(k) {
			t.Errorf("IsNetworkKind(%q) = false; want true", k)
		}
	}
}

func TestIsNetworkKind_UnrecognizedKinds(t *testing.T) {
	notNetwork := []string{
		"",
		"entry_signer_rotation_v1",
		"some_application_payload_v3",
		"BP-GOSSIP-EQUIV-V1",
		"witness_endpoint_declaration_v0", // version suffix wrong
		"WITNESS_ENDPOINT_DECLARATION_V1", // case-sensitive
		strings.Repeat("x", 256),          // pathological
	}
	for _, k := range notNetwork {
		if IsNetworkKind(k) {
			t.Errorf("IsNetworkKind(%q) = true; want false", k)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// Compile-time guards — sentinel imports
// ─────────────────────────────────────────────────────────────

// These references force the imports to stay live. A regression
// that renames or removes the SDK sentinels would break this
// test file at compile time — the loudest possible signal.
var (
	_ = network.ErrWitnessEndpointKindMismatch
	_ = network.ErrWitnessLabelKindMismatch
	_ = network.ErrAuditorKindMismatch
)
