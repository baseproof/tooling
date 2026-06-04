/*
FILE PATH: libs/crosslog/decode_network.go

v1.32.0 SDK adoption — kind-discriminated decoder for the three
new on-log network payload kinds:

  - WitnessEndpointDeclarationV1
  - WitnessIdentityLabelV1
  - AuditorRegistrationV1

# WHY THIS HELPER EXISTS

The SDK exposes three independent Decode*Payload functions,
each keyed off the wire "kind" field with its own Kind-mismatch
sentinel. Without this helper, every consumer needs the same
three-step ladder:

	if d, err := network.DecodeWitnessEndpointDeclarationPayload(payload); err == nil { ... }
	else if !errors.Is(err, network.ErrWitnessEndpointKindMismatch) { return err }
	if l, err := network.DecodeWitnessIdentityLabelPayload(payload); err == nil { ... }
	else if !errors.Is(err, network.ErrWitnessLabelKindMismatch) { return err }
	if r, err := network.DecodeAuditorRegistrationPayload(payload); err == nil { ... }
	else if !errors.Is(err, network.ErrAuditorKindMismatch) { return err }

This helper compresses that to one call returning a
DecodedNetworkEntry sum-type. Used by ledgerscan-shipped
Indexer implementations + the materialize.go in this package.

# RELATIONSHIP TO materialize.go

materialize.go inlines this dispatch because it needs to emit
per-kind log lines + accumulate into three separate slices.
This file is the standalone helper for consumers that JUST
need to know "what kind is this entry" without going through
the materialize aggregation.

# DESIGN NOTE — POINTER RETURNS

Each non-nil field carries a pointer to the decoded value so
callers can type-switch on which field is set:

	d, err := DecodeNetworkEntry(payload)
	switch {
	case err != nil: ...
	case d == nil: ... // not a network kind
	case d.Endpoint != nil: ...
	case d.Label != nil: ...
	case d.Auditor != nil: ...
	}

Returning pointers (vs an interface) keeps the SDK's value-typed
record shapes intact — callers can mutate the embedded values
without affecting the underlying network record.
*/
package crosslog

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/network"
)

// DecodedNetworkEntry is the sum-type return of DecodeNetworkEntry.
// Exactly one of Endpoint/Label/Auditor/Amendment is non-nil on success;
// Kind carries the SDK's protocol-permanent Kind string so callers
// can dispatch on Kind without inspecting which field is non-nil.
type DecodedNetworkEntry struct {
	Kind      string                              // network.WitnessEndpointDeclarationKindV1 | ...
	Endpoint  *network.WitnessEndpointDeclaration // non-nil iff Kind == WitnessEndpointDeclarationKindV1
	Label     *network.WitnessIdentityLabel       // non-nil iff Kind == WitnessIdentityLabelKindV1
	Auditor   *network.AuditorRegistration        // non-nil iff Kind == AuditorRegistrationKindV1
	Amendment *network.AuditorScopeAmendment      // non-nil iff Kind == AuditorScopeAmendmentKindV1 (v1.33.x Gap 2)
}

// ErrMalformedNetworkPayload wraps decode-time errors that aren't
// kind-mismatch sentinels — the wire bytes are NOT well-formed JSON,
// OR the JSON shape is present but unrecognised. Returned with a wrap
// of json.Unmarshal's original error so the operator can debug.
//
// Distinguished from per-SDK Decode validation errors (which surface
// directly so the operator sees the SDK's structural message) — this
// sentinel only fires when the kind-probe itself fails, before any
// SDK decoder runs.
var ErrMalformedNetworkPayload = errors.New("crosslog/decode_network: payload not JSON-parseable")

// DecodeNetworkEntry attempts to decode payload as one of the v1.33.x
// network entry kinds (Endpoint / Label / Auditor / Amendment).
//
// Returns:
//
//   - (*DecodedNetworkEntry, nil) — wire kind matched + the SDK's Validate
//     passed.
//   - (nil, err) — wire kind matched but the SDK's Validate rejected the
//     payload (caller surfaces err verbatim).
//   - (nil, ErrMalformedNetworkPayload-wrap) — payload was not parseable
//     as JSON at all (the kind-probe failed). Distinguishable via
//     errors.Is(err, ErrMalformedNetworkPayload).
//   - (nil, nil) — payload was JSON-parseable BUT the embedded "kind"
//     field did NOT match any of the v1.33.x network kinds. The
//     payload is some other entry kind (admission policy amendment,
//     gossip finding, application payload, etc.) — caller passes
//     through to a non-network handler.
//
// # KIND-PROBE-FIRST DISPATCH (#21 C1)
//
// The previous try-each-decoder-then-check-sentinel cascade was brittle
// against future SDK changes: a Decode function returning a JSON-level
// error (instead of the kind-mismatch sentinel) would exit at the first
// decoder and mis-label the entry. At 1K+ TPS × 15 networks =
// 120-150M entries fleet-wide, even a 0.001% rate of mis-classification
// is ~1500 silent data-loss events per backfill.
//
// New shape: probe the "kind" field first, dispatch to EXACTLY ONE
// SDK decoder. Any error from that decoder is the operator's structural
// failure for that specific kind — surfaced verbatim. Same pattern
// Ledger uses at admission/network_payload_validator.go.
func DecodeNetworkEntry(payload []byte) (*DecodedNetworkEntry, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedNetworkPayload, err)
	}
	switch probe.Kind {
	case network.WitnessEndpointDeclarationKindV1:
		d, err := network.DecodeWitnessEndpointDeclarationPayload(payload)
		if err != nil {
			return nil, err
		}
		return &DecodedNetworkEntry{
			Kind:     network.WitnessEndpointDeclarationKindV1,
			Endpoint: &d,
		}, nil
	case network.WitnessIdentityLabelKindV1:
		l, err := network.DecodeWitnessIdentityLabelPayload(payload)
		if err != nil {
			return nil, err
		}
		return &DecodedNetworkEntry{
			Kind:  network.WitnessIdentityLabelKindV1,
			Label: &l,
		}, nil
	case network.AuditorRegistrationKindV1:
		r, err := network.DecodeAuditorRegistrationPayload(payload)
		if err != nil {
			return nil, err
		}
		return &DecodedNetworkEntry{
			Kind:    network.AuditorRegistrationKindV1,
			Auditor: &r,
		}, nil
	case network.AuditorScopeAmendmentKindV1:
		a, err := network.DecodeAuditorScopeAmendmentPayload(payload)
		if err != nil {
			return nil, err
		}
		return &DecodedNetworkEntry{
			Kind:      network.AuditorScopeAmendmentKindV1,
			Amendment: &a,
		}, nil
	default:
		// "kind" field present but not one of the network kinds — payload
		// belongs to a different domain (admission policy amendment,
		// gossip finding, application payload, etc.). Or "kind" is empty
		// (entry has no kind field at all — also not a network entry).
		return nil, nil
	}
}

// IsNetworkKind reports whether the supplied kind string is one of
// the v1.33.x network kind discriminators (Endpoint / Label / Auditor /
// Amendment). Convenience for callers that want a kind-string check
// without invoking the decoder (e.g., a fast pre-filter before the
// heavier JSON parse).
func IsNetworkKind(kind string) bool {
	switch kind {
	case network.WitnessEndpointDeclarationKindV1,
		network.WitnessIdentityLabelKindV1,
		network.AuditorRegistrationKindV1,
		network.AuditorScopeAmendmentKindV1:
		return true
	default:
		return false
	}
}
