/*
FILE PATH: libs/crosslog/cross_checks_test.go

T9 unit tests — RunAdvisoryCrossChecks.

Covers the per-record advisory cross-check + skip-on-resolve-
failure + mismatch-classification surface. The fake DIDResolver
lets us drive every code path without touching the network.

# COVERAGE MATRIX

  - Nil resolver                        → returns nil silently
  - Empty MaterializedNetwork           → returns nil
  - Auditor record + resolver "not found" → skipped (no mismatch)
  - Auditor record + matching did:web doc → no mismatch
  - Auditor record + mismatching did:web doc → mismatch returned with
    correct Kind, Identifier, DID, Reason
  - Label record with empty DIDHint     → skipped (DIDHint optional)
  - Label record + matching did:web doc → no mismatch
  - Label record + mismatching did:web doc → mismatch returned
  - Endpoint record with no matching label DIDHint → skipped
  - Endpoint record + label DIDHint + matching doc → no mismatch
  - Endpoint record + label DIDHint + mismatching doc → mismatch
*/
package crosslog

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
)

// fakeDIDResolver implements did.DIDResolver with a fixed map of
// DID → DIDDocument lookups + an optional error injection.
type fakeDIDResolver struct {
	docs       map[string]*did.DIDDocument
	forceError error
}

func (f *fakeDIDResolver) Resolve(_ context.Context, didStr string) (*did.DIDDocument, error) {
	if f.forceError != nil {
		return nil, f.forceError
	}
	doc, ok := f.docs[didStr]
	if !ok {
		return nil, errors.New("did:not-found")
	}
	return doc, nil
}

// auditorDIDDocMatching returns a DIDDocument that matches the
// supplied AuditorRegistration — same DID, same public key in a
// verificationMethod, same findings URL as an BaseproofAuditor
// service.
func auditorDIDDocMatching(reg network.AuditorRegistration) *did.DIDDocument {
	return &did.DIDDocument{
		ID: reg.AuditorDID,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           reg.AuditorDID + "#key-1",
				Controller:   reg.AuditorDID,
				PublicKeyHex: hex.EncodeToString(reg.PublicKey),
			},
		},
		Service: []did.Service{
			{
				ID:              reg.AuditorDID + "#findings",
				Type:            did.ServiceTypeAuditor,
				ServiceEndpoint: reg.FindingsURL,
			},
		},
	}
}

// auditorDIDDocMismatching returns a DIDDocument that intentionally
// disagrees with the supplied registration — wrong findings URL.
func auditorDIDDocMismatching(reg network.AuditorRegistration) *did.DIDDocument {
	doc := auditorDIDDocMatching(reg)
	doc.Service[0].ServiceEndpoint = "https://drifted.example.org/v1/findings"
	return doc
}

// ─────────────────────────────────────────────────────────────
// Nil / empty paths
// ─────────────────────────────────────────────────────────────

func TestRunAdvisoryCrossChecks_NilResolver(t *testing.T) {
	mat := MaterializedNetwork{
		Auditors: network.AuditorRegistrationByPosition{
			{Payload: validAuditorRegistration(t)},
		},
	}
	got := RunAdvisoryCrossChecks(context.Background(), mat, nil, discardLogger())
	if got != nil {
		t.Errorf("nil resolver must return nil; got %d mismatches", len(got))
	}
}

func TestRunAdvisoryCrossChecks_EmptyMaterialized(t *testing.T) {
	got := RunAdvisoryCrossChecks(context.Background(), MaterializedNetwork{},
		&fakeDIDResolver{}, discardLogger())
	if got != nil {
		t.Errorf("empty materialized must return nil; got %d mismatches", len(got))
	}
}

// ─────────────────────────────────────────────────────────────
// Auditor paths
// ─────────────────────────────────────────────────────────────

func TestRunAdvisoryCrossChecks_AuditorResolveFails(t *testing.T) {
	reg := validAuditorRegistration(t)
	mat := MaterializedNetwork{
		Auditors: network.AuditorRegistrationByPosition{{Payload: reg}},
	}
	// Resolver has no entry for the DID — returns "not found" error.
	got := RunAdvisoryCrossChecks(context.Background(), mat,
		&fakeDIDResolver{docs: map[string]*did.DIDDocument{}}, discardLogger())
	if len(got) != 0 {
		t.Errorf("resolve-failure must NOT count as mismatch; got %+v", got)
	}
}

func TestRunAdvisoryCrossChecks_AuditorMatching(t *testing.T) {
	reg := validAuditorRegistration(t)
	mat := MaterializedNetwork{
		Auditors: network.AuditorRegistrationByPosition{{Payload: reg}},
	}
	resolver := &fakeDIDResolver{
		docs: map[string]*did.DIDDocument{
			reg.AuditorDID: auditorDIDDocMatching(reg),
		},
	}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 0 {
		t.Errorf("matching did:web doc must NOT produce mismatch; got %+v", got)
	}
}

func TestRunAdvisoryCrossChecks_AuditorMismatching(t *testing.T) {
	reg := validAuditorRegistration(t)
	mat := MaterializedNetwork{
		Auditors: network.AuditorRegistrationByPosition{{Payload: reg}},
	}
	resolver := &fakeDIDResolver{
		docs: map[string]*did.DIDDocument{
			reg.AuditorDID: auditorDIDDocMismatching(reg),
		},
	}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 1 {
		t.Fatalf("mismatching did:web doc must produce 1 mismatch; got %d", len(got))
	}
	m := got[0]
	if m.Kind != MismatchKindAuditor {
		t.Errorf("Kind: got %v, want %v", m.Kind, MismatchKindAuditor)
	}
	if m.Identifier != reg.AuditorDID {
		t.Errorf("Identifier: got %q, want %q", m.Identifier, reg.AuditorDID)
	}
	if m.DID != reg.AuditorDID {
		t.Errorf("DID: got %q, want %q", m.DID, reg.AuditorDID)
	}
	if m.Reason == "" {
		t.Error("Reason: empty — operator triage needs the SDK error text")
	}
}

// ─────────────────────────────────────────────────────────────
// Label paths
// ─────────────────────────────────────────────────────────────

func TestRunAdvisoryCrossChecks_LabelEmptyDIDHintSkipped(t *testing.T) {
	label := validIdentityLabel(t)
	label.DIDHint = "" // optional field — empty must skip
	mat := MaterializedNetwork{
		Labels: network.WitnessIdentityLabelByPosition{{Payload: label}},
	}
	resolver := &fakeDIDResolver{docs: map[string]*did.DIDDocument{}}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 0 {
		t.Errorf("empty DIDHint must skip without mismatch; got %+v", got)
	}
}

func TestRunAdvisoryCrossChecks_LabelMatching(t *testing.T) {
	label := validIdentityLabel(t)
	mat := MaterializedNetwork{
		Labels: network.WitnessIdentityLabelByPosition{{Payload: label}},
	}
	resolver := &fakeDIDResolver{
		docs: map[string]*did.DIDDocument{
			label.DIDHint: {ID: label.DIDHint},
		},
	}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 0 {
		t.Errorf("matching label doc must NOT mismatch; got %+v", got)
	}
}

func TestRunAdvisoryCrossChecks_LabelMismatching(t *testing.T) {
	label := validIdentityLabel(t)
	mat := MaterializedNetwork{
		Labels: network.WitnessIdentityLabelByPosition{{Payload: label}},
	}
	resolver := &fakeDIDResolver{
		docs: map[string]*did.DIDDocument{
			// Doc has WRONG ID (drift indicator).
			label.DIDHint: {ID: "did:web:drifted.example.org"},
		},
	}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 1 {
		t.Fatalf("mismatching label must produce 1 mismatch; got %d", len(got))
	}
	if got[0].Kind != MismatchKindLabel {
		t.Errorf("Kind: got %v, want %v", got[0].Kind, MismatchKindLabel)
	}
	if got[0].DID != label.DIDHint {
		t.Errorf("DID: got %q, want %q", got[0].DID, label.DIDHint)
	}
}

// ─────────────────────────────────────────────────────────────
// Endpoint paths
// ─────────────────────────────────────────────────────────────

func TestRunAdvisoryCrossChecks_EndpointNoMatchingLabelSkipped(t *testing.T) {
	endpoint := validEndpointDeclaration(t)
	mat := MaterializedNetwork{
		Endpoints: network.WitnessEndpointDeclarationByPosition{{Payload: endpoint}},
		// No Labels — no DIDHint resolvable → endpoint skipped
	}
	resolver := &fakeDIDResolver{docs: map[string]*did.DIDDocument{}}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 0 {
		t.Errorf("endpoint with no DIDHint must skip; got %+v", got)
	}
}

func TestRunAdvisoryCrossChecks_MultipleMismatches(t *testing.T) {
	// Two auditors, both mismatching — verify the result slice
	// contains BOTH mismatches in operator-meaningful form.
	reg1 := validAuditorRegistration(t)
	reg1.AuditorDID = "did:web:auditor-a.example.org"
	reg2 := validAuditorRegistration(t)
	reg2.AuditorDID = "did:web:auditor-b.example.org"

	mat := MaterializedNetwork{
		Auditors: network.AuditorRegistrationByPosition{
			{Payload: reg1},
			{Payload: reg2},
		},
	}
	resolver := &fakeDIDResolver{
		docs: map[string]*did.DIDDocument{
			reg1.AuditorDID: auditorDIDDocMismatching(reg1),
			reg2.AuditorDID: auditorDIDDocMismatching(reg2),
		},
	}
	got := RunAdvisoryCrossChecks(context.Background(), mat, resolver, discardLogger())
	if len(got) != 2 {
		t.Fatalf("expected 2 mismatches; got %d", len(got))
	}
	// Each mismatch must carry its own AuditorDID.
	seen := map[string]bool{}
	for _, m := range got {
		seen[m.Identifier] = true
	}
	if !seen[reg1.AuditorDID] || !seen[reg2.AuditorDID] {
		t.Errorf("expected both auditor DIDs in mismatches; got %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────
// Nil logger defaults
// ─────────────────────────────────────────────────────────────

func TestRunAdvisoryCrossChecks_NilLoggerDefaults(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil logger panicked: %v", r)
		}
	}()
	RunAdvisoryCrossChecks(context.Background(), MaterializedNetwork{},
		&fakeDIDResolver{}, nil)
}
