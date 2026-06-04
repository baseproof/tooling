/*
FILE PATH: libs/monitoring/url_drift_audit_test.go

T11 unit tests — CheckURLDrift.

Covers the periodic URL drift auditor's alert-emission contract:
how it maps the cross-check's mismatches to monitoring.Alerts, and
the critical distinction between "audit ran, no drift detected"
and "audit itself failed".
*/
package monitoring

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/monitoring"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/crosslog"
)

// fakeDIDResolverT11 implements did.DIDResolver with a configurable
// docs map. Same shape as T9's fakeDIDResolver — duplicated here to
// keep the test file self-contained (no cross-package fixtures).
type fakeDIDResolverT11 struct {
	docs map[string]*did.DIDDocument
}

func (f *fakeDIDResolverT11) Resolve(_ context.Context, didStr string) (*did.DIDDocument, error) {
	doc, ok := f.docs[didStr]
	if !ok {
		return nil, errors.New("not-found")
	}
	return doc, nil
}

// auditorReg returns a valid registration with the given DID.
func auditorReg(did string) network.AuditorRegistration {
	pub := make([]byte, 33)
	pub[0] = 0x02
	return network.AuditorRegistration{
		AuditorDID:  did,
		PublicKey:   pub,
		SchemeTag:   1,
		FindingsURL: "https://" + extractHost(did) + "/v1/findings",
		Scope:       network.ScopeEquivocation,
	}
}

// extractHost takes a did:web:xxx string and returns xxx (for
// building a matching FindingsURL host). Fragile parser — only
// used in tests where the input is controlled.
func extractHost(didStr string) string {
	const prefix = "did:web:"
	if !strings.HasPrefix(didStr, prefix) {
		return "example.org"
	}
	return didStr[len(prefix):]
}

// auditorDoc returns a DIDDocument that matches reg (no drift).
func auditorDoc(reg network.AuditorRegistration) *did.DIDDocument {
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
				Type:            did.ServiceTypeAuditor,
				ServiceEndpoint: reg.FindingsURL,
			},
		},
	}
}

// auditorDocDrifted returns a doc with a WRONG findings URL.
func auditorDocDrifted(reg network.AuditorRegistration) *did.DIDDocument {
	doc := auditorDoc(reg)
	doc.Service[0].ServiceEndpoint = "https://drifted.example.org/v1/findings"
	return doc
}

func discardLoggerT11() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ─────────────────────────────────────────────────────────────
// Required-field validation
// ─────────────────────────────────────────────────────────────

func TestCheckURLDrift_NilMaterializedSourceErrors(t *testing.T) {
	cfg := URLDriftAuditConfig{
		Resolver: &fakeDIDResolverT11{},
	}
	_, err := CheckURLDrift(context.Background(), cfg, discardLoggerT11(), time.Now())
	if err == nil {
		t.Fatal("nil MaterializedSource must error")
	}
	if !strings.Contains(err.Error(), "MaterializedSource") {
		t.Errorf("error must name the offending field; got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────
// Disabled paths
// ─────────────────────────────────────────────────────────────

func TestCheckURLDrift_NilResolverReturnsEmpty(t *testing.T) {
	cfg := URLDriftAuditConfig{
		LocalLogDID: "did:test:local",
		MaterializedSource: func(_ context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{}, nil
		},
		Resolver: nil, // audit disabled
	}
	alerts, err := CheckURLDrift(context.Background(), cfg, discardLoggerT11(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("nil resolver must return empty alerts; got %d", len(alerts))
	}
}

func TestCheckURLDrift_NoMismatchesReturnsEmpty(t *testing.T) {
	reg := auditorReg("did:web:auditor-ok.example.org")
	cfg := URLDriftAuditConfig{
		LocalLogDID: "did:test:local",
		MaterializedSource: func(_ context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{
				Auditors: network.AuditorRegistrationByPosition{
					{Payload: reg},
				},
			}, nil
		},
		Resolver: &fakeDIDResolverT11{
			docs: map[string]*did.DIDDocument{
				reg.AuditorDID: auditorDoc(reg),
			},
		},
	}
	alerts, err := CheckURLDrift(context.Background(), cfg, discardLoggerT11(), time.Now())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("no mismatches must return empty alerts; got %d", len(alerts))
	}
}

// ─────────────────────────────────────────────────────────────
// Mismatch → Warning alert
// ─────────────────────────────────────────────────────────────

func TestCheckURLDrift_OneMismatchEmitsOneWarning(t *testing.T) {
	reg := auditorReg("did:web:auditor-drifted.example.org")
	now := time.Now()
	cfg := URLDriftAuditConfig{
		LocalLogDID: "did:test:local",
		MaterializedSource: func(_ context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{
				Auditors: network.AuditorRegistrationByPosition{{Payload: reg}},
			}, nil
		},
		Resolver: &fakeDIDResolverT11{
			docs: map[string]*did.DIDDocument{
				reg.AuditorDID: auditorDocDrifted(reg),
			},
		},
	}
	alerts, err := CheckURLDrift(context.Background(), cfg, discardLoggerT11(), now)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("one mismatch must yield one alert; got %d", len(alerts))
	}
	a := alerts[0]
	if a.Monitor != MonitorURLDrift {
		t.Errorf("Monitor: got %v, want %v", a.Monitor, MonitorURLDrift)
	}
	if a.Severity != monitoring.Warning {
		t.Errorf("Severity: got %v, want Warning (drift is investigate-not-page)",
			a.Severity)
	}
	if a.Destination != monitoring.Ops {
		t.Errorf("Destination: got %v, want Ops", a.Destination)
	}
	if !a.EmittedAt.Equal(now) {
		t.Errorf("EmittedAt: got %v, want %v", a.EmittedAt, now)
	}
	// Details must carry the operator-triage shape.
	if a.Details["local_log"] != "did:test:local" {
		t.Errorf("Details.local_log missing/wrong: %v", a.Details["local_log"])
	}
	if a.Details["kind"] == "" {
		t.Error("Details.kind empty")
	}
	if a.Details["did"] != reg.AuditorDID {
		t.Errorf("Details.did: got %v, want %q", a.Details["did"], reg.AuditorDID)
	}
}

// ─────────────────────────────────────────────────────────────
// Audit-itself-failed → Critical alert
// ─────────────────────────────────────────────────────────────

func TestCheckURLDrift_MaterializedSourceErrorEmitsCritical(t *testing.T) {
	now := time.Now()
	boom := errors.New("walker down")
	cfg := URLDriftAuditConfig{
		LocalLogDID: "did:test:local",
		MaterializedSource: func(_ context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{}, boom
		},
		Resolver: &fakeDIDResolverT11{},
	}
	alerts, err := CheckURLDrift(context.Background(), cfg, discardLoggerT11(), now)
	if err != nil {
		// The audit-failure path returns the alert via the slice,
		// NOT via err. err MUST be nil so the scheduler advances.
		t.Errorf("audit failure must NOT return go error; got %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("audit failure must yield 1 Critical alert; got %d", len(alerts))
	}
	a := alerts[0]
	if a.Severity != monitoring.Critical {
		t.Errorf("Severity: got %v, want Critical (audit itself broken)", a.Severity)
	}
	if !strings.Contains(a.Message, "walker down") {
		t.Errorf("Message must surface underlying error; got %q", a.Message)
	}
	if a.Details["error"] != boom.Error() {
		t.Errorf("Details.error: got %v, want %q", a.Details["error"], boom.Error())
	}
}

// ─────────────────────────────────────────────────────────────
// Multiple mismatches → multiple Warning alerts
// ─────────────────────────────────────────────────────────────

func TestCheckURLDrift_MultipleMismatchesEmitsMultipleAlerts(t *testing.T) {
	reg1 := auditorReg("did:web:auditor-a.example.org")
	reg2 := auditorReg("did:web:auditor-b.example.org")
	cfg := URLDriftAuditConfig{
		LocalLogDID: "did:test:local",
		MaterializedSource: func(_ context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{
				Auditors: network.AuditorRegistrationByPosition{
					{Payload: reg1},
					{Payload: reg2},
				},
			}, nil
		},
		Resolver: &fakeDIDResolverT11{
			docs: map[string]*did.DIDDocument{
				reg1.AuditorDID: auditorDocDrifted(reg1),
				reg2.AuditorDID: auditorDocDrifted(reg2),
			},
		},
	}
	alerts, err := CheckURLDrift(context.Background(), cfg, discardLoggerT11(), time.Now())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts; got %d", len(alerts))
	}
	// Each alert MUST be Warning (per-mismatch is "investigate", not
	// "page" — page is reserved for audit-itself-failed).
	for i, a := range alerts {
		if a.Severity != monitoring.Warning {
			t.Errorf("alert[%d].Severity: got %v, want Warning", i, a.Severity)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// Nil logger defaults
// ─────────────────────────────────────────────────────────────

func TestCheckURLDrift_NilLoggerDefaults(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil logger panicked: %v", r)
		}
	}()
	cfg := URLDriftAuditConfig{
		MaterializedSource: func(_ context.Context) (crosslog.MaterializedNetwork, error) {
			return crosslog.MaterializedNetwork{}, nil
		},
		Resolver: &fakeDIDResolverT11{},
	}
	_, _ = CheckURLDrift(context.Background(), cfg, nil, time.Now())
}
