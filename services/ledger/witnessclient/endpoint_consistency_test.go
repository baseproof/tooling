package witnessclient

import (
	"context"
	"io"
	"log/slog"
	"testing"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
)

func discardMonitorLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestWitnessEndpointMonitor_Tick exercises the three advisory outcomes:
// a matching did:web doc → no mismatch; a drifted doc → one mismatch (WARN);
// no doc (the did:key / unreachable case) → skipped, no false alarm.
func TestWitnessEndpointMonitor_Tick(t *testing.T) {
	decl := network.WitnessEndpointDeclaration{
		PubKeyID:  [32]byte{9, 9, 9},
		Endpoints: map[string]string{"BaseproofWitness": "https://w1.example.com"},
	}
	records := func() network.WitnessEndpointDeclarationByPosition {
		return network.WitnessEndpointDeclarationByPosition{{Payload: decl}}
	}
	ctx := context.Background()

	// Matching did:web document → no mismatch.
	match := &sdkdid.DIDDocument{Service: []sdkdid.Service{
		{Type: "BaseproofWitness", ServiceEndpoint: "https://w1.example.com"},
	}}
	m := &WitnessEndpointMonitor{
		Records: records,
		Fetch: func(context.Context, network.WitnessEndpointDeclaration) (*sdkdid.DIDDocument, error) {
			return match, nil
		},
		Logger: discardMonitorLogger(),
	}
	if n := m.Tick(ctx); n != 0 {
		t.Fatalf("matching did:web doc: want 0 mismatches, got %d", n)
	}

	// Drifted did:web document (attacker / DNS churn) → one mismatch.
	drift := &sdkdid.DIDDocument{Service: []sdkdid.Service{
		{Type: "BaseproofWitness", ServiceEndpoint: "https://attacker.example.com"},
	}}
	m.Fetch = func(context.Context, network.WitnessEndpointDeclaration) (*sdkdid.DIDDocument, error) {
		return drift, nil
	}
	if n := m.Tick(ctx); n != 1 {
		t.Fatalf("drifted did:web doc: want 1 mismatch, got %d", n)
	}

	// No did:web document (did:key witness / unreachable) → skipped.
	m.Fetch = func(context.Context, network.WitnessEndpointDeclaration) (*sdkdid.DIDDocument, error) {
		return nil, nil
	}
	if n := m.Tick(ctx); n != 0 {
		t.Fatalf("no did:web doc: want 0 mismatches (advisory no-op), got %d", n)
	}
}
