/*
FILE PATH: witnessclient/rotation_emitter_test.go

Unit tests for WitnessRotationEmitter + RotationHandler.WithEmitter.

# WHAT'S COVERED

	(1) NopWitnessRotationEmitter — Emit is a no-op; safe with nil
	    finding too.

	(2) LoggingWitnessRotationEmitter — Emit increments the Emitted
	    counter and writes a structured log line carrying the
	    load-bearing fields of the finding.

	(3) Compile-time pins — both implementations satisfy the
	    WitnessRotationEmitter interface (drift surfaces as a build
	    error, not a runtime panic).

	(4) RotationHandler.WithEmitter — chains, stores the supplied
	    emitter, accepts nil.

# WHAT'S ABSENT (and why)

End-to-end "rotation lands in DB, emitter fires" tests live in the
witnessclient/rotation_cross_network_test.go and the integration
package (which gates on a real Postgres). The unit boundary here
is the emitter contract + the handler's wire-up. The DB-write→emit
ordering is enforced by the linear control flow in
rotation_handler.go::ProcessRotation — visual inspection +
integration tests cover the cross-boundary property.
*/
package witnessclient

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	envelope "github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/gossip/findings"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// fakeRotationAppender commits a rotation payload as a (fake) on-log entry
// at a fixed sequence, returning a structurally-valid one-leaf inclusion
// proof. The proof is NOT root-checked by ProcessRotation/Validate, so a
// minimal structurally-valid proof suffices.
//
// (External-package copy lives in rotation_cross_network_test.go; the two
// are identical but live in different test packages — the emitter test is
// internal `witnessclient`, the DB/cross-network tests are
// `witnessclient_test` — so neither can see the other's definition.)
type fakeRotationAppender struct {
	logDID string
	seq    uint64
	err    error // optional injected failure
}

func (f fakeRotationAppender) AppendRotationEntry(_ context.Context, payload []byte) ([]byte, types.LogPosition, *types.MerkleProof, error) {
	if f.err != nil {
		return nil, types.LogPosition{}, nil, f.err
	}
	entry, err := envelope.NewEntry(
		envelope.ControlHeader{SignerDID: "did:web:ledger.example.gov", Destination: "did:web:ledger.example.gov"},
		payload,
		[]envelope.Signature{{SignerDID: "did:web:ledger.example.gov", AlgoID: 1, Bytes: make([]byte, 64)}},
	)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}
	canonical, err := envelope.Serialize(entry)
	if err != nil {
		return nil, types.LogPosition{}, nil, err
	}
	// On-log entry leaf = H(0x00 || EntryIdentity) (baseproof v1.40.0
	// OnLogEntryLeafHash) — the ledger feeds Tessera the 32-byte identity.
	leaf := envelope.OnLogEntryLeafHash(canonical)
	pos := types.LogPosition{LogDID: f.logDID, Sequence: f.seq}
	proof := &types.MerkleProof{LeafPosition: f.seq, LeafHash: leaf, Siblings: nil, TreeSize: f.seq + 1}
	return canonical, pos, proof, nil
}

var _ RotationLogAppender = fakeRotationAppender{}

// rotationFinding drives a rotation through fakeRotationAppender to obtain
// the self-contained (entryCanonical, effectivePos, proof) triple the v1.39
// findings.NewWitnessRotationFinding requires, then constructs the finding.
// Mirrors ProcessRotation's Step 1 (encode) → Step 2b (append) → Step 5
// (build finding) pipeline so the fixture exercises the same SDK path.
func rotationFinding(t *testing.T, rotation types.WitnessRotation, endpoint string) *findings.WitnessRotationFinding {
	t.Helper()
	payload, err := witness.EncodeWitnessRotationPayload(rotation)
	if err != nil {
		t.Fatalf("EncodeWitnessRotationPayload: %v", err)
	}
	app := fakeRotationAppender{logDID: "did:web:ledger.example.gov", seq: 7}
	canonical, pos, proof, err := app.AppendRotationEntry(context.Background(), payload)
	if err != nil {
		t.Fatalf("fake AppendRotationEntry: %v", err)
	}
	f, err := findings.NewWitnessRotationFinding(canonical, pos, proof, endpoint)
	if err != nil {
		t.Fatalf("fixture finding rejected by SDK Validate: %v", err)
	}
	return f
}

// Compile-time pins — same surface as the production rotation_
// emitter.go file already declares; duplicated here so a future
// refactor that splits the file doesn't drop the assertion.
var (
	_ WitnessRotationEmitter = NopWitnessRotationEmitter{}
	_ WitnessRotationEmitter = (*LoggingWitnessRotationEmitter)(nil)
)

// fixtureFinding returns a structurally-valid (but NOT
// cryptographically-verifiable) WitnessRotationFinding suitable
// for emitter-surface tests. As of v1.39 the finding is
// self-contained: the rotation is encoded as an on-log entry
// payload, committed through fakeRotationAppender to obtain the
// (entryCanonical, effectivePos, proof) triple, and only then
// handed to findings.NewWitnessRotationFinding — so the SDK's
// Validate fires (decode the entry, leaf-hash/position binding).
// If Validate rejects, the test fixture is broken, not the
// emitter contract.
func fixtureFinding(t *testing.T) *findings.WitnessRotationFinding {
	t.Helper()
	rotation := types.WitnessRotation{
		CurrentSetHash: [32]byte{0xab, 0xcd, 0xef},
		NewSet: []types.WitnessPublicKey{
			{
				ID:        [32]byte{0x01},
				PublicKey: []byte{0x04, 0x01, 0x02, 0x03}, // structurally-valid; not crypto-verified
			},
		},
		SchemeTagOld:      0x01,
		CurrentSignatures: []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: []byte{0xAA}}},
		SchemeTagNew:      0x01,
		NewSignatures:     []types.WitnessSignature{{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: []byte{0xBB}}},
	}
	return rotationFinding(t, rotation, "https://ledger.example/")
}

// ─────────────────────────────────────────────────────────────────────
// (1) NopWitnessRotationEmitter
// ─────────────────────────────────────────────────────────────────────

func TestNopWitnessRotationEmitter_IsNoOp(t *testing.T) {
	var e NopWitnessRotationEmitter
	// Should not panic on nil finding (defense-in-depth).
	e.Emit(context.Background(), nil)
	// Should not panic on a real finding.
	e.Emit(context.Background(), fixtureFinding(t))
}

// ─────────────────────────────────────────────────────────────────────
// (2) LoggingWitnessRotationEmitter
// ─────────────────────────────────────────────────────────────────────

func TestLoggingWitnessRotationEmitter_EmitIncrementsCounterAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e := NewLoggingWitnessRotationEmitter(logger)

	if got := e.Emitted(); got != 0 {
		t.Fatalf("Emitted before any Emit = %d, want 0", got)
	}

	f := fixtureFinding(t)
	e.Emit(context.Background(), f)

	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted after one Emit = %d, want 1", got)
	}

	line := buf.String()
	if !strings.Contains(line, "witnessclient: rotation event") {
		t.Errorf("log line missing event marker: %q", line)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, line)
	}
	// Spot-check the load-bearing field — new_set_size. If a
	// future refactor drops a field, the structured-log shape
	// detects it.
	if got, want := int(parsed["new_set_size"].(float64)), 1; got != want {
		t.Errorf("log new_set_size = %d, want %d", got, want)
	}
	if got, want := parsed["ledger_endpoint"].(string), "https://ledger.example/"; got != want {
		t.Errorf("log ledger_endpoint = %q, want %q", got, want)
	}
}

func TestLoggingWitnessRotationEmitter_NilFindingIsNoOp(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	e.Emit(context.Background(), nil) // must not panic
	if got := e.Emitted(); got != 0 {
		t.Errorf("nil-finding Emit incremented counter: got %d, want 0", got)
	}
}

func TestLoggingWitnessRotationEmitter_NilLoggerFallsBackToDefault(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(nil)
	if e == nil {
		t.Fatal("NewLoggingWitnessRotationEmitter(nil) returned nil")
	}
	e.Emit(context.Background(), fixtureFinding(t))
	if got := e.Emitted(); got != 1 {
		t.Errorf("Emitted = %d, want 1", got)
	}
}

func TestLoggingWitnessRotationEmitter_EmittedIsConcurrencySafe(t *testing.T) {
	e := NewLoggingWitnessRotationEmitter(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	f := fixtureFinding(t)
	const N = 100

	done := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			e.Emit(context.Background(), f)
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
	if got := e.Emitted(); got != N {
		t.Errorf("Emitted after %d concurrent Emits = %d, want %d", N, got, N)
	}
}

// ─────────────────────────────────────────────────────────────────────
// (3) RotationHandler.WithEmitter — wire-up
// ─────────────────────────────────────────────────────────────────────

func TestRotationHandler_WithEmitter_ChainsAndStores(t *testing.T) {
	rh := &RotationHandler{}
	cap := &capturingEmitter{}
	got := rh.WithEmitter(cap)
	if got != rh {
		t.Fatal("WithEmitter must return the receiver for chaining")
	}
	if rh.emitter != cap {
		t.Errorf("WithEmitter did not store the emitter: got %v, want %v", rh.emitter, cap)
	}
}

func TestRotationHandler_WithEmitter_AcceptsNil(t *testing.T) {
	rh := (&RotationHandler{}).WithEmitter(&capturingEmitter{})
	if rh.emitter == nil {
		t.Fatal("test setup wrong: emitter should be non-nil before reset")
	}
	rh.WithEmitter(nil)
	if rh.emitter != nil {
		t.Errorf("WithEmitter(nil) did not clear the emitter; got %v", rh.emitter)
	}
}

// TestRotationHandler_WithAppender_ChainsAndStores mirrors the WithEmitter
// wiring test for the v1.39 on-log appender seam: WithAppender stores the
// supplied RotationLogAppender on the handler and returns the receiver for
// chaining. The stored appender is what ProcessRotation's Step 2b invokes;
// a regression that drops it would surface as the "appender not wired"
// fail-closed error.
func TestRotationHandler_WithAppender_ChainsAndStores(t *testing.T) {
	rh := &RotationHandler{}
	app := fakeRotationAppender{logDID: "did:web:ledger.example.gov", seq: 1}
	got := rh.WithAppender(app)
	if got != rh {
		t.Fatal("WithAppender must return the receiver for chaining")
	}
	if rh.appender != RotationLogAppender(app) {
		t.Errorf("WithAppender did not store the appender: got %v, want %v", rh.appender, app)
	}
}

// capturingEmitter records every Emit so the handler-side wiring
// tests can assert on the call. Mirrors the captureEmitter pattern
// in sequencer/ghost_emit_test.go.
type capturingEmitter struct {
	findings []*findings.WitnessRotationFinding
}

func (c *capturingEmitter) Emit(_ context.Context, f *findings.WitnessRotationFinding) {
	c.findings = append(c.findings, f)
}

var _ WitnessRotationEmitter = (*capturingEmitter)(nil)
