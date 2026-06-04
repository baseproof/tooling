/*
FILE PATH: libs/crosslog/materialize_test.go

T1 unit tests — MaterializeFromEntries.

Verifies the kind-discriminated decode + warn-and-continue +
sort-by-EffectivePos pipeline that bridges raw envelope entries
to the three SDK *ByPosition record slices the resolver consumes.

# COVERAGE MATRIX

  - Empty / nil entry slice                    → zero MaterializedNetwork
  - Single endpoint entry                      → one endpoint record, no labels/auditors
  - Single label entry                         → one label record, no endpoints/auditors
  - Single auditor entry                       → one auditor record, no endpoints/labels
  - Mixed kinds across entries                 → all three slices populated
  - Non-network kind entry (admission rotation, etc.) → silently skipped
  - Out-of-order EffectivePos input            → output sorted ascending
  - Invalid network-kind entry (kind matches, Validate fails) → skipped + warn (not in output)
  - Nil Entry pointer in EntryAtPosition       → skipped (no panic)
  - Empty DomainPayload                         → skipped (no panic)
  - Checkpoint field threaded into output      → record carries it
*/
package crosslog

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
)

// makeEntry wraps domain payload bytes into a minimal envelope.Entry
// with just the header fields the materializer reads (none — only
// DomainPayload is touched by MaterializeFromEntries).
func makeEntry(t *testing.T, payload []byte) *envelope.Entry {
	t.Helper()
	hdr := envelope.ControlHeader{
		SignerDID:   "did:web:test-signer",
		Destination: "did:test:log",
		EventTime:   1700000000,
	}
	e, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("envelope.NewUnsignedEntry: %v", err)
	}
	return e
}

// at returns an EntryAtPosition with the given sequence + payload.
func at(t *testing.T, seq uint64, payload []byte) EntryAtPosition {
	t.Helper()
	return EntryAtPosition{
		Position: types.LogPosition{Sequence: seq},
		Entry:    makeEntry(t, payload),
	}
}

// discardLogger returns a logger that drops every record so tests
// can assert on return values without noise.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger returns a logger that writes to a bytes.Buffer the
// caller can inspect for WARN lines (used to verify warn-and-continue).
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// ─────────────────────────────────────────────────────────────
// Empty / nil
// ─────────────────────────────────────────────────────────────

func TestMaterialize_EmptyEntries(t *testing.T) {
	got := MaterializeFromEntries(nil, discardLogger())
	if len(got.Endpoints) != 0 || len(got.Labels) != 0 || len(got.Auditors) != 0 {
		t.Errorf("empty input must yield zero MaterializedNetwork; got %+v", got)
	}
}

func TestMaterialize_NilEntryPointer(t *testing.T) {
	// EntryAtPosition with nil Entry — must skip without panic.
	got := MaterializeFromEntries([]EntryAtPosition{
		{Position: types.LogPosition{Sequence: 1}, Entry: nil},
	}, discardLogger())
	if len(got.Endpoints) != 0 || len(got.Labels) != 0 || len(got.Auditors) != 0 {
		t.Errorf("nil Entry must be skipped; got %+v", got)
	}
}

func TestMaterialize_EmptyDomainPayload(t *testing.T) {
	got := MaterializeFromEntries([]EntryAtPosition{
		at(t, 1, nil),
		at(t, 2, []byte{}),
	}, discardLogger())
	if len(got.Endpoints) != 0 || len(got.Labels) != 0 || len(got.Auditors) != 0 {
		t.Errorf("empty payload must be skipped; got %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────
// Happy paths — one kind per test
// ─────────────────────────────────────────────────────────────

func TestMaterialize_SingleEndpoint(t *testing.T) {
	payload, err := network.EncodeWitnessEndpointDeclarationPayload(validEndpointDeclaration(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := MaterializeFromEntries([]EntryAtPosition{at(t, 5, payload)}, discardLogger())
	if len(got.Endpoints) != 1 {
		t.Fatalf("Endpoints: got %d, want 1", len(got.Endpoints))
	}
	if got.Endpoints[0].EffectivePos.Sequence != 5 {
		t.Errorf("EffectivePos.Sequence: got %d, want 5", got.Endpoints[0].EffectivePos.Sequence)
	}
	if len(got.Labels) != 0 || len(got.Auditors) != 0 {
		t.Errorf("Labels/Auditors must be empty; got Labels=%d Auditors=%d",
			len(got.Labels), len(got.Auditors))
	}
}

func TestMaterialize_SingleLabel(t *testing.T) {
	payload, err := network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := MaterializeFromEntries([]EntryAtPosition{at(t, 7, payload)}, discardLogger())
	if len(got.Labels) != 1 {
		t.Fatalf("Labels: got %d, want 1", len(got.Labels))
	}
	if got.Labels[0].Payload.Label != "Test Witness" {
		t.Errorf("Label: got %q", got.Labels[0].Payload.Label)
	}
}

func TestMaterialize_SingleAuditor(t *testing.T) {
	payload, err := network.EncodeAuditorRegistrationPayload(validAuditorRegistration(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got := MaterializeFromEntries([]EntryAtPosition{at(t, 9, payload)}, discardLogger())
	if len(got.Auditors) != 1 {
		t.Fatalf("Auditors: got %d, want 1", len(got.Auditors))
	}
	if got.Auditors[0].Payload.AuditorDID != "did:web:auditor.example.org" {
		t.Errorf("AuditorDID: got %q", got.Auditors[0].Payload.AuditorDID)
	}
}

// ─────────────────────────────────────────────────────────────
// Mixed kinds
// ─────────────────────────────────────────────────────────────

func TestMaterialize_MixedKinds(t *testing.T) {
	endpointPayload, _ := network.EncodeWitnessEndpointDeclarationPayload(validEndpointDeclaration(t))
	labelPayload, _ := network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))
	auditorPayload, _ := network.EncodeAuditorRegistrationPayload(validAuditorRegistration(t))

	got := MaterializeFromEntries([]EntryAtPosition{
		at(t, 1, endpointPayload),
		at(t, 2, labelPayload),
		at(t, 3, auditorPayload),
	}, discardLogger())

	if len(got.Endpoints) != 1 {
		t.Errorf("Endpoints: got %d, want 1", len(got.Endpoints))
	}
	if len(got.Labels) != 1 {
		t.Errorf("Labels: got %d, want 1", len(got.Labels))
	}
	if len(got.Auditors) != 1 {
		t.Errorf("Auditors: got %d, want 1", len(got.Auditors))
	}
}

// ─────────────────────────────────────────────────────────────
// Non-network payloads pass through silently
// ─────────────────────────────────────────────────────────────

func TestMaterialize_NonNetworkKindSkipped(t *testing.T) {
	rawNon := []byte(`{"kind":"some_application_v1","data":"x"}`)
	buf := &bytes.Buffer{}
	got := MaterializeFromEntries([]EntryAtPosition{at(t, 1, rawNon)}, captureLogger(buf))

	if len(got.Endpoints) != 0 || len(got.Labels) != 0 || len(got.Auditors) != 0 {
		t.Errorf("non-network payload must be skipped; got %+v", got)
	}
	// Silent skip — no WARN line.
	if bytes.Contains(buf.Bytes(), []byte("level=WARN")) {
		t.Errorf("non-network kind must NOT log WARN; got:\n%s", buf.String())
	}
}

// ─────────────────────────────────────────────────────────────
// Validation failures log WARN and continue
// ─────────────────────────────────────────────────────────────

func TestMaterialize_InvalidEntryLogsAndContinues(t *testing.T) {
	// First entry: malformed endpoint (kind matches, Validate fails)
	wireBad := map[string]any{
		"kind":       network.WitnessEndpointDeclarationKindV1,
		"pub_key_id": "0100000000000000000000000000000000000000000000000000000000000000",
		"endpoints":  map[string]string{}, // empty — SDK rejects
	}
	badPayload, _ := json.Marshal(wireBad)
	// Second entry: valid label
	goodLabel, _ := network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))

	buf := &bytes.Buffer{}
	got := MaterializeFromEntries([]EntryAtPosition{
		at(t, 1, badPayload),
		at(t, 2, goodLabel),
	}, captureLogger(buf))

	// Invalid endpoint skipped; valid label included.
	if len(got.Endpoints) != 0 {
		t.Errorf("invalid endpoint must NOT be included; got %d", len(got.Endpoints))
	}
	if len(got.Labels) != 1 {
		t.Errorf("valid label must be included; got %d", len(got.Labels))
	}
	// And a WARN was emitted for the invalid entry. The Ladder 2 D3
	// kind-probe refactor emits a single generic "SDK validate rejected
	// payload" message regardless of which kind matched, with the SDK's
	// structural error text on the err= attribute. Pin against the
	// generic message + the SDK's per-field error fragment.
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("SDK validate rejected payload")) {
		t.Errorf("expected WARN about SDK validate failure; got:\n%s", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte("endpoints map must be non-empty")) {
		t.Errorf("expected SDK structural error fragment in WARN; got:\n%s", out)
	}
}

// ─────────────────────────────────────────────────────────────
// Sort order
// ─────────────────────────────────────────────────────────────

func TestMaterialize_SortsByEffectivePos(t *testing.T) {
	// Three labels at positions 100, 5, 50. After materialization,
	// the slice MUST be sorted ascending by Sequence.
	p1, _ := network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))
	p2, _ := network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))
	p3, _ := network.EncodeWitnessIdentityLabelPayload(validIdentityLabel(t))

	got := MaterializeFromEntries([]EntryAtPosition{
		at(t, 100, p1),
		at(t, 5, p2),
		at(t, 50, p3),
	}, discardLogger())

	if len(got.Labels) != 3 {
		t.Fatalf("Labels: got %d, want 3", len(got.Labels))
	}
	if !sort.IsSorted(got.Labels) {
		t.Errorf("Labels not sorted; sequences: %d %d %d",
			got.Labels[0].EffectivePos.Sequence,
			got.Labels[1].EffectivePos.Sequence,
			got.Labels[2].EffectivePos.Sequence)
	}
	want := []uint64{5, 50, 100}
	for i, w := range want {
		if got.Labels[i].EffectivePos.Sequence != w {
			t.Errorf("Labels[%d].Sequence: got %d, want %d",
				i, got.Labels[i].EffectivePos.Sequence, w)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// Checkpoint threading
// ─────────────────────────────────────────────────────────────

func TestMaterialize_CheckpointThreaded(t *testing.T) {
	payload, _ := network.EncodeAuditorRegistrationPayload(validAuditorRegistration(t))
	var checkpoint [32]byte
	checkpoint[0] = 0xab
	checkpoint[31] = 0xcd

	got := MaterializeFromEntries([]EntryAtPosition{{
		Position:   types.LogPosition{Sequence: 1},
		Entry:      makeEntry(t, payload),
		Checkpoint: checkpoint,
	}}, discardLogger())

	if len(got.Auditors) != 1 {
		t.Fatalf("Auditors: got %d, want 1", len(got.Auditors))
	}
	if got.Auditors[0].Checkpoint != checkpoint {
		t.Errorf("Checkpoint not threaded; got %x", got.Auditors[0].Checkpoint)
	}
}

// ─────────────────────────────────────────────────────────────
// Nil logger defaults
// ─────────────────────────────────────────────────────────────

func TestMaterialize_NilLoggerDefaults(t *testing.T) {
	// Must not panic on nil logger — defaults to slog.Default().
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil logger panicked: %v", r)
		}
	}()
	MaterializeFromEntries(nil, nil)
}
