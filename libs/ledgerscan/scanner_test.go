package ledgerscan

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// --- test doubles ---

type fakeQuery struct {
	batches map[uint64][]types.EntryWithMetadata // fromPos → entries
}

func (f *fakeQuery) ScanFromPosition(_ context.Context, start uint64, _ int) ([]types.EntryWithMetadata, error) {
	return f.batches[start], nil
}

type recordedEntry struct {
	logID string
	pos   uint64
	entry *envelope.Entry
}

type stubIndexer struct {
	mu  sync.Mutex
	got []recordedEntry
}

func (s *stubIndexer) IndexEntry(logID string, pos uint64, e *envelope.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, recordedEntry{logID, pos, e})
}

func (s *stubIndexer) snapshot() []recordedEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedEntry(nil), s.got...)
}

type stubCursor struct {
	mu  sync.Mutex
	pos map[string]uint64
}

func newStubCursor() *stubCursor { return &stubCursor{pos: map[string]uint64{}} }
func (c *stubCursor) LastScannedPosition(logID string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pos[logID]
}
func (c *stubCursor) SetLastScannedPosition(logID string, p uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pos[logID] = p
}

// signedEntryBytes builds a minimal signed entry and returns its canonical
// bytes (envelope.Serialize requires >=1 signature).
func signedEntryBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	hdr := envelope.ControlHeader{SignerDID: "did:test:signer", Destination: "did:test:log", EventTime: 1}
	e, err := envelope.NewUnsignedEntry(hdr, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := signatures.SignEntry(sha256.Sum256(envelope.SigningPayload(e)), priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	e.Signatures = []envelope.Signature{{SignerDID: hdr.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	raw, err := envelope.Serialize(e)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return raw
}

func meta(t *testing.T, pos uint64, payload []byte) types.EntryWithMetadata {
	return types.EntryWithMetadata{
		CanonicalBytes: signedEntryBytes(t, payload),
		Position:       types.LogPosition{LogDID: "log1", Sequence: pos},
	}
}

// TestScanBatch_IndexesInOrderAndAdvances proves the generic engine: every
// deserializable entry is handed to the Indexer with its position, malformed
// bytes are skipped, and the returned next-position is maxPos+1.
func TestScanBatch_IndexesInOrderAndAdvances(t *testing.T) {
	idx := &stubIndexer{}
	q := &fakeQuery{batches: map[uint64][]types.EntryWithMetadata{
		0: {
			meta(t, 0, []byte(`{"docket_number":"2027-CR-001"}`)),
			{CanonicalBytes: []byte("not an entry"), Position: types.LogPosition{Sequence: 1}}, // skipped
			meta(t, 2, []byte(`{"party_name":"acme"}`)),
		},
	}}
	s := NewScanner(ScannerConfig{QueryAPI: q, Indexer: idx, Cursor: newStubCursor(), LogID: "log1"})

	next, err := s.scanBatch(context.Background(), 0)
	if err != nil {
		t.Fatalf("scanBatch: %v", err)
	}
	if next != 3 { // maxPos(2) + 1
		t.Errorf("next = %d, want 3", next)
	}
	got := idx.snapshot()
	if len(got) != 2 { // the malformed entry was skipped
		t.Fatalf("indexed %d entries, want 2 (malformed skipped)", len(got))
	}
	if got[0].pos != 0 || got[1].pos != 2 || got[0].logID != "log1" {
		t.Errorf("recorded = %+v, want positions [0,2] on log1", []uint64{got[0].pos, got[1].pos})
	}
	// The scanner is domain-agnostic: it forwards the whole entry; it does NOT
	// itself parse docket_number/party_name. The Indexer would.
	if len(got[0].entry.DomainPayload) == 0 {
		t.Error("indexer should receive the entry's domain payload")
	}
}

func TestScanBatch_EmptyBatchHoldsPosition(t *testing.T) {
	s := NewScanner(ScannerConfig{
		QueryAPI: &fakeQuery{batches: map[uint64][]types.EntryWithMetadata{}},
		Indexer:  &stubIndexer{}, Cursor: newStubCursor(), LogID: "log1",
	})
	next, err := s.scanBatch(context.Background(), 7)
	if err != nil || next != 7 {
		t.Fatalf("empty batch: next=%d err=%v, want 7,nil", next, err)
	}
}

// TestRun_ResumesFromCursorAndPersists proves Run starts at the cursor's saved
// position, advances it, and drains on context cancel.
func TestRun_ResumesFromCursorAndPersists(t *testing.T) {
	idx := &stubIndexer{}
	cur := newStubCursor()
	cur.SetLastScannedPosition("log1", 10) // resume point
	q := &fakeQuery{batches: map[uint64][]types.EntryWithMetadata{
		10: {meta(t, 10, []byte(`{}`)), meta(t, 11, []byte(`{}`))},
	}}
	s := NewScanner(ScannerConfig{QueryAPI: q, Indexer: idx, Cursor: cur, LogID: "log1", Interval: 5 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for cur.LastScannedPosition("log1") < 12 {
		select {
		case <-deadline:
			t.Fatalf("cursor did not advance past 12 (got %d)", cur.LastScannedPosition("log1"))
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	if n := len(idx.snapshot()); n != 2 {
		t.Errorf("indexed %d, want 2 (resumed at 10, no re-scan from 0)", n)
	}
}
