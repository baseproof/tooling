// Tests for the JournaledHeadStore decorator.
//
// The decorator's contract:
//
//  1. Inner store advances on every Record (the existing
//     gossip-reconciler path).
//  2. Journal also captures every Record (the durable archive).
//  3. Journal failure does NOT break the inner advance — live
//     verification stays available even if the journal is down.
//  4. The journal's HeadsJournal contract holds end-to-end —
//     historical reads via the journal return what was written
//     via the decorator.
package monitoring

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/baseproof/baseproof/types"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func cosignedFixture(seq uint64, rootSeed byte) types.CosignedTreeHead {
	return types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: [32]byte{rootSeed},
			TreeSize: seq,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0xAA, rootSeed}, SchemeTag: 0x01, SigBytes: []byte{0xCD, rootSeed}},
		},
	}
}

// TestJournaled_NilJournal_NoOpDelegation pins that wrapping with a
// nil journal is structurally equivalent to using the inner store
// directly. The "no durable archive" mode is a valid deployment
// (small / dev / test).
func TestJournaled_NilJournal_NoOpDelegation(t *testing.T) {
	t.Parallel()
	inner := NewTrustedHeadStore(quietLogger())
	dec := NewJournaledHeadStore(inner, nil, quietLogger())

	cosigned := cosignedFixture(100, 0x01)
	verdict := dec.RecordCosignedHead(context.Background(),
		"did:web:tn", cosigned, 1, time.Now().UTC(), []byte("wire"))

	if verdict != VerdictAdvanced {
		t.Errorf("verdict = %v, want VerdictAdvanced", verdict)
	}
	got, ok := dec.TrustedHead("did:web:tn")
	if !ok || got.TreeSize != 100 {
		t.Errorf("TrustedHead = %+v ok=%v", got, ok)
	}
}

// TestJournaled_FanOut_JournalReceivesEveryRecord pins the core
// decorator contract: every Record on the decorator becomes both
// an inner-store advance AND a journal write.
func TestJournaled_FanOut_JournalReceivesEveryRecord(t *testing.T) {
	t.Parallel()
	inner := NewTrustedHeadStore(quietLogger())
	journal := NewMemoryHeadsJournal()
	dec := NewJournaledHeadStore(inner, journal, quietLogger())

	const did = "did:web:tn"
	heads := []types.CosignedTreeHead{
		cosignedFixture(10, 0xAA),
		cosignedFixture(20, 0xBB),
		cosignedFixture(30, 0xCC),
	}
	committed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, h := range heads {
		dec.RecordCosignedHead(context.Background(), did, h,
			uint64(i+1), committed.Add(time.Duration(i)*time.Hour),
			[]byte("wire"))
	}

	// Inner store sees the latest only.
	got, ok := inner.TrustedHead(did)
	if !ok || got.TreeSize != 30 {
		t.Errorf("inner TrustedHead = %+v ok=%v, want size 30", got, ok)
	}

	// Journal sees every Record.
	for i, h := range heads {
		journaled, err := journal.HeadByRootHash(context.Background(), did, h.TreeSize, h.RootHash)
		if err != nil {
			t.Errorf("journal HeadByRootHash[%d]: %v", i, err)
			continue
		}
		if journaled.TreeSize != h.TreeSize || journaled.RootHash != h.RootHash {
			t.Errorf("journal[%d]: got %x size %d, want %x size %d",
				i, journaled.RootHash, journaled.TreeSize, h.RootHash, h.TreeSize)
		}
	}
}

// TestJournaled_AsOfReadsHistorical pins that historical-asOf
// reads against the journal return the right head — i.e., the
// fan-out preserves enough state for the journal contract to hold.
func TestJournaled_AsOfReadsHistorical(t *testing.T) {
	t.Parallel()
	inner := NewTrustedHeadStore(quietLogger())
	journal := NewMemoryHeadsJournal()
	dec := NewJournaledHeadStore(inner, journal, quietLogger())

	const did = "did:web:tn"
	dec.RecordCosignedHead(context.Background(), did, cosignedFixture(10, 0xAA), 1,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), []byte("wire"))
	dec.RecordCosignedHead(context.Background(), did, cosignedFixture(20, 0xBB), 2,
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), []byte("wire"))
	dec.RecordCosignedHead(context.Background(), did, cosignedFixture(30, 0xCC), 3,
		time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), []byte("wire"))

	// Historical: asOf=15 → seq=10.
	got, err := journal.HeadAt(context.Background(), did, 15)
	if err != nil {
		t.Fatalf("HeadAt: %v", err)
	}
	if got.TreeSize != 10 {
		t.Errorf("HeadAt(15).TreeSize = %d, want 10", got.TreeSize)
	}

	// Live: inner reports latest=30.
	live, _ := dec.TrustedHead(did)
	if live.TreeSize != 30 {
		t.Errorf("live TrustedHead = %d, want 30", live.TreeSize)
	}
}

// brokenJournal returns an error from every Record call. Used to
// pin that journal failures do not break the inner advance.
type brokenJournal struct{ MemoryHeadsJournal }

func (b *brokenJournal) Record(ctx context.Context, h Head) (RecordVerdict, error) {
	return RecordVerdict{}, errors.New("broken: simulated journal outage")
}

// TestJournaled_JournalFailure_InnerStillAdvances pins decision 4
// applied to the fan-out: if the journal is broken, live
// verification stays available (the in-memory anchor still advances)
// and the journal failure surfaces as a log event, not a verification
// outage.
func TestJournaled_JournalFailure_InnerStillAdvances(t *testing.T) {
	t.Parallel()
	inner := NewTrustedHeadStore(quietLogger())
	broken := &brokenJournal{*NewMemoryHeadsJournal()}
	dec := NewJournaledHeadStore(inner, broken, quietLogger())

	verdict := dec.RecordCosignedHead(context.Background(),
		"did:web:tn", cosignedFixture(100, 0x01), 1, time.Now().UTC(), []byte("wire"))

	// Inner advance: SUCCEEDED despite the journal failure.
	if verdict != VerdictAdvanced {
		t.Errorf("inner verdict = %v, want VerdictAdvanced (journal failure must not block live verification)", verdict)
	}
	got, ok := inner.TrustedHead("did:web:tn")
	if !ok || got.TreeSize != 100 {
		t.Errorf("inner TrustedHead = %+v ok=%v after journal failure", got, ok)
	}
}

// TestJournaled_Inner_PanicsOnNil pins the constructor contract:
// inner store is REQUIRED.
func TestJournaled_Inner_PanicsOnNil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewJournaledHeadStore(nil, ...) should panic")
		}
	}()
	_ = NewJournaledHeadStore(nil, nil, quietLogger())
}

// TestJournaled_Accessors_ReturnUnderlyings pins the Inner() and
// Journal() escape hatches.
func TestJournaled_Accessors_ReturnUnderlyings(t *testing.T) {
	t.Parallel()
	inner := NewTrustedHeadStore(quietLogger())
	journal := NewMemoryHeadsJournal()
	dec := NewJournaledHeadStore(inner, journal, quietLogger())

	if dec.Inner() != inner {
		t.Error("Inner() did not return the original inner store")
	}
	if dec.Journal() != journal {
		t.Error("Journal() did not return the original journal")
	}
}
