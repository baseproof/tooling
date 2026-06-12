// FILE PATH: libs/witnessrotation/journal_memory.go
//
// MemoryRotationJournal — the in-memory RotationJournal, for processes whose
// rotation chain is an ENFORCER'S CACHE rather than custody: rebuilt at boot
// by the gossip puller's natural re-ingest (in-memory pull cursors restart at
// zero), while year-15 durability stays with the durable journal
// (journalpg.PostgresWitnessRotationJournal), which is custody's job.
//
// CONTRACT PARITY (locked by the parity test beside the PG implementation):
// the observable behavior mirrors the durable journal exactly —
//
//   - RecordRotation refuses a null EffectivePos (historical reconstruction
//     requires a concrete proven position per record);
//   - the rotation is round-tripped through the SDK's canonical codec at
//     record time (EncodeWitnessRotationPayload validates structure; the
//     stored truth is the canonical wire bytes, decoded on read — the same
//     bytes-first posture as the durable rows);
//   - idempotent on (LogDID, EffectivePos.Sequence): a rotation's proven
//     position is its identity, so an at-least-once gossip redelivery is a
//     harmless no-op (first write wins — the PG row's ON CONFLICT DO NOTHING);
//   - RecordsFor returns the chain sorted ascending by sequence — exactly the
//     sorted form witness.WitnessSetAt requires.
//
// Concurrency: guarded by one RWMutex — reconciler writes and resolver reads
// race-free (mirrors monitoring.MemoryHeadsJournal's posture).
package witnessrotation

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// memRotationRow is one journaled rotation: canonical wire bytes + the clock.
type memRotationRow struct {
	seq        uint64
	payload    []byte
	recordedAt time.Time
}

// MemoryRotationJournal is the in-memory RotationJournal implementation.
// Construct via NewMemoryRotationJournal. Safe for concurrent use.
type MemoryRotationJournal struct {
	mu    sync.RWMutex
	byLog map[string][]memRotationRow // sorted ascending by seq
	now   func() time.Time
}

// Static conformance: the scan reconciler's read+append seam. (The gossip
// reconciler's narrower RotationJournal seam is asserted in the test file —
// keeping this package free of a production monitoring import.)
var _ RotationJournal = (*MemoryRotationJournal)(nil)

// NewMemoryRotationJournal constructs an empty in-memory journal.
func NewMemoryRotationJournal() *MemoryRotationJournal {
	return &MemoryRotationJournal{byLog: make(map[string][]memRotationRow), now: time.Now}
}

// RecordRotation persists one verified rotation as a position-bearing record.
// Idempotent on (LogDID, EffectivePos.Sequence); fail-closed on a null
// EffectivePos. See the file header for the locked contract.
func (j *MemoryRotationJournal) RecordRotation(_ context.Context, record types.WitnessRotationRecord) error {
	if record.EffectivePos.IsNull() {
		return fmt.Errorf("witnessrotation: refusing to journal record with null EffectivePos")
	}
	payload, err := witness.EncodeWitnessRotationPayload(record.Rotation)
	if err != nil {
		return fmt.Errorf("witnessrotation: encode rotation: %w", err)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	rows := j.byLog[record.EffectivePos.LogDID]
	i := sort.Search(len(rows), func(i int) bool { return rows[i].seq >= record.EffectivePos.Sequence })
	if i < len(rows) && rows[i].seq == record.EffectivePos.Sequence {
		return nil // first write wins — idempotent re-delivery
	}
	rows = append(rows, memRotationRow{})
	copy(rows[i+1:], rows[i:])
	rows[i] = memRotationRow{seq: record.EffectivePos.Sequence, payload: payload, recordedAt: j.now().UTC()}
	j.byLog[record.EffectivePos.LogDID] = rows
	return nil
}

// RecordsFor returns the full rotation chain for logDID, sorted ascending by
// EffectivePos.Sequence — exactly the sorted form witness.WitnessSetAt requires.
func (j *MemoryRotationJournal) RecordsFor(_ context.Context, logDID string) ([]types.WitnessRotationRecord, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	rows := j.byLog[logDID]
	out := make([]types.WitnessRotationRecord, 0, len(rows))
	for _, row := range rows {
		rot, err := witness.DecodeWitnessRotationPayload(row.payload)
		if err != nil {
			return nil, fmt.Errorf("witnessrotation: decode seq=%d: %w", row.seq, err)
		}
		out = append(out, types.WitnessRotationRecord{
			Rotation:     rot,
			EffectivePos: types.LogPosition{LogDID: logDID, Sequence: row.seq},
		})
	}
	return out, nil
}

// LatestRecordedAtFor returns when the NEWEST rotation for logDID was
// journaled — the wall clock adoption-grace windows run against. ok=false when
// the log has no journaled rotations.
func (j *MemoryRotationJournal) LatestRecordedAtFor(_ context.Context, logDID string) (time.Time, bool, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	rows := j.byLog[logDID]
	if len(rows) == 0 {
		return time.Time{}, false, nil
	}
	return rows[len(rows)-1].recordedAt, true, nil
}

// PurgeFor deletes the journaled rotation chain for logDID. The journal is a
// rebuildable cache, not bedrock: dropping it is safe because the chain is
// re-materialized by re-ingesting the log's rotation records through the
// idempotent RecordRotation (the DoD rebuild cycle).
func (j *MemoryRotationJournal) PurgeFor(_ context.Context, logDID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.byLog, logDID)
	return nil
}
