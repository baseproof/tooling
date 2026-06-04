package aggregator

import (
	"context"
	"testing"

	"github.com/baseproof/tooling/libs/clitools"
)

type fakeLedger struct {
	byStart map[uint64][]clitools.RawEntry
}

func (f *fakeLedger) ScanFrom(_ context.Context, startPos uint64, _ int) ([]clitools.RawEntry, error) {
	return f.byStart[startPos], nil
}

type fakeWatermarks struct{ wm map[string]uint64 }

func (f *fakeWatermarks) GetWatermark(logDID string) (uint64, error) { return f.wm[logDID], nil }
func (f *fakeWatermarks) UpdateWatermark(logDID string, pos uint64) error {
	f.wm[logDID] = pos
	return nil
}

type recordingProjector struct{ seen []uint64 }

func (p *recordingProjector) Project(_ context.Context, e *DecodedEntry) error {
	p.seen = append(p.seen, e.Sequence)
	return nil
}

func TestScanner_RunOnce_ProjectsAndAdvancesWatermark(t *testing.T) {
	led := &fakeLedger{byStart: map[uint64][]clitools.RawEntry{
		0: {rawFrom(t, 0, mustRoot(t)), rawFrom(t, 1, mustRoot(t))},
	}}
	wm := &fakeWatermarks{wm: map[string]uint64{}}
	proj := &recordingProjector{}

	s := NewScanner(ScannerConfig{LogDIDs: []string{"log-a"}, BatchSize: 10}, led, wm, proj, quietLogger())
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(proj.seen) != 2 {
		t.Fatalf("projected %d entries, want 2", len(proj.seen))
	}
	if wm.wm["log-a"] != 1 {
		t.Errorf("watermark = %d, want 1 (lastSeq)", wm.wm["log-a"])
	}
}

func TestScanner_RunOnce_EmptyLeavesWatermark(t *testing.T) {
	led := &fakeLedger{byStart: map[uint64][]clitools.RawEntry{}}
	wm := &fakeWatermarks{wm: map[string]uint64{"log-a": 5}}
	proj := &recordingProjector{}

	s := NewScanner(ScannerConfig{LogDIDs: []string{"log-a"}, BatchSize: 10}, led, wm, proj, quietLogger())
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(proj.seen) != 0 {
		t.Errorf("projected %d, want 0", len(proj.seen))
	}
	if wm.wm["log-a"] != 5 {
		t.Errorf("watermark moved to %d, want unchanged 5", wm.wm["log-a"])
	}
}

func TestScanner_RunOnce_SkipsUndecodableButAdvances(t *testing.T) {
	led := &fakeLedger{byStart: map[uint64][]clitools.RawEntry{
		0: {
			rawFrom(t, 3, mustRoot(t)),          // good
			{Sequence: 4, CanonicalHex: "zzzz"}, // non-hex → decode error
		},
	}}
	wm := &fakeWatermarks{wm: map[string]uint64{}}
	proj := &recordingProjector{}

	s := NewScanner(ScannerConfig{LogDIDs: []string{"log-a"}, BatchSize: 10}, led, wm, proj, quietLogger())
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(proj.seen) != 1 || proj.seen[0] != 3 {
		t.Errorf("projected %v, want [3] (bad entry skipped)", proj.seen)
	}
	if wm.wm["log-a"] != 4 {
		t.Errorf("watermark = %d, want 4 (batch advances past a skip)", wm.wm["log-a"])
	}
}
