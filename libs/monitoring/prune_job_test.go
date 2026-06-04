package monitoring

import (
	"context"
	"errors"
	"testing"
)

type fakePruner struct {
	n          int64
	err        error
	calledWith int
}

func (f *fakePruner) Prune(_ context.Context, days int) (int64, error) {
	f.calledWith = days
	return f.n, f.err
}

func TestPruneJob_RunsWithRetention(t *testing.T) {
	fp := &fakePruner{n: 3}
	alerts, err := PruneJob(fp, 30, nil)(context.Background())
	if err != nil {
		t.Fatalf("job: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("alerts = %d, want 0 (prune raises none)", len(alerts))
	}
	if fp.calledWith != 30 {
		t.Errorf("Prune retentionDays = %d, want 30", fp.calledWith)
	}
}

func TestPruneJob_PropagatesError(t *testing.T) {
	want := errors.New("db down")
	if _, err := PruneJob(&fakePruner{err: want}, 7, nil)(context.Background()); !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}
