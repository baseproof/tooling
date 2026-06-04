package monitoring

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baseproof/baseproof/monitoring"
)

type fakeSink struct {
	mu   sync.Mutex
	runs []sinkCall
}

type sinkCall struct {
	job   string
	ok    bool
	bySev map[string]int
}

func (f *fakeSink) RecordRun(job string, ok bool, _ time.Duration, bySev map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, sinkCall{job: job, ok: ok, bySev: bySev})
}

func (f *fakeSink) calls() []sinkCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sinkCall(nil), f.runs...)
}

func okJob(name string) Job {
	return Job{Name: name, Interval: time.Hour, Run: func(context.Context) ([]monitoring.Alert, error) {
		return nil, nil
	}}
}

func TestScheduler_Register_Validation(t *testing.T) {
	s := NewScheduler(SchedulerConfig{})
	cases := []Job{
		{Name: "", Interval: time.Minute, Run: func(context.Context) ([]monitoring.Alert, error) { return nil, nil }},
		{Name: "x", Interval: 0, Run: func(context.Context) ([]monitoring.Alert, error) { return nil, nil }},
		{Name: "x", Interval: time.Minute, Run: nil},
	}
	for i, j := range cases {
		if err := s.Register(j); !errors.Is(err, ErrInvalidJob) {
			t.Fatalf("case %d: want ErrInvalidJob, got %v", i, err)
		}
	}
	if err := s.Register(okJob("dup")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := s.Register(okJob("dup")); !errors.Is(err, ErrInvalidJob) {
		t.Fatalf("duplicate name must be rejected, got %v", err)
	}
}

func TestScheduler_RunOnce_RecordsAlertsToCacheAndSink(t *testing.T) {
	sink := &fakeSink{}
	s := NewScheduler(SchedulerConfig{Sink: sink})
	job := Job{Name: "mirror", Interval: time.Hour, Run: func(context.Context) ([]monitoring.Alert, error) {
		return []monitoring.Alert{
			{Severity: monitoring.Warning}, {Severity: monitoring.Warning}, {Severity: monitoring.Critical},
		}, nil
	}}
	s.runOnce(context.Background(), job)

	res, ok := s.Cache().Get("mirror")
	if !ok || !res.OK {
		t.Fatalf("cache: ok=%v res.OK=%v", ok, res.OK)
	}
	if res.AlertsBySeverity["warning"] != 2 || res.AlertsBySeverity["critical"] != 1 {
		t.Fatalf("severity counts wrong: %+v", res.AlertsBySeverity)
	}
	calls := sink.calls()
	if len(calls) != 1 || calls[0].job != "mirror" || !calls[0].ok {
		t.Fatalf("sink not driven correctly: %+v", calls)
	}
	if calls[0].bySev["warning"] != 2 {
		t.Fatalf("sink severity wrong: %+v", calls[0].bySev)
	}
}

func TestScheduler_RunOnce_CheckErrorRecordedAsNotOK(t *testing.T) {
	sink := &fakeSink{}
	s := NewScheduler(SchedulerConfig{Sink: sink})
	job := Job{Name: "anchor", Interval: time.Hour, Run: func(context.Context) ([]monitoring.Alert, error) {
		return nil, errors.New("ledger unreachable")
	}}
	s.runOnce(context.Background(), job)

	res, _ := s.Cache().Get("anchor")
	if res.OK || res.Err == "" {
		t.Fatalf("error run must record OK=false with Err set: %+v", res)
	}
	if calls := sink.calls(); len(calls) != 1 || calls[0].ok {
		t.Fatalf("sink should record a failed run: %+v", calls)
	}
}

func TestScheduler_PanicRecovered(t *testing.T) {
	s := NewScheduler(SchedulerConfig{})
	job := Job{Name: "boom", Interval: time.Hour, Run: func(context.Context) ([]monitoring.Alert, error) {
		panic("kaboom")
	}}
	// Must not propagate the panic.
	s.runOnce(context.Background(), job)
	res, ok := s.Cache().Get("boom")
	if !ok || res.OK {
		t.Fatalf("panicking job must be recorded as a failed run: ok=%v %+v", ok, res)
	}
}

func TestScheduler_Run_ImmediateThenCancel(t *testing.T) {
	s := NewScheduler(SchedulerConfig{})
	var runs int32
	done := make(chan struct{})
	var once sync.Once
	job := Job{Name: "tick", Interval: time.Hour, Run: func(context.Context) ([]monitoring.Alert, error) {
		atomic.AddInt32(&runs, 1)
		once.Do(func() { close(done) })
		return nil, nil
	}}
	if err := s.Register(job); err != nil {
		t.Fatalf("register: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() { s.Run(ctx); close(finished) }()

	select {
	case <-done: // immediate first run happened
	case <-time.After(2 * time.Second):
		t.Fatal("immediate run did not occur")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if atomic.LoadInt32(&runs) < 1 {
		t.Fatalf("expected >=1 run, got %d", atomic.LoadInt32(&runs))
	}
}
