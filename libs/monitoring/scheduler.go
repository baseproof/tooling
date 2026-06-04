// FILE PATH: libs/monitoring/scheduler.go
//
// DESCRIPTION:
//
//	The continuous-monitoring ticker engine — the JN's pulse. It turns
//	the on-demand Check* functions into autonomous audits: each
//	registered Job runs on its own time.Ticker, in its own
//	panic-recovered goroutine, until the supplied context is cancelled.
//	A slow or panicking job never starves or tears down its siblings.
//
//	Every run's outcome is written to a HealthCache (O(1) reads) and,
//	optionally, to a Sink (the OTel adapter lives in the observability
//	package — this package imports no metrics backend, keeping the engine
//	unit-testable and dependency-light). The loops evaluate the math and
//	publish gauges; they perform NO external alerting I/O (no Slack /
//	PagerDuty) — routing is left to the scrape-side infrastructure.
//
// KEY DEPENDENCIES:
//   - baseproof/monitoring: Alert, Severity (the universal alert shape the
//     Check* functions emit).
package monitoring

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/baseproof/baseproof/monitoring"
)

// ErrInvalidJob is returned by Register for a malformed Job.
var ErrInvalidJob = errors.New("monitoring/scheduler: invalid job")

// JobFunc runs one monitoring check and returns the alerts it raised.
// A non-nil error means the check itself could not complete (distinct
// from completing and finding alerts).
type JobFunc func(ctx context.Context) ([]monitoring.Alert, error)

// Job is a named, periodically-scheduled check.
type Job struct {
	// Name labels the job in the cache, gauges, and logs. Must be unique.
	Name string
	// Interval is the cadence between runs (e.g. 5m / 1h / 24h).
	Interval time.Duration
	// Run executes the check.
	Run JobFunc
}

// Sink receives the outcome of each run. The OTel implementation lives
// in api/middleware/observability; tests inject a fake. nil is allowed
// (the scheduler still records to its HealthCache).
type Sink interface {
	RecordRun(job string, ok bool, dur time.Duration, alertsBySeverity map[string]int)
}

// Scheduler runs registered jobs until ctx is cancelled.
type Scheduler struct {
	jobs   []Job
	sink   Sink
	cache  *HealthCache
	logger *slog.Logger
}

// SchedulerConfig configures a Scheduler.
type SchedulerConfig struct {
	// Sink receives per-run telemetry. Optional.
	Sink Sink
	// Logger; nil ⇒ slog.Default().
	Logger *slog.Logger
}

// NewScheduler returns an empty scheduler ready for Register.
func NewScheduler(cfg SchedulerConfig) *Scheduler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{sink: cfg.Sink, cache: NewHealthCache(), logger: logger}
}

// Register adds a job. Rejects empty names, non-positive intervals, nil
// Run funcs, and duplicate names.
func (s *Scheduler) Register(j Job) error {
	if j.Name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidJob)
	}
	if j.Interval <= 0 {
		return fmt.Errorf("%w: %s: interval must be positive", ErrInvalidJob, j.Name)
	}
	if j.Run == nil {
		return fmt.Errorf("%w: %s: nil Run", ErrInvalidJob, j.Name)
	}
	for _, e := range s.jobs {
		if e.Name == j.Name {
			return fmt.Errorf("%w: duplicate name %q", ErrInvalidJob, j.Name)
		}
	}
	s.jobs = append(s.jobs, j)
	return nil
}

// Cache exposes the health cache (scraped / served read-only).
func (s *Scheduler) Cache() *HealthCache { return s.cache }

// Len reports the number of registered jobs.
func (s *Scheduler) Len() int { return len(s.jobs) }

// JobNames returns the registered job names in registration order.
func (s *Scheduler) JobNames() []string {
	out := make([]string, len(s.jobs))
	for i, j := range s.jobs {
		out[i] = j.Name
	}
	return out
}

// Run launches every registered job on its own ticker and blocks until
// ctx is cancelled. Each job runs once immediately (so the first audit
// is at boot, not one interval later) and then every Interval.
func (s *Scheduler) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, j := range s.jobs {
		wg.Add(1)
		go func(j Job) {
			defer wg.Done()
			s.loop(ctx, j)
		}(j)
	}
	wg.Wait()
}

func (s *Scheduler) loop(ctx context.Context, j Job) {
	t := time.NewTicker(j.Interval)
	defer t.Stop()
	s.runOnce(ctx, j)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runOnce(ctx, j)
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context, j Job) {
	start := time.Now()
	alerts, err := s.safeRun(ctx, j)
	dur := time.Since(start)
	bySev := severityCounts(alerts)

	res := Result{Job: j.Name, LastRun: start, Duration: dur, OK: err == nil, AlertsBySeverity: bySev}
	if err != nil {
		res.Err = err.Error()
	}
	s.cache.put(res)
	if s.sink != nil {
		s.sink.RecordRun(j.Name, err == nil, dur, bySev)
	}

	switch {
	case err != nil:
		s.logger.Error("monitoring/scheduler: job failed",
			slog.String("job", j.Name), slog.String("error", err.Error()))
	case len(alerts) > 0:
		s.logger.Warn("monitoring/scheduler: job raised alerts",
			slog.String("job", j.Name), slog.Int("alerts", len(alerts)))
	default:
		s.logger.Debug("monitoring/scheduler: job ok", slog.String("job", j.Name))
	}
}

// safeRun isolates a job's panic so one bad check never tears down the
// scheduler — a panicking job is recorded as a failed run.
func (s *Scheduler) safeRun(ctx context.Context, j Job) (alerts []monitoring.Alert, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("monitoring/scheduler: job panicked",
				slog.String("job", j.Name),
				slog.String("panic", fmt.Sprint(r)),
				slog.String("stack", string(debug.Stack())))
			alerts = nil
			err = fmt.Errorf("monitoring/scheduler: job %q panicked: %v", j.Name, r)
		}
	}()
	return j.Run(ctx)
}

func severityCounts(alerts []monitoring.Alert) map[string]int {
	if len(alerts) == 0 {
		return nil
	}
	m := make(map[string]int, 3)
	for _, a := range alerts {
		m[severityLabel(a.Severity)]++
	}
	return m
}

func severityLabel(s monitoring.Severity) string {
	switch s {
	case monitoring.Critical:
		return "critical"
	case monitoring.Warning:
		return "warning"
	default:
		return "info"
	}
}
