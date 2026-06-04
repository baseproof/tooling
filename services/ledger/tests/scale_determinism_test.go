//go:build scale
// +build scale

/*
FILE PATH: tests/scale_determinism_test.go

At-scale validation of the P5 idempotent-replay contract:

	byte-identical wire input → byte-identical SCT bytes

# DESIGN: continuous end-to-end per iteration

Each worker goroutine runs its own continuous loop:

	for not-done {
	    build wire FRESH (EventTime = now)
	    submit first  → SCT_A
	    submit second → SCT_B (replay)
	    verify canonical_hash + log_time_micros + signature byte-identity
	    next
	}

This is the **transaction-shape** the real-world client uses — one
submission round-trip at a time, fully validated, then move on.
The earlier batched shape (pre-build N envelopes, blast through a
shared queue) had two structural defects that this redesign
eliminates by construction:

	Bug B: pre-built envelopes go stale
	  The freshness policy rejects entries with EventTime older than
	  5 minutes. Pre-building all N envelopes at t=0 and draining
	  them over wall-time T means the last (T/5min × rate) envelopes
	  are stale at submission. Per-iteration construction stamps
	  EventTime at the moment of submission — staleness is impossible.

	Bug C: shared-worker-pool fail-fatal silently kills workers
	  submitEntry calls t.Fatalf on any non-202 response; from a
	  worker goroutine t.Fatalf invokes runtime.Goexit, killing the
	  worker without returning. This redesign uses trySubmitEntry
	  (returns (map, error)) so every failure increments the
	  diagnostic counter correctly.

# WHAT IT VALIDATES

 1. SDK primitive determinism (RFC 6979 ECDSA). Drift on
    `signature` alone → SDK regression.
 2. Ledger dedup-and-replay path. canonical_hash + log_time_micros
    must be persisted at first admission and returned verbatim on
    replay. Drift in either → ledger persistence regression.
 3. Pipeline integrity under concurrent realistic load.

# SESSION LIFETIME: batched re-seed (run length decoupled from TTL)

	The session token seeded by testLedger.seedSession has a fixed TTL
	(now+1h). On a single token, any run that outlasts the TTL expires
	mid-flight; from that point every submission returns 401 "session
	expired" and the retry path spins until the safety-net deadline
	(observed: a 2h N=1M run completed ~263k pairs in the first hour,
	then logged ~48M 401s in the second — drifts=0, i.e. the contract
	held; only the harness session died).

	Fix: the run is chunked into batches of BASEPROOF_SCALE_DETERMINISM_BATCH
	pairs and a FRESH token is seeded at each batch boundary. The token
	in use is therefore always far younger than its TTL, and run length
	is decoupled from session lifetime BY CONSTRUCTION — no TTL guessing,
	works for an arbitrarily long run. Batch size only has to keep one
	batch well inside the TTL on the slowest backend (default 10000
	leaves a wide margin). Credits live on the exchange, not the token,
	so they're bought once up front.

# STOPPING CONDITIONS (whichever fires first)

  - target N pairs completed
  - per-test max-duration safety net (BASEPROOF_SCALE_DETERMINISM_MAX_DURATION)
  - first drift detected (BASEPROOF_SCALE_DETERMINISM_STOP_ON_DRIFT)
  - submit error budget exhausted / auth failure (fail-fast abort)

# HOW TO RUN

	Direct:
	  BASEPROOF_SCALE_DETERMINISM_N=10000 \
	  BASEPROOF_SCALE_DETERMINISM_CONCURRENCY=8 \
	  BASEPROOF_TEST_DSN=postgres://... \
	  go test -tags=scale -count=1 -timeout=20m \
	    -run TestScale_DeterministicReplay -v ./tests/

	Via wrapper script:
	  ./scripts/run-scale-determinism.sh

# DEFAULTS

	N            = 1000 pairs (= 2000 submissions) — fast smoke; ~80s
	CONCURRENCY  = 8 workers
	BATCH        = 10000 pairs per session re-seed
	MAX_DURATION = 15 minutes (safety net)
	STOP_ON_DRIFT = true (fail fast on contract violation)
*/
package tests

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
)

// ─────────────────────────────────────────────────────────────────
// Env tuning — file-local names; soak/scale tags don't overlap
// ─────────────────────────────────────────────────────────────────

func getScaleDeterminismN() int { return scaleDetEnvInt("BASEPROOF_SCALE_DETERMINISM_N", 1000) }

func getScaleDeterminismConcurrency() int {
	return scaleDetEnvInt("BASEPROOF_SCALE_DETERMINISM_CONCURRENCY", 8)
}

// getScaleDeterminismBatchSize is the number of pairs admitted per
// session batch. A fresh session token is seeded at each batch
// boundary, so this must be small enough that one batch completes
// comfortably inside the token TTL (testLedger.seedSession → 1h) on
// the slowest backend in use. Default 10000 leaves a wide margin.
func getScaleDeterminismBatchSize() int {
	return scaleDetEnvInt("BASEPROOF_SCALE_DETERMINISM_BATCH", 10000)
}

func getScaleDeterminismMaxDuration() time.Duration {
	v := os.Getenv("BASEPROOF_SCALE_DETERMINISM_MAX_DURATION")
	if v == "" {
		return 15 * time.Minute
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 15 * time.Minute
	}
	return d
}

func getScaleDeterminismStopOnDrift() bool {
	v := os.Getenv("BASEPROOF_SCALE_DETERMINISM_STOP_ON_DRIFT")
	// Default: true. Explicit "0" / "false" disables.
	if v == "0" || v == "false" {
		return false
	}
	return true
}

func scaleDetEnvInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// ─────────────────────────────────────────────────────────────────
// driftDetail — captured on first byte-identity violation
// ─────────────────────────────────────────────────────────────────

type driftDetail struct {
	workerID                             int
	iteration                            int64
	hashFirst, hashSecond                string
	timeFirst, timeSecond                any
	sigFirst, sigSecond                  string
	hashDrifted, timeDrifted, sigDrifted bool
}

func compareSCTPair(workerID int, iter int64, first, second map[string]any) *driftDetail {
	hF, _ := first["canonical_hash"].(string)
	hS, _ := second["canonical_hash"].(string)
	sF, _ := first["signature"].(string)
	sS, _ := second["signature"].(string)
	tF := first["log_time_micros"]
	tS := second["log_time_micros"]

	hashDrift := hF != hS
	timeDrift := tF != tS
	sigDrift := sF != sS

	if !hashDrift && !timeDrift && !sigDrift {
		return nil
	}
	return &driftDetail{
		workerID:    workerID,
		iteration:   iter,
		hashFirst:   hF,
		hashSecond:  hS,
		timeFirst:   tF,
		timeSecond:  tS,
		sigFirst:    sF,
		sigSecond:   sS,
		hashDrifted: hashDrift,
		timeDrifted: timeDrift,
		sigDrifted:  sigDrift,
	}
}

// ─────────────────────────────────────────────────────────────────
// TestScale_DeterministicReplay — continuous per-iteration loop,
// batched session re-seed
// ─────────────────────────────────────────────────────────────────

func TestScale_DeterministicReplay(t *testing.T) {
	target := int64(getScaleDeterminismN())
	concurrency := getScaleDeterminismConcurrency()
	maxDuration := getScaleDeterminismMaxDuration()
	stopOnDrift := getScaleDeterminismStopOnDrift()
	batchSize := int64(getScaleDeterminismBatchSize())
	if concurrency < 1 {
		concurrency = 1
	}
	if batchSize < 1 {
		batchSize = 1
	}

	// Bytestore backend: default in-memory; the determinism profile
	// sets BASEPROOF_SCALE_DETERMINISM_BYTESTORE=s3 to run the full
	// scale + end-to-end pipeline against SeaweedFS (the production
	// bytestore.S3 wire), closing the gap between this test and a
	// real deployment. The shipper migrates every WAL entry into the
	// configured backend during the run.
	bytestoreBackend := os.Getenv("BASEPROOF_SCALE_DETERMINISM_BYTESTORE")
	// WitnessFromEnv: discover the witness tier via LEDGER_WITNESS_*
	// (production-shape quorum when a fleet is wired; NON-WITNESS with a
	// warning otherwise). The determinism profile never spawns witnesses.
	op := startTestLedgerWithOpts(t, testLedgerOpts{
		BytestoreBackend: bytestoreBackend,
		WitnessFromEnv:   true,
	})

	// Session lifecycle is BATCHED. testLedger.seedSession stamps a
	// fixed TTL (now+1h); a multi-hour run on a single token expires
	// mid-flight, after which every submission 401s ("session
	// expired") and the retry path spins until the safety-net
	// deadline. We instead chunk the run into batches of batchSize
	// pairs and seed a FRESH token at each batch boundary, so the
	// token in use is always far younger than its TTL — run length is
	// decoupled from session lifetime by construction.
	//
	// Credits live on the exchange, not the token, so they're bought
	// once up front for the whole run; per-batch tokens carry 0
	// additional credits.
	exchangeDID := "did:example:det-scale-exchange"
	if _, err := op.CreditStore.BulkPurchase(context.Background(), exchangeDID, target*4+1000); err != nil {
		t.Fatalf("seed credits: %v", err)
	}

	backendLabel := bytestoreBackend
	if backendLabel == "" {
		backendLabel = "memory"
	}
	t.Logf("scale-determinism: target=%d concurrency=%d batch=%d max_duration=%s stop_on_drift=%v bytestore=%s",
		target, concurrency, batchSize, maxDuration, stopOnDrift, backendLabel)

	deadline := time.Now().Add(maxDuration)

	var (
		completed        atomic.Int64
		submitErrors     atomic.Int64
		driftCount       atomic.Int64
		firstDriftFound  atomic.Bool
		firstDriftDetail atomic.Pointer[driftDetail]
		abort            atomic.Bool // systemic failure → stop all workers + batches
	)

	// errorBudget bounds a systemic-failure spin. A healthy run has
	// zero submit errors (the verdict fails on any), so this only
	// caps how long we hammer a broken server before aborting,
	// instead of looping to the safety-net deadline.
	errorBudget := int64(concurrency) * 64
	if errorBudget < 256 {
		errorBudget = 256
	}

	// noteSubmitErr records a submission failure and trips the abort
	// flag on auth failure (never transient — a 401 on a freshly
	// seeded per-batch token means the batch outran the session TTL)
	// or once the error budget is spent.
	noteSubmitErr := func(workerID int, iter int64, phase string, err error) {
		n := submitErrors.Add(1)
		if n <= 5 {
			t.Logf("submit_error[%d] worker=%d iter=%d (%s): %v", n, workerID, iter, phase, err)
		}
		if strings.Contains(err.Error(), "got 401") {
			if abort.CompareAndSwap(false, true) {
				t.Logf("scale-determinism: ABORT — auth failure on a freshly-seeded "+
					"per-batch token (worker=%d iter=%d): %v. A batch outran the session "+
					"TTL; lower BASEPROOF_SCALE_DETERMINISM_BATCH.", workerID, iter, err)
			}
			return
		}
		if n >= errorBudget {
			if abort.CompareAndSwap(false, true) {
				t.Logf("scale-determinism: ABORT — submit error budget exhausted (%d errors); "+
					"systemic submission failure, stopping instead of spinning to the deadline.", n)
			}
		}
	}

	startTotal := time.Now()
	progressEvery := target / 10
	if progressEvery < 1 {
		progressEvery = 1
	}

	for batchIdx := 0; completed.Load() < target; batchIdx++ {
		if time.Now().After(deadline) || abort.Load() || (stopOnDrift && firstDriftFound.Load()) {
			break
		}

		// Pairs to admit this batch (clamp to the run remainder).
		batchTarget := batchSize
		if rem := target - completed.Load(); batchTarget > rem {
			batchTarget = rem
		}

		// FRESH per-batch session token — new now+1h TTL each time.
		token := fmt.Sprintf("tok-det-scale-b%d", batchIdx)
		op.seedSession(t, token, exchangeDID, 0)

		// batchRemaining is the per-batch reservation counter:
		// workers decrement to claim a slot (return when it goes
		// negative) and give the slot back on a transient failure so
		// the batch still lands batchTarget successful pairs.
		var batchRemaining atomic.Int64
		batchRemaining.Store(batchTarget)

		var wg sync.WaitGroup
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				var iter int64
				for {
					// Stopping conditions (cheap checks, in order of likelihood).
					if time.Now().After(deadline) || abort.Load() {
						return
					}
					if stopOnDrift && firstDriftFound.Load() {
						return
					}

					// Reserve a slot in this batch. Negative → batch full.
					if batchRemaining.Add(-1) < 0 {
						return
					}
					iter++

					// FRESH wire — EventTime stamped at this moment, not
					// at test setup. Eliminates Bug B (staleness) by
					// construction. batchIdx keeps the payload globally
					// unique across batches (iter resets per batch).
					wire := buildWireEntry(t, envelope.ControlHeader{
						SignerDID: "did:example:det-scale-signer",
					}, []byte(fmt.Sprintf("scale-det-b%d-w%d-iter%010d", batchIdx, workerID, iter)))

					// First submission — captures the persisted SCT.
					first, err := trySubmitEntry(op.BaseURL, token, wire)
					if err != nil {
						noteSubmitErr(workerID, iter, "first", err)
						// Give the slot back so the batch still reaches
						// batchTarget successes; abort/budget bounds any
						// systemic-failure spin.
						batchRemaining.Add(1)
						continue
					}

					// Replay submission — must hit the dedup path and
					// return byte-identical SCT.
					second, err := trySubmitEntry(op.BaseURL, token, wire)
					if err != nil {
						noteSubmitErr(workerID, iter, "replay", err)
						batchRemaining.Add(1)
						continue
					}

					completed.Add(1)

					// Per-iteration end-to-end verification — the load-
					// bearing assertion. No phase-3 batch; we verify
					// here, while the SCTs are still hot.
					if drift := compareSCTPair(workerID, iter, first, second); drift != nil {
						driftCount.Add(1)
						if firstDriftFound.CompareAndSwap(false, true) {
							firstDriftDetail.Store(drift)
						}
						if stopOnDrift {
							return
						}
					}

					// Progress log every 10% — bounded chatter.
					c := completed.Load()
					if progressEvery > 0 && c%progressEvery == 0 && c > 0 {
						rate := float64(c) / time.Since(startTotal).Seconds()
						t.Logf("  scale-determinism progress: pairs=%d/%d (%.1f pairs/sec) drifts=%d errors=%d",
							c, target, rate, driftCount.Load(), submitErrors.Load())
					}
				}
			}(w)
		}
		wg.Wait()

		t.Logf("  scale-determinism batch %d done: completed=%d/%d errors=%d drifts=%d (token=%s)",
			batchIdx, completed.Load(), target, submitErrors.Load(), driftCount.Load(), token)
	}

	totalElapsed := time.Since(startTotal)
	finalCompleted := completed.Load()
	if finalCompleted < 0 {
		finalCompleted = 0
	}
	rate := 0.0
	if totalElapsed.Seconds() > 0 {
		rate = float64(finalCompleted) / totalElapsed.Seconds()
	}

	t.Logf("scale-determinism: %d pairs end-to-end in %s (%.1f pairs/sec) "+
		"drifts=%d submit_errors=%d",
		finalCompleted, totalElapsed.Round(time.Millisecond), rate,
		driftCount.Load(), submitErrors.Load())

	// ─────────────────────────────────────────────────────────────
	// Verdict
	// ─────────────────────────────────────────────────────────────

	if driftCount.Load() > 0 {
		if d := firstDriftDetail.Load(); d != nil {
			t.Logf("FIRST_DRIFT_EXAMPLE worker=%d iter=%d", d.workerID, d.iteration)
			if d.hashDrifted {
				t.Logf("  canonical_hash drift: first=%s second=%s",
					safeHashPrefix(d.hashFirst), safeHashPrefix(d.hashSecond))
			}
			if d.timeDrifted {
				t.Logf("  log_time_micros drift: first=%v second=%v",
					d.timeFirst, d.timeSecond)
			}
			if d.sigDrifted {
				t.Logf("  signature drift: first=%s second=%s",
					safeHashPrefix(d.sigFirst), safeHashPrefix(d.sigSecond))
			}
		}
		t.Fatalf("scale-determinism: byte-identity violated — %d drifts in %d pairs. "+
			"Drift type → regression layer: "+
			"canonical_hash = wire-construction mutation; "+
			"log_time_micros = ledger persisted-replay regression; "+
			"signature = SDK RFC 6979 regression OR random state in the signed payload.",
			driftCount.Load(), finalCompleted)
	}

	if submitErrors.Load() > 0 {
		t.Fatalf("scale-determinism: %d submission errors (see submit_error[N] log lines above; "+
			"an ABORT line names the cause if the run stopped early)",
			submitErrors.Load())
	}

	if finalCompleted < target {
		t.Fatalf("scale-determinism: only %d/%d pairs completed before deadline (%s). "+
			"Increase BASEPROOF_SCALE_DETERMINISM_MAX_DURATION or reduce N.",
			finalCompleted, target, maxDuration)
	}

	t.Logf("scale-determinism PASS: %d pairs end-to-end, all byte-identical "+
		"(canonical_hash + log_time_micros + signature)", finalCompleted)
}

// safeHashPrefix returns the first 16 chars of a hex hash, or the
// whole string if shorter. Used in drift logging so the example
// line stays readable.
func safeHashPrefix(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
