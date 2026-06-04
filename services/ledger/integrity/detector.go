/*
FILE PATH: integrity/detector.go

Detector — the periodic agreement check between the ledger's
WAL and the embedded Tessera log. Read-only verifier; does not
mutate either side.

	Loop (periodic):
	  Sample N random sequences below HWM. For each, compare:
	    WAL.HashAt(seq)        ← what admission recorded
	    Tessera.HashAt(seq)    ← what the Merkle tree commits to
	  Mismatch → return ErrDiverged (composition root panics).
	  A read/parse failure (tile won't read, I/O blip, malformed
	  tile) is NOT a mismatch: it is traced, counted (VerifyErrors),
	  and skipped — never fatal. Only a proven divergence stops the
	  ledger, so an inability to verify can't be confused with a
	  verified disagreement.

	  The samples-per-cycle and tick interval are configurable.
	  Production defaults: 3 samples per minute. With a uniform
	  distribution over [1, HWM], divergence detection latency at
	  HWM=10B is roughly HWM / (samples_per_cycle * cycles_per_day).

BOOT RECOVERY:

	No longer this package's concern. The Sequencer drains
	StatePending entries on Run start (sequencer/sequencer.go),
	which subsumes the old Reasserter/Reconcile path with the
	added benefit of also INSERTing entry_index rows.

PANIC SEMANTICS:

	Detector itself never panics. It returns ErrDiverged. The
	composition root in cmd/ledger/main.go is responsible for
	panic-on-fatal — that's the infra-agnostic boundary.
*/
package integrity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/baseproof/tooling/services/ledger/tessera"
)

// walLeafHash maps the WAL's stored leaf DATA — the canonical entry hash the
// sequencer appended via tessera.AppendLeaf — to the RFC 6962 leaf HASH Tessera
// commits in its level-0 tiles. It routes through tessera.LeafHash, THE one
// canonical leaf-data↔leaf-hash converter, so this comparison can never drift
// from how Tessera actually hashes leaves. The WAL holds the data, Tessera's
// tile holds the leaf hash; comparing them without this conversion made every
// seq mismatch (data != HashLeaf(data)) and FALSE-positived the detector.
func walLeafHash(walData [32]byte) [32]byte {
	return tessera.LeafHash(walData[:])
}

// DetectorConfig configures NewDetector.
type DetectorConfig struct {
	// SampleInterval is the period between Loop sampling cycles.
	// Default 1 minute.
	SampleInterval time.Duration

	// SamplesPerCycle is the number of random sequences sampled
	// per cycle. Default 3. Set to 0 to disable periodic checks
	// (boot reconciliation still runs).
	SamplesPerCycle int

	// Rand is the source of randomness for sample selection.
	// Default: a per-process rng seeded with time.Now().UnixNano().
	// Tests inject deterministic sources.
	Rand *rand.Rand

	// Logger. Defaults to slog.Default if nil.
	Logger *slog.Logger
}

// Detector runs the periodic Loop against a WAL and a
// Tessera-backed Verifier. Read-only — never mutates either side.
type Detector struct {
	wal      WALReader
	verifier Verifier
	cfg      DetectorConfig
	logger   *slog.Logger

	rngMu sync.Mutex // guards rng — math/rand.Rand is not goroutine-safe

	// invariantFailures counts sample cycles that detected a PROVEN
	// divergence — WAL and Tessera committed different hashes for the
	// same seq (ErrDiverged). This is the only condition that aborts a
	// cycle and, via the composition root's fatal channel, terminates
	// the process: it is the audit invariant actually being violated.
	// Read-side errors that merely PREVENT a check (a tile that won't
	// read or parse) are counted under verifyErrors instead — fusing
	// the two is precisely what let a spurious tile-parse error take
	// down a healthy ledger. Maps to
	// `baseproof_audit_invariant_failures_total`.
	invariantFailures atomic.Uint64

	// verifyErrors counts samples where the verifier (or the WAL HWM
	// read) returned a NON-divergence error — a tile that won't
	// read/parse, an I/O blip, a malformed tile. These never abort the
	// cycle and never FATAL the ledger: an inability to read is not
	// proof of divergence, so the detector traces the error, counts it
	// here, and skips. A climbing verifyErrors rate is an operational
	// signal (investigate the tile store), categorically distinct from
	// invariantFailures (a genuine integrity alarm).
	verifyErrors atomic.Uint64

	// samplesVerified counts successful sample checks (WAL == Tessera).
	// Pairs with the failure/error/skip counters for rate math.
	samplesVerified atomic.Uint64

	// samplesSkipped counts samples that bailed out for an EXPECTED,
	// benign reason: the tile wasn't yet flushed at the requested
	// partial count (ErrTileNotYetFlushed) or the WAL had GC'd the
	// entry. Distinct from verifyErrors (unexpected read failures) so
	// SREs can tell "Tessera lag / GC tail" (normal) apart from "tile
	// store is unhealthy" (investigate).
	samplesSkipped atomic.Uint64
}

// NewDetector returns a Detector wired to the supplied surfaces.
// Both arguments are required; nil checks happen at first use
// for clear panic messages.
//
// The Verifier typically comes from a *TesseraAdapter
// (NewTesseraAdapter). The WAL is typically the ledger's
// *wal.Committer.
func NewDetector(
	wal WALReader,
	verifier Verifier,
	cfg DetectorConfig,
) *Detector {
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = 1 * time.Minute
	}
	if cfg.SamplesPerCycle == 0 {
		cfg.SamplesPerCycle = 3
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Detector{
		wal:      wal,
		verifier: verifier,
		cfg:      cfg,
		logger:   cfg.Logger,
	}
}

// SampleVerify runs ONE sampling cycle: pick SamplesPerCycle random
// sequences in [1, HWM] and check WAL.HashAt == Verifier.HashAt for
// each.
//
// The only non-context error it returns is ErrDiverged, on the first
// PROVEN WAL/Tessera mismatch. Everything that merely PREVENTS a check
// — a WAL miss (GC'd entry), a tile not yet flushed, an unreadable or
// malformed tile, or a WAL HWM read blip — is traced, counted, and
// skipped, so a transient or spurious read failure can never FATAL the
// ledger. Returns nil when HWM is 0 (no shipped entries to sample yet)
// or when a cycle completes without proving divergence.
func (d *Detector) SampleVerify(ctx context.Context) error {
	if d.wal == nil || d.verifier == nil {
		return errors.New("integrity/detector: SampleVerify requires wal + verifier")
	}
	hwm, err := d.wal.HWM(ctx)
	if err != nil {
		// A WAL HWM read failure means we can't choose a sample range
		// this cycle — an operational blip, not a divergence. Trace it,
		// count it, and let the next tick retry rather than FATAL-ing
		// the ledger over a transient read.
		d.verifyErrors.Add(1)
		d.logger.Warn("integrity/detector: cycle skipped (WAL HWM read failed)",
			"err", err)
		return nil
	}
	if hwm == 0 {
		return nil
	}

	for i := 0; i < d.cfg.SamplesPerCycle; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		seq := d.pickSeq(hwm)

		walHash, err := d.wal.HashAt(ctx, seq)
		if err != nil {
			// Sequence not in WAL — possible if the entry was
			// shipped + GC'd. Skip rather than treating as
			// divergence; the GC retention buffer is the
			// invariant that prevents this in production.
			d.samplesSkipped.Add(1)
			d.logger.Debug("integrity/detector: sample skipped (WAL miss)",
				"seq", seq, "err", err)
			continue
		}
		tesseraHash, err := d.verifier.HashAt(ctx, seq)
		if err != nil {
			// Tile not flushed at the requested partial count
			// (transient; Tessera flushes at batch_max_age or
			// batch_size boundaries). Skip rather than treating
			// as divergence — the integrator will catch up; the
			// next sample cycle will re-roll.
			if errors.Is(err, ErrTileNotYetFlushed) {
				d.samplesSkipped.Add(1)
				d.logger.Debug("integrity/detector: sample skipped (tile not flushed)",
					"seq", seq)
				continue
			}
			// Any other verifier error means we COULDN'T verify this
			// seq — a tile that won't read or parse, an I/O blip, a
			// malformed tile. That is not proof of divergence, so it
			// must not abort the cycle or FATAL the ledger. Trace it
			// with full tile coordinates, count it as a verify error,
			// and move on; only a proven hash mismatch (below) is
			// terminal.
			d.verifyErrors.Add(1)
			d.logger.Warn("integrity/detector: sample verify error (skipped, not divergence)",
				"seq", seq,
				"tile_index", seq/EntriesPerEntryTile,
				"offset", seq%EntriesPerEntryTile,
				"err", err)
			continue
		}
		// Compare like-for-like: Tessera's tile holds the RFC 6962 leaf HASH,
		// the WAL holds the leaf DATA, so normalize the WAL side through
		// HashLeaf. A mismatch here is a PROVEN divergence (Tessera committed a
		// different entry at this seq than the WAL recorded).
		walLeaf := walLeafHash(walHash)
		if walLeaf != tesseraHash {
			d.invariantFailures.Add(1)
			// Capture indisputable root-cause evidence BEFORE the composition
			// root panics: scan every seq, compare WAL vs Tessera, and classify
			// the divergence (ordering race vs drop/duplicate). This turns a
			// one-line panic into a forensic verdict in the captured logs.
			d.dumpForensic(ctx, hwm)
			return fmt.Errorf("%w: seq=%d wal_leaf=%x tessera=%x",
				ErrDiverged, seq, walLeaf[:], tesseraHash[:])
		}
		d.samplesVerified.Add(1)
		d.logger.Debug("integrity/detector: sample ok",
			"seq", seq,
			"hash", fmt.Sprintf("%x", walHash[:8]),
		)
	}
	return nil
}

// forensicScanCap bounds the full-scan on divergence so a 10B-leaf tree
// produces evidence in seconds rather than hours. The first ~100k seqs are
// where ordering/sequencing races manifest; that's the diagnostic window.
const forensicScanCap = 100000

// dumpForensic is the indisputable-evidence path. On a proven WAL/Tessera
// divergence it scans every seq in [0, hwm] (bounded), compares the two
// subsystems, and classifies the failure mode so the root cause is in the
// captured logs — not inferred:
//
//   - PERMUTATION: the WAL and Tessera hold the SAME set of entry hashes but at
//     DIFFERENT seqs → a sequencing/commit ORDERING race (the smoking gun for
//     concurrent AppendLeaf workers committing out of seq order). For each
//     mismatched seq it reports WHERE that entry actually lives on the other
//     side — e.g. "Tessera[2] == WAL[3]" proves a swap, not corruption.
//   - DISJOINT: a hash present on one side is absent on the other → a dropped or
//     duplicated entry (admission/idempotency bug), not mere reordering.
//   - MIXED: both kinds present.
//
// Read-only; runs once, immediately before the composition root panics.
func (d *Detector) dumpForensic(ctx context.Context, hwm uint64) {
	n := hwm
	if n > forensicScanCap {
		n = forensicScanCap
	}
	walAt := make(map[uint64][32]byte)
	tessAt := make(map[uint64][32]byte)
	walHashSeq := make(map[[32]byte]uint64)
	tessHashSeq := make(map[[32]byte]uint64)
	walReadErr, tessReadErr := 0, 0
	for seq := uint64(0); seq <= n; seq++ {
		if err := ctx.Err(); err != nil {
			break
		}
		if h, err := d.wal.HashAt(ctx, seq); err == nil {
			lh := walLeafHash(h) // normalize WAL leaf-data → RFC 6962 leaf hash
			walAt[seq] = lh
			walHashSeq[lh] = seq
		} else {
			walReadErr++
		}
		if h, err := d.verifier.HashAt(ctx, seq); err == nil {
			tessAt[seq] = h
			tessHashSeq[h] = seq
		} else {
			tessReadErr++
		}
	}

	mismatches, permutationLike, disjointLike := 0, 0, 0
	firstMismatch := int64(-1)
	for seq := uint64(0); seq <= n; seq++ {
		w, wok := walAt[seq]
		t, tok := tessAt[seq]
		if !wok || !tok || w == t {
			continue
		}
		mismatches++
		if firstMismatch < 0 {
			firstMismatch = int64(seq)
		}
		tessSeqOfWalEntry, walEntryInTess := tessHashSeq[w]
		walSeqOfTessEntry, tessEntryInWal := walHashSeq[t]
		if walEntryInTess && tessEntryInWal {
			permutationLike++
		} else {
			disjointLike++
		}
		if mismatches <= 12 {
			d.logger.Error("integrity/forensic: seq divergence",
				"seq", seq,
				"wal_hash", fmt.Sprintf("%x", w[:]),
				"tessera_hash", fmt.Sprintf("%x", t[:]),
				"wal_entry_also_in_tessera_at_seq", seqOrNeg(tessSeqOfWalEntry, walEntryInTess),
				"tessera_entry_also_in_wal_at_seq", seqOrNeg(walSeqOfTessEntry, tessEntryInWal))
		}
	}

	var pattern string
	switch {
	case mismatches == 0:
		pattern = "NONE (mismatch not reproduced in full scan — likely a transient read window)"
	case disjointLike == 0:
		pattern = "PERMUTATION — same entries, swapped seqs ⇒ SEQUENCER/COMMIT ORDERING RACE"
	case permutationLike == 0:
		pattern = "DISJOINT — entries present on only one side ⇒ DROP/DUPLICATE (admission/idempotency)"
	default:
		pattern = "MIXED — both reordering and drop/duplicate present"
	}
	d.logger.Error("integrity/forensic: VERDICT",
		"scanned_seqs", n+1,
		"mismatches", mismatches,
		"first_mismatch_seq", firstMismatch,
		"permutation_like", permutationLike,
		"disjoint_like", disjointLike,
		"wal_distinct_hashes", len(walHashSeq),
		"tessera_distinct_hashes", len(tessHashSeq),
		"wal_read_errors", walReadErr,
		"tessera_read_errors", tessReadErr,
		"pattern", pattern)
}

// seqOrNeg renders a seq for logging, or -1 when the entry is absent on the
// other side (the DISJOINT signal).
func seqOrNeg(seq uint64, present bool) int64 {
	if !present {
		return -1
	}
	return int64(seq)
}

// InvariantFailures returns the cumulative count of sample cycles
// that detected a PROVEN divergence (WAL and Tessera committed
// different hashes for the same seq). This is the genuine integrity
// alarm and the only condition that FATALs the ledger; read-side
// errors that merely prevented a check are counted by VerifyErrors,
// not here. Maps to `baseproof_audit_invariant_failures_total`.
// Read-only; safe under any concurrency.
func (d *Detector) InvariantFailures() uint64 {
	return d.invariantFailures.Load()
}

// VerifyErrors returns the cumulative count of samples where the
// verifier (or the WAL HWM read) returned a non-divergence error —
// a tile that wouldn't read or parse, an I/O blip, a malformed tile.
// These are traced and skipped, never fatal. A climbing rate is an
// operational signal to investigate the tile store, distinct from
// InvariantFailures (a genuine integrity alarm). Read-only; safe
// under any concurrency.
func (d *Detector) VerifyErrors() uint64 {
	return d.verifyErrors.Load()
}

// SamplesVerified returns the cumulative count of sample checks
// that completed successfully (no divergence, no error). Pairs
// with InvariantFailures to compute a failure rate.
func (d *Detector) SamplesVerified() uint64 {
	return d.samplesVerified.Load()
}

// SamplesSkipped returns the cumulative count of sample checks
// that bailed out before reaching the divergence comparison —
// WAL miss (GC'd entry) OR tile-not-yet-flushed. Pairs with
// SamplesVerified + InvariantFailures to give SREs three
// orthogonal counters: skip rate (Tessera lag / GC tail),
// failure rate (divergence), verify rate (healthy).
func (d *Detector) SamplesSkipped() uint64 {
	return d.samplesSkipped.Load()
}

// Loop runs SampleVerify on a ticker until ctx is cancelled or the
// detector proves a divergence. The composition root reads the
// returned error from a fatal channel and panics on it.
//
// Returns ctx.Err() on graceful shutdown, or ErrDiverged on a proven
// WAL/Tessera disagreement. Non-divergence verifier/WAL read errors
// are NOT returned — SampleVerify traces and counts them (VerifyErrors)
// and the loop keeps running, so a spurious or transient read failure
// can never FATAL a healthy ledger.
func (d *Detector) Loop(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.SampleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := d.SampleVerify(ctx); err != nil {
				if errors.Is(err, ErrDiverged) {
					d.logger.Error("integrity/detector: divergence detected",
						"err", err)
				}
				return err
			}
		}
	}
}

// pickSeq returns a uniformly-random seq in [1, hwm].
func (d *Detector) pickSeq(hwm uint64) uint64 {
	d.rngMu.Lock()
	defer d.rngMu.Unlock()
	// Int63n with hwm > 0; +1 so we land in [1, hwm].
	// hwm can be larger than int63 only at scale we don't reach here
	// (10B << 2^63), but clamp defensively.
	if hwm > 1<<62 {
		hwm = 1 << 62
	}
	return uint64(d.cfg.Rand.Int63n(int64(hwm))) + 1
}
