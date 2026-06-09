/*
Package loadgen generates VALID, INTERCONNECTED ledger entries — the
authority-lane traffic the SMT indexes — and streams an expected-state oracle
for validation. It is the engine the unified client CLI's `load` command and the
e2e harness both drive; nothing here knows about a process boundary, so the e2e
runs it IN-PROCESS (no separate, memory-unbounded `/backfill` sidecar competing
with the federation for host RAM).

# WHY THIS IS A LIBRARY (and the OOM it cures)

The legacy cmd/backfill held two O(roots) structures that peaked at the end of a
run and made it the OOM-killer's victim at ~98%:

 1. every root's keypair, retained for the whole run so amendments could re-sign
    (the same-signer rule); and
 2. the ENTIRE oracle, accumulated in a []manifestLeaf and json.MarshalIndent'd
    in one shot at completion.

loadgen removes both, structurally:

  - keys are DERIVED on demand from (seed, rootIndex) — see deriveIdentity — so
    none are retained, and the run is byte-for-byte reproducible from the seed;
  - the oracle is STREAMED as JSON Lines, one record per root, emitted the moment
    a root can no longer change (see amendWindow) — no terminal marshal; and
  - amendments target a BOUNDED window of recent roots, so live model state is
    O(window), not O(roots).

Net: memory is O(workers·batch + window), independent of N. A 20M-entry run can
no longer OOM, whatever the container limit.
*/
package loadgen

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"runtime"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/types"
)

// Config parameterises a load run. HTTPClient and LogDID are required; the caller
// owns HTTPClient (its mTLS + retry posture). The rest take the defaults applied
// by normalize().
type Config struct {
	LedgerURL  string // ledger base URL (e.g. https://ledger:8443)
	LogDID     string // destination log DID (Header.Destination) — REQUIRED
	N          int    // total entries to submit (roots + amendments)
	AmendRatio float64
	EpochSize  int   // entries built+submitted+discovered per epoch
	Seed       int64 // run seed; same seed reproduces the run (incl. identities)

	// Admission: Token set ⇒ Mode A (credit, no PoW, may batch). Token empty ⇒
	// Mode B PoW at Difficulty (0 ⇒ queried from the ledger), EpochWindowSec.
	Token          string
	Difficulty     uint32
	EpochWindowSec uint64
	BatchSize      int // Mode A only; >1 groups N entries per /v1/entries/batch

	Workers     int           // concurrent PoW/submit workers (bounded in-flight)
	AmendWindow int           // K: recent-root ring capacity (bounds memory + finalises the oracle)
	SeqTimeout  time.Duration // per-entry sequence-discovery ceiling

	HTTPClient *http.Client    // REQUIRED; caller's outbound client (mTLS + retry)
	Progress   func(Progress)  // optional per-epoch progress callback (CLI prints; nil = quiet)
}

// Progress is one per-epoch sample for the optional callback.
type Progress struct {
	Submitted, N, Roots, Amendments int
	Pct, Rate                       float64
	ETA                             time.Duration
}

// Stats is the run summary.
type Stats struct {
	Submitted, Roots, Amendments int
	Elapsed                      time.Duration
}

func (c *Config) normalize() {
	if c.EpochSize <= 0 {
		c.EpochSize = 64
	}
	if c.Workers <= 0 {
		c.Workers = runtime.GOMAXPROCS(0)
	}
	if c.AmendWindow <= 0 {
		c.AmendWindow = 1 << 16 // 64Ki recent roots (~tens of MB), bounded
	}
	if c.SeqTimeout <= 0 {
		c.SeqTimeout = 120 * time.Second
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 1
	}
	if c.EpochWindowSec == 0 {
		c.EpochWindowSec = 3600
	}
}

func (c Config) validate() error {
	if c.HTTPClient == nil {
		return fmt.Errorf("loadgen: Config.HTTPClient is required")
	}
	if c.LogDID == "" {
		return fmt.Errorf("loadgen: Config.LogDID is required")
	}
	if c.N < 1 {
		return fmt.Errorf("loadgen: Config.N must be >= 1, got %d", c.N)
	}
	if c.BatchSize > 1 && c.Token == "" {
		return fmt.Errorf("loadgen: BatchSize>1 requires Token (Mode A); Mode B PoW does not batch")
	}
	if c.BatchSize > 256 {
		return fmt.Errorf("loadgen: BatchSize=%d exceeds server MaxBatchSize=256", c.BatchSize)
	}
	return nil
}

// Run generates cfg.N entries against the ledger, streaming each root's final
// expected state to sink (nil ⇒ DiscardSink). It blocks until done, ctx is
// cancelled, or an error occurs. Memory stays O(workers·batch + AmendWindow)
// regardless of N.
func Run(ctx context.Context, cfg Config, sink Sink) (Stats, error) {
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return Stats{}, err
	}
	if sink == nil {
		sink = DiscardSink{}
	}

	e := &engine{
		client: cfg.HTTPClient, ledgerURL: cfg.LedgerURL, logDID: cfg.LogDID,
		token: cfg.Token, difficulty: cfg.Difficulty, epochWindowSec: cfg.EpochWindowSec,
		seqTimeout: cfg.SeqTimeout, batchSize: cfg.BatchSize, workers: cfg.Workers,
	}
	if e.token == "" && e.difficulty == 0 {
		d, err := e.queryDifficulty(ctx)
		if err != nil {
			return Stats{}, fmt.Errorf("loadgen: query difficulty: %w", err)
		}
		e.difficulty = d
	}

	seed := seedBytes(cfg.Seed)
	rng := rand.New(rand.NewSource(cfg.Seed))
	win := newAmendWindow(cfg.AmendWindow)
	var nextRoot uint64
	submitted, amendments, roots := 0, 0, 0
	t0 := time.Now()

	emit := func(r *root) error {
		key := smt.DeriveKey(r.pos)
		return sink.Leaf(LeafRecord{
			RootIndex: r.index, Key: key, SignerDID: r.did,
			OriginTipSeq: r.originTipSeq, AuthorityTipSeq: r.authTipSeq,
		})
	}

	for submitted < cfg.N {
		if err := ctx.Err(); err != nil {
			return Stats{}, err
		}
		batch := cfg.EpochSize
		if rem := cfg.N - submitted; rem < batch {
			batch = rem
		}

		// BUILD sequentially so the seeded rng drives a reproducible stream
		// (amend-vs-root choice + which windowed root to amend). No PoW here.
		items := make([]workItem, 0, batch)
		for j := 0; j < batch; j++ {
			if win.len() > 0 && rng.Float64() < cfg.AmendRatio {
				target := win.pick(rng)
				id, err := deriveIdentity(seed, target.index)
				if err != nil {
					return Stats{}, err
				}
				entry, err := builder.BuildAmendment(builder.AmendmentParams{
					Destination: cfg.LogDID,
					SignerDID:   id.DID,
					TargetRoot:  target.pos,
					Payload:     []byte(fmt.Sprintf("amend-%d-of-%d", submitted+j, target.pos.Sequence)),
					EventTime:   time.Now().UTC().UnixMicro(),
				})
				if err != nil {
					return Stats{}, fmt.Errorf("loadgen: BuildAmendment: %w", err)
				}
				items = append(items, workItem{entry: entry, priv: id.Priv, did: id.DID, amend: target})
				amendments++
			} else {
				idx := nextRoot
				nextRoot++
				id, err := deriveIdentity(seed, idx)
				if err != nil {
					return Stats{}, err
				}
				entry, err := builder.BuildRootEntity(builder.RootEntityParams{
					Destination: cfg.LogDID,
					SignerDID:   id.DID,
					Payload:     []byte(fmt.Sprintf("root-%d", idx)),
					EventTime:   time.Now().UTC().UnixMicro(),
				})
				if err != nil {
					return Stats{}, fmt.Errorf("loadgen: BuildRootEntity: %w", err)
				}
				items = append(items, workItem{entry: entry, priv: id.Priv, did: id.DID, root: &root{index: idx, did: id.DID}})
			}
		}

		// STAMP + sign + POST across the worker pool.
		var hashes []string
		var err error
		if cfg.BatchSize <= 1 {
			hashes, err = submitConcurrent(ctx, e.workers, items, func(c context.Context, it workItem) (string, error) {
				return e.signAndSubmit(c, it.entry, it.priv, it.did)
			})
		} else {
			hashes, err = e.submitBatched(ctx, items)
		}
		if err != nil {
			return Stats{}, fmt.Errorf("loadgen: submit: %w", err)
		}

		// DISCOVER sequences (single-goroutine): advance amend tips on the
		// still-windowed target; collect this epoch's new roots.
		var newRoots []*root
		for i := range items {
			seq, err := e.waitForSequence(ctx, hashes[i])
			if err != nil {
				return Stats{}, fmt.Errorf("loadgen: sequence discovery: %w", err)
			}
			pos := types.LogPosition{LogDID: cfg.LogDID, Sequence: seq}
			switch {
			case items[i].root != nil:
				items[i].root.pos = pos
				items[i].root.originTipSeq = seq
				items[i].root.authTipSeq = seq
				newRoots = append(newRoots, items[i].root)
			case items[i].amend != nil:
				// Concurrent submission ⇒ arrival order need not match build order,
				// and a root may be amended twice in an epoch — take the MAX, the
				// state the ledger's in-order apply converges to.
				if seq > items[i].amend.originTipSeq {
					items[i].amend.originTipSeq = seq
				}
			}
		}

		// PUSH new roots oldest-target-stays-resident: only here can the window
		// evict, and an evicted root's state is final ⇒ stream it.
		for _, r := range newRoots {
			roots++
			if ev := win.push(r); ev != nil {
				if err := emit(ev); err != nil {
					return Stats{}, fmt.Errorf("loadgen: oracle emit: %w", err)
				}
			}
		}
		submitted += batch

		if cfg.Progress != nil {
			el := time.Since(t0).Seconds()
			rate := 0.0
			if el > 0 {
				rate = float64(submitted) / el
			}
			eta := time.Duration(0)
			if rate > 0 {
				eta = time.Duration(float64(cfg.N-submitted)/rate) * time.Second
			}
			cfg.Progress(Progress{
				Submitted: submitted, N: cfg.N, Roots: roots, Amendments: amendments,
				Pct: 100 * float64(submitted) / float64(cfg.N), Rate: rate, ETA: eta.Round(time.Second),
			})
		}
	}

	// FLUSH the records that never evicted (the final ≤K window).
	for _, r := range win.drain() {
		if err := emit(r); err != nil {
			return Stats{}, fmt.Errorf("loadgen: oracle flush: %w", err)
		}
	}
	return Stats{Submitted: submitted, Roots: roots, Amendments: amendments, Elapsed: time.Since(t0)}, nil
}
