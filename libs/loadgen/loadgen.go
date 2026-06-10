/*
Package loadgen generates VALID, INTERCONNECTED ledger entries — the
authority-lane traffic the SMT indexes — and streams an expected-state oracle
for validation. It is the engine the unified client CLI's `load` command and the
e2e harness both drive; nothing here knows about a process boundary, so the e2e
runs it IN-PROCESS (no separate, memory-unbounded `/backfill` sidecar competing
with the federation for host RAM).

# AUTHORITY COVERAGE

Amendments are authorized two ways, so the load covers both ways the ledger
resolves an update's authority:

  - same-signer: the entity's OWNER key amends its own leaf
    (builder.BuildAmendment).
  - delegated authority: a DELEGATE key — distinct from the owner — amends the
    entity, citing a live delegation the owner minted for it
    (builder.BuildDelegation, then builder.BuildPathBEntry). DelegateRatio opts a
    fraction of entities into this.

Both produce the same expected leaf state (an advanced OriginTip); only the
authorization differs. This is a load-coverage detail — the client surface
reports it only as a "delegated" count, never as a protocol-path label.

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
  - the oracle is STREAMED as JSON Lines, one record per leaf, emitted the moment
    it can no longer change (see amendWindow) — no terminal marshal; and
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
	LedgerURL string // ledger base URL (e.g. https://ledger:8443)
	LogDID    string // destination log DID (Header.Destination) — REQUIRED
	N         int    // total entries to submit (roots + delegations + amendments)

	AmendRatio float64 // fraction of entries that amend an existing entity
	// DelegateRatio is the fraction of NEW ENTITIES also given a delegation, so
	// their amendments are authorized by a delegate (delegated authority) instead
	// of the entity's own key. 0 ⇒ all amendments same-signer; a value in (0,1)
	// exercises both authorization styles in one run.
	DelegateRatio float64

	EpochSize int   // entries built+submitted+discovered per epoch
	Seed      int64 // run seed; same seed reproduces the run (incl. identities)

	// Admission: Token set ⇒ Mode A (credit, no PoW, may batch). Token empty ⇒
	// Mode B PoW at Difficulty (0 ⇒ queried from the ledger), EpochWindowSec.
	Token          string
	Difficulty     uint32
	EpochWindowSec uint64
	BatchSize      int // Mode A only; >1 groups N entries per /v1/entries/batch

	Workers     int           // concurrent PoW/submit workers (bounded in-flight)
	AmendWindow int           // K: recent-root ring capacity (bounds memory + finalises the oracle)
	SeqTimeout  time.Duration // per-entry sequence-discovery ceiling

	HTTPClient *http.Client   // REQUIRED; caller's outbound client (mTLS + retry)
	Progress   func(Progress) // optional per-epoch progress callback (CLI prints; nil = quiet)
}

// Progress is one per-epoch sample for the optional callback.
type Progress struct {
	Submitted, N, Roots, Delegations, Amendments, DelegatedAmendments int
	Pct, Rate                                                         float64
	ETA                                                               time.Duration
}

// Stats is the run summary. Submitted == Roots + Delegations + Amendments; the
// SMT-leaf count is Roots + Delegations (amendments mutate existing leaves, they
// do not create new ones). DelegatedAmendments is the subset of Amendments
// authorized by a delegate rather than the entity's own key.
type Stats struct {
	Submitted, Roots, Delegations, Amendments, DelegatedAmendments int
	Elapsed                                                        time.Duration
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

// Run generates cfg.N entries against the ledger, streaming each leaf's final
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
	var st Stats
	t0 := time.Now()

	emit := func(r *root) error {
		return sink.Leaf(LeafRecord{
			RootIndex: r.index, Key: smt.DeriveKey(r.pos), SignerDID: r.did,
			OriginTipSeq: r.originTipSeq, AuthorityTipSeq: r.authTipSeq,
		})
	}

	for st.Submitted < cfg.N {
		if err := ctx.Err(); err != nil {
			return st, err
		}

		// BUILD sequentially (the seeded rng drives a reproducible stream). Append
		// entries until the epoch is full or N is reached. A DELEGATED root appends
		// TWO entries — the root and its delegation — so we build by appending,
		// bounded by the remaining N.
		items := make([]workItem, 0, cfg.EpochSize+1)
		for len(items) < cfg.EpochSize {
			remaining := cfg.N - st.Submitted - len(items)
			if remaining <= 0 {
				break
			}

			if win.len() > 0 && rng.Float64() < cfg.AmendRatio {
				target := win.pick(rng)
				st.Amendments++
				if target.delegated {
					// Delegated authority — a DELEGATE signs, citing the live delegation.
					del, err := deriveDelegateIdentity(seed, target.delegateIndex)
					if err != nil {
						return st, err
					}
					entry, err := builder.BuildPathBEntry(builder.PathBParams{
						Destination:        cfg.LogDID,
						SignerDID:          del.DID,
						TargetRoot:         target.pos,
						DelegationPointers: []types.LogPosition{target.delegationPos},
						Payload:            []byte(fmt.Sprintf("deleg-amend-%d-of-%d", st.Submitted+len(items), target.pos.Sequence)),
						EventTime:          time.Now().UTC().UnixMicro(),
					})
					if err != nil {
						return st, fmt.Errorf("loadgen: build delegated amendment: %w", err)
					}
					items = append(items, workItem{entry: entry, priv: del.Priv, did: del.DID, amend: target})
					st.DelegatedAmendments++
				} else {
					// Same-signer — the entity's OWNER key signs.
					owner, err := deriveIdentity(seed, target.index)
					if err != nil {
						return st, err
					}
					entry, err := builder.BuildAmendment(builder.AmendmentParams{
						Destination: cfg.LogDID,
						SignerDID:   owner.DID,
						TargetRoot:  target.pos,
						Payload:     []byte(fmt.Sprintf("amend-%d-of-%d", st.Submitted+len(items), target.pos.Sequence)),
						EventTime:   time.Now().UTC().UnixMicro(),
					})
					if err != nil {
						return st, fmt.Errorf("loadgen: build amendment: %w", err)
					}
					items = append(items, workItem{entry: entry, priv: owner.Priv, did: owner.DID, amend: target})
				}
				continue
			}

			// New root entity → a fresh SMT leaf.
			idx := nextRoot
			nextRoot++
			owner, err := deriveIdentity(seed, idx)
			if err != nil {
				return st, err
			}
			entry, err := builder.BuildRootEntity(builder.RootEntityParams{
				Destination: cfg.LogDID,
				SignerDID:   owner.DID,
				Payload:     []byte(fmt.Sprintf("root-%d", idx)),
				EventTime:   time.Now().UTC().UnixMicro(),
			})
			if err != nil {
				return st, fmt.Errorf("loadgen: BuildRootEntity: %w", err)
			}
			r := &root{index: idx, did: owner.DID}
			items = append(items, workItem{entry: entry, priv: owner.Priv, did: owner.DID, root: r})
			st.Roots++

			// Optionally mint a delegation in the SAME epoch (needs room for two), so
			// this entity becomes delegation-capable once both are discovered. The
			// delegation is owner-signed and standalone (no TargetRoot), so it has no
			// build-time dependency on the root's position.
			if remaining >= 2 && rng.Float64() < cfg.DelegateRatio {
				del, err := deriveDelegateIdentity(seed, idx)
				if err != nil {
					return st, err
				}
				dentry, err := builder.BuildDelegation(builder.DelegationParams{
					Destination: cfg.LogDID,
					SignerDID:   owner.DID,
					DelegateDID: del.DID,
					Payload:     []byte(fmt.Sprintf("deleg-%d", idx)),
					EventTime:   time.Now().UTC().UnixMicro(),
				})
				if err != nil {
					return st, fmt.Errorf("loadgen: BuildDelegation: %w", err)
				}
				r.delegated = true
				r.delegateIndex = idx
				items = append(items, workItem{entry: dentry, priv: owner.Priv, did: owner.DID, delegFor: r})
				st.Delegations++
			}
		}
		if len(items) == 0 {
			break
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
			return st, fmt.Errorf("loadgen: submit: %w", err)
		}

		// DISCOVER sequences (single-goroutine): advance amend tips on the still-
		// windowed target, link discovered delegations, collect new roots.
		var newRoots []*root
		for i := range items {
			seq, err := e.waitForSequence(ctx, hashes[i])
			if err != nil {
				return st, fmt.Errorf("loadgen: sequence discovery: %w", err)
			}
			pos := types.LogPosition{LogDID: cfg.LogDID, Sequence: seq}
			switch {
			case items[i].root != nil:
				items[i].root.pos = pos
				items[i].root.originTipSeq = seq
				items[i].root.authTipSeq = seq
				newRoots = append(newRoots, items[i].root)
			case items[i].delegFor != nil:
				// The delegation is its OWN leaf with final state (we never revoke it,
				// so its OriginTip stays == creation). Record it, and link it to the
				// root it enables so delegated amendments can cite delegationPos.
				items[i].delegFor.delegationPos = pos
				if err := sink.Leaf(LeafRecord{
					RootIndex: items[i].delegFor.index, Key: smt.DeriveKey(pos),
					SignerDID: items[i].did, OriginTipSeq: seq, AuthorityTipSeq: seq,
				}); err != nil {
					return st, fmt.Errorf("loadgen: oracle emit (delegation): %w", err)
				}
			case items[i].amend != nil:
				// Same-signer and delegated amendments both advance the target's
				// OriginTip; concurrent arrival ⇒ take the MAX (the state the in-order
				// apply converges to).
				if seq > items[i].amend.originTipSeq {
					items[i].amend.originTipSeq = seq
				}
			}
		}

		// PUSH new roots; an evicted root's state is final ⇒ stream it.
		for _, r := range newRoots {
			if ev := win.push(r); ev != nil {
				if err := emit(ev); err != nil {
					return st, fmt.Errorf("loadgen: oracle emit: %w", err)
				}
			}
		}
		st.Submitted += len(items)

		if cfg.Progress != nil {
			el := time.Since(t0).Seconds()
			rate := 0.0
			if el > 0 {
				rate = float64(st.Submitted) / el
			}
			eta := time.Duration(0)
			if rate > 0 {
				eta = time.Duration(float64(cfg.N-st.Submitted)/rate) * time.Second
			}
			cfg.Progress(Progress{
				Submitted: st.Submitted, N: cfg.N, Roots: st.Roots, Delegations: st.Delegations,
				Amendments: st.Amendments, DelegatedAmendments: st.DelegatedAmendments,
				Pct: 100 * float64(st.Submitted) / float64(cfg.N), Rate: rate, ETA: eta.Round(time.Second),
			})
		}
	}

	// FLUSH the records that never evicted (the final ≤K window).
	for _, r := range win.drain() {
		if err := emit(r); err != nil {
			return st, fmt.Errorf("loadgen: oracle flush: %w", err)
		}
	}
	st.Elapsed = time.Since(t0)
	return st, nil
}
