package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/baseproof/tooling/libs/loadgen"
)

// RunLoad drives the loadgen engine against the bundle's network and, when
// --manifest is given, streams the expected-state oracle as JSON Lines. Memory
// stays O(workers·batch + window) regardless of -n (the cure for the backfill
// OOM), and the run is reproducible from --seed.
func RunLoad(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (network identity + transport) — REQUIRED")
		n          = fs.Int("n", 1000, "total entries to submit (roots + delegations + amendments)")
		amendRatio = fs.Float64("amend-ratio", 0.5, "fraction of entries that amend a recent root")
		delegRatio = fs.Float64("delegate-ratio", 0, "fraction of new entities given a delegation ⇒ their amendments use delegated authority; 0 = all same-signer, 1 = all delegated")
		workers    = fs.Int("workers", 0, "concurrent PoW/submit workers (0 = NumCPU)")
		batch      = fs.Int("batch-size", 1, "Mode A: entries per /v1/entries/batch (requires --token)")
		window     = fs.Int("amend-window", 0, "recent-root amend window K (0 = default 64Ki); bounds memory")
		seed       = fs.Int64("seed", 1, "run seed — same seed reproduces the exact stream + identities")
		token      = fs.String("token", "", "Mode A credit token; empty ⇒ Mode B PoW")
		difficulty = fs.Int("difficulty", 0, "Mode B PoW difficulty (0 ⇒ query the ledger)")
		manifest   = fs.String("manifest", "", "write the JSONL expected-state oracle to this path")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return fmt.Errorf("--bundle is required")
	}
	b, err := LoadClientBundle(*bundlePath)
	if err != nil {
		return err
	}
	logDID, err := b.RequireLogDID()
	if err != nil {
		return err
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	var sink loadgen.Sink = loadgen.DiscardSink{}
	var ow *loadgen.OracleWriter
	if *manifest != "" {
		f, ferr := os.Create(*manifest)
		if ferr != nil {
			return fmt.Errorf("create manifest %q: %w", *manifest, ferr)
		}
		ow, err = loadgen.NewOracleWriter(f, loadgen.OracleHeader{
			LogDID: logDID, Seed: *seed, N: *n, AmendRatio: *amendRatio,
		})
		if err != nil {
			_ = f.Close()
			return err
		}
		sink = ow
	}

	fmt.Printf("load: endpoint=%s log-did=%s n=%d amend-ratio=%.2f delegate-ratio=%.2f workers=%d batch=%d window=%d seed=%d\n",
		b.Endpoint, logDID, *n, *amendRatio, *delegRatio, *workers, *batch, *window, *seed)

	st, runErr := loadgen.Run(ctx, loadgen.Config{
		LedgerURL:      b.Endpoint,
		LogDID:         logDID,
		N:              *n,
		AmendRatio:     *amendRatio,
		DelegateRatio:  *delegRatio,
		Seed:           *seed,
		Token:          *token,
		Difficulty:     uint32(*difficulty),
		EpochWindowSec: b.Admission.EpochWindowSec,
		BatchSize:      *batch,
		Workers:        *workers,
		AmendWindow:    *window,
		HTTPClient:     hc,
		Progress: func(p loadgen.Progress) {
			fmt.Printf("load: %d/%d (%.1f%%) entities=%d delegations=%d amendments=%d(%d delegated) %.1f/s eta=%s\n",
				p.Submitted, p.N, p.Pct, p.Roots, p.Delegations, p.Amendments, p.DelegatedAmendments, p.Rate, p.ETA)
		},
	}, sink)

	if ow != nil {
		if cerr := ow.Close(); cerr != nil && runErr == nil {
			runErr = fmt.Errorf("close manifest: %w", cerr)
		}
	}
	if runErr != nil {
		return runErr
	}
	fmt.Printf("load: complete — %d entries (%d entities, %d delegations, %d amendments [%d delegated]) in %s\n",
		st.Submitted, st.Roots, st.Delegations, st.Amendments, st.DelegatedAmendments, st.Elapsed.Round(time.Second))
	if ow != nil {
		fmt.Printf("load: oracle = %s (%d leaves)\n", *manifest, ow.Count())
	}
	return nil
}
