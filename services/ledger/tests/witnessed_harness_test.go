// FILE PATH: tests/witnessed_harness_test.go
//
// Test harness that bundles a real tessera.EmbeddedAppender +
// real witness fixture + real witnessclient.HeadSync into a
// single value. Used by ad-hoc tests that build their own
// builder loop without going through startTestLedgerWithOpts —
// scale_test.go, soak_test.go, e2e_graceful_shutdown_test.go,
// e2e_shipper_redirect_test.go.
//
// PHYSICS, NOT MOCKS:
//
//   - Real Tessera EmbeddedAppender writes tile bytes to a
//     fresh t.TempDir() POSIX directory. The cosigned-checkpoint
//     file the BuilderLoop publishes after K-of-N collection
//     lands at <tempdir>/cosigned-checkpoint and remains
//     available for assertion at end-of-test.
//
//   - Real witnessFixture (httptest cosign servers backed by
//     SDK's NewWitnessHandler) processes every cosign POST.
//     The Ledger's HeadSync hits the fixture URLs over real
//     HTTP and persists signatures in the supplied TreeHeadStore.
//
// USAGE:
//
//	h := newWitnessedTestHarness(t, ctx, pool, logger)
//	bl := opbuilder.NewBuilderLoop(loopCfg, pool, tree, leafStore,
//	    nodeCache, reader, fetcher, schema, deltaBuffer, bufferStore,
//	    commitPub, h.Adapter, h.Cosigner, logger)
//	// ... drive the test, assert on h.CosignedCheckpointPath()
package tests

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	uptessera "github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	tposixantispam "github.com/transparency-dev/tessera/storage/posix/antispam"

	"github.com/baseproof/baseproof/crypto/cosign"

	opstore "github.com/baseproof/tooling/services/ledger/store"
	optessera "github.com/baseproof/tooling/services/ledger/tessera"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// witnessedTestHarness packages every piece an ad-hoc test
// needs to wire a production-shape BuilderLoop:
//
//   - Adapter        : *tessera.TesseraAdapter (MerkleAppender)
//   - Embedded       : *tessera.EmbeddedAppender (held for Close)
//   - Cosigner       : *witnessclient.HeadSync (WitnessCosigner)
//   - Fixture        : the underlying httptest witness fixture
//   - TileRoot       : the tempdir Tessera writes to
//
// CleanUp is registered with t.Cleanup; callers do not Close
// anything manually.
type witnessedTestHarness struct {
	Adapter   *optessera.TesseraAdapter
	Embedded  *optessera.EmbeddedAppender
	Cosigner  *witnessclient.HeadSync
	Fixture   *witnessFixture
	NetworkID cosign.NetworkID
	TileRoot  string
}

// CosignedCheckpointPath returns the absolute path the
// EmbeddedAppender writes the cosigned-checkpoint file to. After
// the BuilderLoop's first successful K-of-N collection, the file
// at this path contains a JSON-encoded types.CosignedTreeHead.
// Tests assert on the file's existence as the load-bearing
// proof that the entire pipeline (HTTP cosign → atomic commit →
// CDN write) succeeded end-to-end.
func (h *witnessedTestHarness) CosignedCheckpointPath() string {
	return filepath.Join(h.TileRoot, "cosigned-checkpoint")
}

// tesseraHarness packages the Tessera half of the production-shape
// pipeline — a real EmbeddedAppender + TesseraAdapter over a fresh
// t.TempDir() POSIX tile tree — WITHOUT any witness fixture. The
// at-scale validation profiles (soak, determinism) compose this with
// an env-DISCOVERED witness cosigner (cosignerFromEnv) instead of an
// in-process fixture, so they never orchestrate a witness tier.
type tesseraHarness struct {
	Adapter   *optessera.TesseraAdapter
	Embedded  *optessera.EmbeddedAppender
	NetworkID cosign.NetworkID
	TileRoot  string
}

// CosignedCheckpointPath returns the path the EmbeddedAppender writes
// the cosigned-checkpoint file to once the BuilderLoop completes a
// K-of-N collection.
func (h *tesseraHarness) CosignedCheckpointPath() string {
	return filepath.Join(h.TileRoot, "cosigned-checkpoint")
}

// newTesseraHarness builds the Tessera EmbeddedAppender + adapter only
// (no witnesses). Storage is a fresh t.TempDir(); embedded.Close is
// registered with t.Cleanup. CheckpointInterval / BatchSize /
// BatchMaxAge are scaled down for fast tests.
func newTesseraHarness(
	t *testing.T,
	ctx context.Context,
	logger *slog.Logger,
) *tesseraHarness {
	t.Helper()

	netID := nonZeroTestNetworkID()
	tileRoot := t.TempDir()

	// Real Tessera embedded appender, mirroring production wiring.
	signer, _, err := optessera.GenerateEphemeralSigner("test-witnessed-harness")
	if err != nil {
		t.Fatalf("tessera harness: GenerateEphemeralSigner: %v", err)
	}
	driver, err := posix.New(ctx, posix.Config{Path: tileRoot})
	if err != nil {
		t.Fatalf("tessera harness: posix.New: %v", err)
	}
	_ = uptessera.Driver(driver)

	publicCheckpointPath := filepath.Join(tileRoot, "cosigned-checkpoint")

	// ANTISPAM (dedup) — load-bearing for the sequencer + builder
	// architecture. Both the sequencer (sequencer/loop.go:238) AND
	// the builder loop (builder/loop.go:402) call merkle.AppendLeaf
	// for the same content hash. With antispam OFF, Tessera assigns
	// each call a DISTINCT seq, the WAL's seqIndex is sparse (only
	// sequencer-side seqs), and the shipper's hwmAdvancer's
	// contiguous-run invariant stalls at the first gap.
	//
	// Antispam path is a tmpdir directory; AntispamOpts{} keeps the
	// upstream defaults (cache size, retention).
	antispamPath := filepath.Join(tileRoot, "antispam")
	antispam, err := tposixantispam.NewAntispam(ctx, antispamPath, tposixantispam.AntispamOpts{})
	if err != nil {
		t.Fatalf("tessera harness: tposixantispam.NewAntispam(%s): %v", antispamPath, err)
	}

	// CTX LIFETIME: Tessera's background goroutines listen to ctx
	// for termination. The t.Cleanup below calls embedded.Close
	// BEFORE the test ctx fires (the close uses a fresh shutdownCtx
	// with its own timeout), so Shutdown can poll the checkpoint
	// while the integration loop is still alive. Do NOT wrap with
	// context.WithoutCancel — that leaks the integration goroutine
	// forever (Close doesn't stop it; only ctx cancellation does).
	embedded, err := optessera.NewEmbeddedAppender(ctx, driver, optessera.AppenderOptions{
		Origin:               testLogDID,
		Signer:               signer,
		CheckpointInterval:   100 * time.Millisecond,
		BatchSize:            4,
		BatchMaxAge:          50 * time.Millisecond,
		PublicCheckpointPath: publicCheckpointPath,
		Antispam:             antispam,
	}, logger)
	if err != nil {
		t.Fatalf("tessera harness: NewEmbeddedAppender: %v", err)
	}

	backend, err := optessera.NewPOSIXTileBackend(tileRoot)
	if err != nil {
		_ = embedded.Close(ctx)
		t.Fatalf("tessera harness: NewPOSIXTileBackend: %v", err)
	}
	tileReader := optessera.NewTileReader(backend, 256)
	adapter := optessera.NewTesseraAdapter(ctx, embedded, tileReader, logger)

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = embedded.Close(shutdownCtx)
	})

	return &tesseraHarness{
		Adapter:   adapter,
		Embedded:  embedded,
		NetworkID: netID,
		TileRoot:  tileRoot,
	}
}

// newWitnessedTestHarness builds the K=1 default harness. Use
// newWitnessedTestHarnessN for K>1.
func newWitnessedTestHarness(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logger *slog.Logger,
) *witnessedTestHarness {
	return newWitnessedTestHarnessN(t, ctx, pool, logger, 1, 1)
}

// newWitnessedTestHarnessN builds an N-witness, K-quorum harness with
// an IN-PROCESS witness fixture (httptest cosign servers). This is for
// hermetic integration / scale tests; the at-scale validation profiles
// (soak, determinism) instead DISCOVER an external fleet via
// cosignerFromEnv and use newTesseraHarness directly.
func newWitnessedTestHarnessN(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	witnessCount int,
	quorumK int,
) *witnessedTestHarness {
	t.Helper()

	th := newTesseraHarness(t, ctx, logger)

	// Real witness fixture — N httptest cosign servers.
	fixture := newWitnessFixture(t, th.NetworkID, witnessCount)

	// Real cosign client — Ledger HeadSync against the fixture's
	// URLs. Persists head + sigs to the supplied TreeHeadStore.
	treeHeadStore := opstore.NewTreeHeadStore(pool)
	cosigner, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		EndpointResolver:       staticEndpointResolver{urls: fixture.URLs()},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                quorumK,
		PerWitnessTimeout:      2 * time.Second,
		NetworkID:              th.NetworkID,
		HTTPClient:             newTunedHTTPClient(2 * time.Second),
	}, treeHeadStore, logger)
	if err != nil {
		t.Fatalf("witnessed harness: NewHeadSync: %v", err)
	}

	return &witnessedTestHarness{
		Adapter:   th.Adapter,
		Embedded:  th.Embedded,
		Cosigner:  cosigner,
		Fixture:   fixture,
		NetworkID: th.NetworkID,
		TileRoot:  th.TileRoot,
	}
}
