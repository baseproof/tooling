/*
FILE PATH:

	tests/testserver_setup_test.go

DESCRIPTION:

	Opts-driven entry point for the integration-test ledger harness.
	startTestLedger delegates here with a zero-value opts (legacy
	stub default); scenarios / persona tests pass UseRealTessera=true
	to wire production-shape Tessera (POSIX + EmbeddedAppender +
	TesseraAdapter) instead.

KEY ARCHITECTURAL DECISIONS:
  - Sibling, not flag mutation. Existing 600+ tests reach this
    function via the unchanged startTestLedger delegator; their
    stub path is byte-for-byte equivalent.
  - Single decision point. buildTesseraForTests returns a
    tesseraSlots struct filling all four production roles
    (admission TesseraAppender, builder MerkleAppender,
    InclusionProver, ConsistencyProver). Every slot uses the
    same source of truth.
  - Lifecycle ordering. Real Tessera owns background batchers +
    a checkpoint signer; cleanup drains them before pool.Close.

OVERVIEW:

	startTestLedgerWithOpts → pool → tessera slots → builder loop
	→ handlers → http.Server on random port → testLedger.
	buildTesseraForTests → (admission, builder, incl, consist,
	embedded?, tileReader?, tileRoot, closer).

KEY DEPENDENCIES:
  - testserver_test.go: testLedger + stubs + testServer.
  - ledger/tessera: NewEmbeddedAppender, NewPOSIXTileBackend,
    NewTileReader, NewTesseraAdapter, GenerateEphemeralSigner.
  - transparency-dev/tessera/storage/posix: driver.
*/
package tests

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkbuilder "github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/signatures"

	"github.com/baseproof/tooling/services/ledger/admission"
	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/api/middleware"
	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	opbytestore "github.com/baseproof/tooling/services/ledger/bytestore"
	"github.com/baseproof/tooling/services/ledger/sequencer"
	"github.com/baseproof/tooling/services/ledger/shipper"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/store/indexes"
	"github.com/baseproof/tooling/services/ledger/wal"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// -------------------------------------------------------------------------------------------------
// 1) Opts struct
// -------------------------------------------------------------------------------------------------

// testLedgerOpts carries the knobs scenarios / persona tests use
// to drive the harness toward production-shape wiring. The zero
// value reproduces the legacy stub-Merkle behaviour every existing
// test depends on; only fields the caller sets non-zero override.
type testLedgerOpts struct {
	// UseRealTessera replaces the in-process stubMerkleAppender
	// with a real tessera.EmbeddedAppender + tessera.TesseraAdapter
	// pair, matching cmd/ledger/main.go's production wiring. Tile
	// bytes are written to TileRoot (or a fresh tmpDir if empty).
	UseRealTessera bool

	// TileRoot is the POSIX directory the embedded Tessera writes
	// tile + checkpoint files into. Empty under UseRealTessera=true
	// → a fresh tmp dir registered for cleanup. Ignored when
	// UseRealTessera is false.
	TileRoot string

	// CheckpointInterval / BatchSize / BatchMaxAge override the
	// upstream Tessera batcher tunables. Zero → SDK defaults
	// scaled down for fast tests (500 ms / 4 / 100 ms). Ignored
	// when UseRealTessera is false.
	CheckpointInterval time.Duration
	BatchSize          int
	BatchMaxAge        time.Duration

	// Origin is the Tessera "origin" line written into every
	// signed checkpoint. Defaults to testLogDID. Ignored when
	// UseRealTessera is false.
	Origin string

	// LowDifficulty caps admission PoW at 4-bit min / 8-bit
	// initial / 12-bit max. Default config is 16/8/24 — too
	// expensive when a single test submits 256+ entries.
	// Crypto / tile / byte tests opt in; persona tests keep
	// the production-shape default.
	LowDifficulty bool

	// PublicURLer wires the /v1/entries/{seq}/raw 302 redirect
	// path. Default nil → handler returns 500 on shipped
	// entries (fail-closed). BYTE-VER-02 supplies a static
	// fixture that maps (seq, hash) → an http test fixture URL.
	PublicURLer api.PublicURLer

	// BytestoreBackend selects the durable byte store the shipper
	// migrates WAL bytes into:
	//
	//   "" / "memory" — opbytestore.NewMemory() (default). Fast,
	//       zero external deps. The right choice for unit-shaped
	//       integration tests that only assert WAL→bytestore→read
	//       semantics, not the production S3 wire.
	//
	//   "s3"          — opbytestore.NewFromConfig against the
	//       BASEPROOF_TEST_S3_* env family (endpoint, bucket, creds,
	//       region, path-style). Routes through the SAME
	//       bytestore.S3 adapter production uses — SeaweedFS,
	//       RustFS, MinIO, AWS S3 all speak the same SigV4 wire.
	//       The determinism profile sets this so its end-to-end
	//       run exercises the real S3 shipper path, not the
	//       in-memory shortcut (no "gaps" between the determinism
	//       test and production shape).
	//
	// When "s3" and BASEPROOF_TEST_S3_BUCKET is unset, the harness
	// t.Skip()s — the caller asked for S3 but no S3 endpoint is
	// wired, which is a setup error, not a silent fallback to
	// memory.
	BytestoreBackend string

	// WitnessFromEnv switches the builder loop's cosigner from the
	// default in-process httptest fixture to one DISCOVERED via the
	// LEDGER_WITNESS_* env (cosignerFromEnv) — the at-scale validation
	// profiles (determinism) set this so they consume an externally-run
	// witness fleet instead of orchestrating one. When the env is unset
	// the run is NON-WITNESS (a logged warning). Other integration tests
	// leave this false and keep the hermetic in-process fixture.
	WitnessFromEnv bool
}

// tesseraSlots and buildTesseraForTests live in testserver_tessera_test.go
// to keep this file under the project's per-file LoC ceiling.

// -------------------------------------------------------------------------------------------------
// 2) startTestLedgerWithOpts — the full constructor
// -------------------------------------------------------------------------------------------------

// startTestLedgerWithOpts boots the integration-test ledger with
// the supplied options. Skips on missing BASEPROOF_TEST_DSN. Returns
// the testLedger with real-Tessera fields populated when
// opts.UseRealTessera was true.
func startTestLedgerWithOpts(t *testing.T, opts testLedgerOpts) *testLedger {
	t.Helper()

	dsn := os.Getenv("BASEPROOF_TEST_DSN")
	if dsn == "" {
		t.Skip("BASEPROOF_TEST_DSN not set — skipping HTTP integration test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		cancel()
		t.Fatalf("migrations: %v", err)
	}
	cleanTables(t, pool)

	// Bytestore selection. Default in-memory; "s3" routes through
	// the production bytestore.S3 adapter (SeaweedFS / RustFS / MinIO
	// / AWS S3) so end-to-end profiles (determinism) exercise the
	// real shipper→S3→read path instead of the in-memory shortcut.
	//
	// entryBytes is the bytestore.Backend interface used by the
	// shipper (writer) + composite reader. entryBytesMem is the
	// concrete *Memory exposed on testLedger.EntryBytes for the
	// handful of tests that call Memory-only methods (.Len()); it
	// is nil under the S3 backend, and those tests run only under
	// the default memory backend.
	entryBytes, entryBytesMem := buildTestBytestore(t, ctx, opts.BytestoreBackend)
	entryStore := store.NewEntryStore(pool)
	creditStore := store.NewCreditStore(pool)
	sequenceCursor := store.NewSequenceCursor(pool)
	reader := opbuilder.NewCursorReader(sequenceCursor)
	treeHeadStore := store.NewTreeHeadStore(pool)
	leafStore := store.NewPostgresLeafStore(pool)
	// De-pollution: the builder computes over the TailedNodeStore (in-memory tail
	// + tile read-through), not a PG node store. Tests run no reconciler, so the
	// in-memory node store backs the read-through and the tail holds every node.
	nodeStore := store.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	commitmentStore := store.NewCommitmentStore(pool)

	walDB, err := wal.OpenInMemory(nil)
	if err != nil {
		pool.Close()
		cancel()
		t.Fatalf("wal open: %v", err)
	}
	walc := wal.NewCommitter(walDB, wal.CommitterConfig{DisableSync: true})
	// walc + walDB cleanup is handled by the single shutdownChain
	// registered at the end of this function; do NOT register another
	// t.Cleanup here. LIFO ordering across multiple Cleanups was the
	// source of the AppendLeaf-future goroutine leak we just fixed.

	// Composite byte reader: WAL first, then in-memory bytestore.
	// In production the Shipper writes WAL→bytestore; the test harness
	// has no shipper, so a bare bytestore.Reader returns "not found"
	// for every hydrate call. The composite mirrors the e2e harness
	// (e2e_shipper_redirect_test.go:216) and lets read-path tests
	// hydrate from WAL even when nothing has shipped yet.
	composite := store.NewCompositeByteReader(walc, entryBytes, logger)
	fetcher := store.NewPostgresEntryFetcher(pool, composite, testLogDID)

	bufferStore := opbuilder.NewDeltaBufferStore(pool, 10, logger)
	deltaBuffer, _ := bufferStore.Load(ctx)
	if deltaBuffer == nil {
		deltaBuffer = sdkbuilder.NewDeltaWindowBuffer(10)
	}

	ts := buildTesseraForTests(t, ctx, opts, logger)

	// Witness cosigner. Default: a hermetic in-process httptest fixture
	// (K=1) so integration tests stay self-contained. The Ledger's
	// HeadSync POSTs to the fixture's cosign server over real HTTP and
	// persists signatures in treeHeadStore; tests asserting on the
	// cosigned-checkpoint file inspect ts.tileRoot/cosigned-checkpoint
	// after the builder loop completes a cycle.
	//
	// opts.WitnessFromEnv flips this to DISCOVER an external fleet via
	// the LEDGER_WITNESS_* env (cosignerFromEnv) — the at-scale
	// validation profiles set it so they never orchestrate witnesses;
	// when that env is unset the run is NON-WITNESS. Typed as the
	// builder interface so a disabled cosigner is a true nil interface
	// (builder/loop.go guards on witness != nil).
	var witnessCosigner opbuilder.WitnessCosigner
	if opts.WitnessFromEnv {
		if hs, enabled := cosignerFromEnv(t, pool, logger); enabled {
			witnessCosigner = hs
		}
	} else {
		witnessNetID := nonZeroTestNetworkID()
		witnessFx := newWitnessFixture(t, witnessNetID, 1)
		hs, hsErr := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
			EndpointResolver:       staticEndpointResolver{urls: witnessFx.URLs()},
			EndpointResolverLogDID: "did:test:log",
			QuorumK:                1,
			PerWitnessTimeout:      2 * time.Second,
			NetworkID:              witnessNetID,
			HTTPClient:             newTunedHTTPClient(2 * time.Second),
		}, treeHeadStore, logger)
		if hsErr != nil {
			cancel()
			pool.Close()
			t.Fatalf("real witness HeadSync: %v", hsErr)
		}
		witnessCosigner = hs
	}

	commitPub := opbuilder.NewCommitmentPublisher(
		testLogDID,
		testLogDID,
		opbuilder.CommitmentPublisherConfig{IntervalEntries: 100000, IntervalTime: 24 * time.Hour},
		func(e *envelope.Entry) error { return nil },
		logger,
	)

	loopCfg := opbuilder.DefaultLoopConfig(testLogDID)
	loopCfg.PollInterval = 50 * time.Millisecond
	loopCfg.BatchSize = 100

	builderLoop := opbuilder.NewBuilderLoop(
		loopCfg, pool, tree, leafStore, nodeStore,
		reader, fetcher, nil, deltaBuffer, bufferStore, commitPub,
		ts.builder, logger,
	).WithRootStore(store.NewSMTRootStateStore(pool))
	loopDone := make(chan struct{})
	go func() {
		builderLoop.Run(ctx)
		close(loopDone)
	}()

	// CheckpointLoop — the single-clock horizon producer: it tiles the latest
	// committed root durable, then cosigns + publishes THAT root as the horizon,
	// lagging the builder (mirrors production wiring in cmd/ledger/boot/wire).
	// Tests asserting on the cosigned-checkpoint file / cosigned heads rely on it.
	// Runs only when a real Tessera adapter AND a witness cosigner are present;
	// otherwise the run is non-witness (no horizon), as before.
	if ts.checkpointer != nil && witnessCosigner != nil {
		checkpointLoop := opbuilder.NewCheckpointLoop(
			store.NewSMTCommitCursor(store.NewSMTRootStateStore(pool)),
			store.NewPgTileFrontier(pool),
			store.NewBuildTilesEmitter(nodeStore, store.NewPosixSMTTileStore(ts.tileRoot)),
			ts.checkpointer, // CheckpointRooter — RootAtSize
			ts.checkpointer, // CheckpointPublisher — POSIX cosigned-checkpoint
			witnessCosigner,
			store.NewEntryIndexReceiptRanger(pool, testLogDID),
			20*time.Millisecond,
			logger,
		)
		go checkpointLoop.Run(ctx)
	}

	// Sequencer (WAL Admitted → Tessera AppendLeaf → entry_index INSERT
	// → WAL Sequenced). Without this goroutine, submissions land in WAL
	// but never reach entry_index, so /v1/entries-hash/{hash} stays a
	// 404 and submitEntry's polling loop times out. Mirrors the e2e
	// harness wiring at e2e_shipper_redirect_test.go:348-361.
	seq := sequencer.NewSequencer(walc, ts.admission, pool, entryStore, sequencer.Config{
		PollInterval: 10 * time.Millisecond,
		Logger:       logger,
	})
	seqDone := make(chan struct{})
	go func() {
		// A discarded error here is how the sequencer died SILENTLY for the
		// HTTP round-trip trio (#82): Run fail-fasts (nil Tessera seam /
		// committer-state init) and nothing downstream ever sequences.
		if err := seq.Run(ctx); err != nil {
			logger.Error("test harness: sequencer.Run exited", "error", err)
		}
		close(seqDone)
	}()

	// Shipper (WAL Sequenced → bytestore WriteEntry → WAL Shipped).
	// Production has a shipper that migrates wire bytes from the WAL
	// into the durable bytestore. TestRule_EndToEnd_BytesNeverTouchPostgres
	// asserts entryBytes contains the bytes after submission — without
	// a shipper that's never true.
	ship := shipper.NewShipper(walc, entryBytes, shipper.Config{
		PollInterval: 50 * time.Millisecond,
		MaxInFlight:  4,
		Logger:       logger,
	})
	shipDone := make(chan struct{})
	go func() {
		if err := ship.Run(ctx); err != nil {
			logger.Error("test harness: shipper.Run exited", "error", err)
		}
		close(shipDone)
	}()

	diffCfg := middleware.DefaultDifficultyConfig()
	if opts.LowDifficulty {
		diffCfg.InitialDifficulty = 8
		diffCfg.MinDifficulty = 4
		diffCfg.MaxDifficulty = 12
	}
	diffController := middleware.NewDifficultyController(
		sequenceCursor, diffCfg, logger,
	)
	queryAPI := indexes.NewPostgresQueryAPI(ctx, pool, composite, testLogDID)

	opSignerPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("ledger signer key: %v", err)
	}
	// Mode-B PoW admission gate (api/submission.go, api/batch.go) requires BOTH
	// Gates.ModeBPoW and a non-nil DifficultyResolver; the harness previously set
	// neither, so every Mode-B submission 403'd ("Mode-B PoW disabled"). Mirror
	// production: enable the gate and wire a StaticDifficultyResolver over the same
	// controller (cmd/ledger/boot/wire/wire.go:buildDifficultyResolver). Only
	// ModeBPoW is flipped — the other gates stay at the harness's permissive zero
	// value, so no other test's admission posture changes.
	diffResolver, drErr := admission.NewStaticDifficultyResolver(diffController)
	if drErr != nil {
		cancel()
		pool.Close()
		t.Fatalf("static difficulty resolver: %v", drErr)
	}
	submissionDeps := &api.SubmissionDeps{
		Storage: api.StorageDeps{
			EntryStore: entryStore,
			WAL:        walc,
			Tessera:    ts.admission,
		},
		Admission: api.AdmissionConfig{
			DiffController:        diffController,
			EpochWindowSeconds:    3600,
			EpochAcceptanceWindow: 1,
		},
		Gates:              admission.Gates{ModeBPoW: true},
		DifficultyResolver: diffResolver,
		Identity:           api.IdentityDeps{Credits: creditStore},
		LogDID:             testLogDID,
		LedgerDID:          testLedgerDID,
		LedgerSignerPriv:   opSignerPriv,
		MaxEntrySize:       1 << 20,
		Logger:             logger,
	}
	treeDeps := &api.TreeDeps{
		TreeHeadStore: treeHeadStore, Inclusion: ts.inclusion,
		Consistency: ts.consistency, Logger: logger,
	}
	smtDeps := &api.SMTDeps{Tree: tree, LeafStore: leafStore, Logger: logger}
	queryDeps := &api.QueryDeps{
		EntryStore: entryStore, QueryAPI: queryAPI, DiffController: diffController,
		WAL: walc, Logger: logger,
	}
	entryReadDeps := &api.EntryReadDeps{
		Fetcher: fetcher, QueryAPI: queryAPI,
		EntryStore: entryStore, WAL: walc,
		// PublicURLer is opt-driven: scenarios tests that exercise
		// the 302 redirect (BYTE-VER-02) supply a static fixture;
		// everything else leaves it nil and the handler fails 500
		// on shipped-entry hits (fail-closed).
		PublicURLer: opts.PublicURLer, LogDID: testLogDID, Logger: logger,
	}
	commitDeps := &api.DerivationCommitmentDeps{
		CommitmentStore: commitmentStore, Logger: logger,
	}
	cryptoCommitDeps := &api.CryptographicCommitmentDeps{
		Fetcher: store.NewPostgresCommitmentFetcher(pool, composite, testLogDID),
		Logger:  logger,
	}

	handlers := buildTestHandlers(submissionDeps, treeDeps, smtDeps, queryDeps, entryReadDeps, commitDeps)
	handlers.CommitmentLookup = api.NewCommitmentLookupHandler(cryptoCommitDeps)

	serverCfg := api.DefaultServerConfig()
	serverCfg.Addr = "127.0.0.1:0"
	server := api.NewServer(serverCfg, store.NewPostgresSessionLookup(pool), handlers, logger)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		pool.Close()
		t.Fatalf("listen: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	go server.Serve(ln)

	op := &testLedger{
		BaseURL: baseURL, Pool: pool, Cursor: sequenceCursor,
		CreditStore: creditStore, EntryStore: entryStore,
		EntryBytes:   entryBytesMem,
		WALCommitter: walc,
		// EntryReader is the SAME composite that fetcher (production
		// read path) uses. Tests asserting against the EntryReader
		// abstraction MUST go through this field — reading EntryBytes
		// directly races the shipper's StateSequenced→StateShipped
		// transition. See testLedger docstring.
		EntryReader:    composite,
		cancel:         cancel,
		RealTesseraDir: ts.tileRoot,
		RealEmbedded:   ts.embedded,
		RealTileReader: ts.tileReader,
	}

	// Single ordered teardown — see tests/shutdownchain_test.go for
	// the spec-order rationale. Do NOT add other t.Cleanup calls in
	// this function: LIFO ordering across multiple Cleanups is what
	// caused the AppendLeaf-future goroutine leak.
	t.Cleanup(shutdownChain{
		Logger:        logger,
		Server:        server,
		Tessera:       ts.embedded,
		Cancel:        cancel,
		GoroutineDone: []<-chan struct{}{loopDone, seqDone, shipDone},
		WALC:          walc,
		WALDB:         walDB,
		Pool:          pool,
		CleanTables:   func() { cleanTables(t, pool) },
	}.Run)

	for i := 0; i < 50; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return op
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("test ledger did not become ready in 2.5s")
	return nil
}

// -------------------------------------------------------------------------------------------------
// 5) Handler-construction helper
// -------------------------------------------------------------------------------------------------

// buildTestHandlers factors the api.Handlers literal out of the
// main constructor so startTestLedgerWithOpts stays under the
// project's per-file LoC ceiling. Returns a fully-populated
// Handlers map matching cmd/ledger/main.go's mount set, except
// WitnessCosign which test scenarios mount on a per-test basis.
func buildTestHandlers(
	submissionDeps *api.SubmissionDeps,
	treeDeps *api.TreeDeps,
	smtDeps *api.SMTDeps,
	queryDeps *api.QueryDeps,
	entryReadDeps *api.EntryReadDeps,
	commitDeps *api.DerivationCommitmentDeps,
) api.Handlers {
	return api.Handlers{
		Submission:      api.NewSubmissionHandler(submissionDeps),
		BatchSubmission: api.NewBatchSubmissionHandler(submissionDeps),
		TreeHead:        api.NewTreeHeadHandler(treeDeps),
		TreeInclusion:   api.NewTreeInclusionHandler(treeDeps),
		TreeConsistency: api.NewTreeConsistencyHandler(treeDeps),
		SMTProof:        api.NewSMTProofHandler(smtDeps),
		SMTBatchProof:   api.NewSMTBatchProofHandler(smtDeps),
		SMTRoot:         api.NewSMTRootHandler(smtDeps),
		CosignatureOf:   api.NewQueryCosignatureOfHandler(queryDeps),
		TargetRoot:      api.NewQueryTargetRootHandler(queryDeps),
		SignerDID:       api.NewQuerySignerDIDHandler(queryDeps),
		SchemaRef:       api.NewQuerySchemaRefHandler(queryDeps),
		Scan:            api.NewQueryScanHandler(queryDeps),
		Difficulty:      api.NewDifficultyHandler(queryDeps),
		EntryBySequence: api.NewEntryBySequenceHandler(entryReadDeps),
		EntryByHash:     api.NewHashLookupHandler(queryDeps),
		EntryBatch:      api.NewEntryBatchHandler(entryReadDeps),
		EntryRaw:        api.NewRawEntryHandler(entryReadDeps),
		SMTLeaf:         api.NewSMTLeafHandler(smtDeps),
		SMTLeafBatch:    api.NewSMTLeafBatchHandler(smtDeps),
		CommitmentQuery: api.NewDerivationCommitmentQueryHandler(commitDeps),
	}
}

// -------------------------------------------------------------------------------------------------
// 4) buildTestBytestore — backend selector (memory | s3)
// -------------------------------------------------------------------------------------------------

// buildTestBytestore constructs the durable byte store the test
// ledger's shipper migrates WAL bytes into. Returns the
// bytestore.Backend interface (consumed by the shipper + composite
// reader) AND, for the in-memory backend, the concrete *Memory that
// testLedger.EntryBytes exposes for Memory-only assertions (.Len()).
// The concrete return is nil under the s3 backend.
//
//	backend == "" / "memory":
//	  opbytestore.NewMemory(). Fast, dependency-free. The default
//	  for every integration-shaped test.
//
//	backend == "s3":
//	  opbytestore.NewFromConfig against the BASEPROOF_TEST_S3_* env
//	  family — the SAME bytestore.S3 adapter production uses
//	  (SeaweedFS / RustFS / MinIO / AWS S3, all SigV4). The
//	  determinism profile sets this so its scale + end-to-end run
//	  exercises the real S3 shipper/read path with NO in-memory
//	  gap. A unique per-run prefix keeps concurrent / repeated runs
//	  from colliding in a shared bucket.
//
// t.Skip when backend=="s3" but BASEPROOF_TEST_S3_BUCKET is unset —
// the caller asked for S3 and no endpoint is wired; silently
// falling back to memory would defeat the "no gaps" contract.
func buildTestBytestore(t *testing.T, ctx context.Context, backend string) (opbytestore.Store, *opbytestore.Memory) {
	t.Helper()
	switch backend {
	case "", "memory":
		mem := opbytestore.NewMemory()
		return mem, mem
	case "s3":
		bucket := os.Getenv("BASEPROOF_TEST_S3_BUCKET")
		if bucket == "" {
			t.Skip("BytestoreBackend=s3 but BASEPROOF_TEST_S3_BUCKET unset — run via scripts/infra up + eval $(./scripts/infra env)")
		}
		cfg := opbytestore.Config{
			Backend:     "s3",
			Bucket:      bucket,
			Prefix:      fmt.Sprintf("determinism/%d", time.Now().UnixNano()),
			S3Endpoint:  os.Getenv("BASEPROOF_TEST_S3_ENDPOINT"),
			S3AccessKey: os.Getenv("BASEPROOF_TEST_S3_ACCESS_KEY"),
			S3SecretKey: os.Getenv("BASEPROOF_TEST_S3_SECRET_KEY"),
			S3Region:    os.Getenv("BASEPROOF_TEST_S3_REGION"),
		}
		if cfg.S3Region == "" {
			cfg.S3Region = "us-east-1"
		}
		// SeaweedFS / RustFS / MinIO use path-style addressing; AWS S3
		// is virtual-host-style. Default path-style ON unless the
		// operator explicitly opts out for real AWS.
		if os.Getenv("BASEPROOF_TEST_S3_PATH_STYLE") != "false" {
			cfg.S3PathStyle = true
		}
		be, err := opbytestore.NewFromConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("buildTestBytestore: s3 NewFromConfig: %v", err)
		}
		return be, nil
	default:
		t.Fatalf("buildTestBytestore: unsupported backend %q (memory|s3)", backend)
		return nil, nil // unreachable
	}
}
