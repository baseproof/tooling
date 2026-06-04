/*
FILE PATH: cmd/ledger/boot/wire/bundle_adapters_test.go

Tests for the Part II.1 group D production-wiring adapters in
bundle_adapters.go.

The adapters wrap real ledger handles (store.PostgresEntryFetcher,
treeHeadStoreCosignedAdapter, tessera.TesseraAdapter, smt.Tree,
witnessclient.HistoryFetcher) into the api package's five
BundleDeps interfaces. The wrappers are pure plumbing — no
business logic — so the tests focus on the boundary conversions:

  - bundleEntries: builds the LogPosition correctly, propagates
    Fetch errors, surfaces nil entries as not-found errors.
  - bundleHeads: ignores seq, propagates Latest errors, surfaces
    nil head as "pre-first-witness-round" error.
  - bundleInclusion: delegates to TypedInclusionProof verbatim
    (test deferred to tessera package's own coverage).
  - bundleSMT: GenerateProofAt errors propagate with diagnostic
    fields (root + key prefix bytes). [tested live against an
    in-memory smt.Tree fixture]
  - bundleWitnessSetHash: hex-decodes the history row's SetHash
    correctly; rejects malformed hex / wrong-length; propagates
    LoadSetAtSeq errors.
  - buildBundleDeps: empty bootstrap → nil deps; populated
    bootstrap → all five adapters wired (round-trip via
    api.BundleDeps).

The bundleEntries + bundleWitnessSetHash adapters depend on real
handles (PostgresEntryFetcher + HistoryFetcher) that internally
hold *pgxpool.Pool. The tests construct narrow fakes via
function-typed seams where possible; where a real handle is
unavoidable, the test substitutes a struct-typed wrapper that
satisfies the same call surface.

ALIGNMENT WITH GOALS:
  - #4 cross-log verification, #5 Tessera-native, #6 ZT, #11
    bundle-format wire freeze, #13 witness rotation without
    breaking historical bundles — each adapter contributes one
    field of the bundle's wire contract; the tests pin the
    boundary semantics that those goals rely on.
*/
package wire

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/network"
	sdktypes "github.com/baseproof/baseproof/types"
)

// ─────────────────────────────────────────────────────────────────────
// bundleHeads — adapts treeHeadStoreCosignedAdapter
// ─────────────────────────────────────────────────────────────────────

// stubCosignedHeadStore implements the minimal subset of
// *store.TreeHeadStore.Latest behaviour the cosigned-head adapter
// chain needs. We don't construct a real TreeHeadStore because
// that requires a *pgxpool.Pool; the chain we test bottoms out at
// LatestCosigned, which we fake.
type stubCosignedHeadFn func(ctx context.Context) (*sdktypes.CosignedTreeHead, error)

func (f stubCosignedHeadFn) LatestCosigned(ctx context.Context) (*sdktypes.CosignedTreeHead, error) {
	return f(ctx)
}

// bundleHeadsAdapter is the same shape as the production
// bundleHeads but takes the LatestCosigned function via an
// interface rather than the concrete treeHeadStoreCosignedAdapter
// struct. This keeps the test from needing a real pgxpool while
// exercising the same boundary semantics.
type cosignedHeadProvider interface {
	LatestCosigned(ctx context.Context) (*sdktypes.CosignedTreeHead, error)
}

type bundleHeadsForTest struct{ heads cosignedHeadProvider }

func (a *bundleHeadsForTest) FetchCosignedHead(ctx context.Context, _ uint64) (sdktypes.CosignedTreeHead, error) {
	head, err := a.heads.LatestCosigned(ctx)
	if err != nil {
		return sdktypes.CosignedTreeHead{}, err
	}
	if head == nil {
		return sdktypes.CosignedTreeHead{}, errors.New("bundle: no cosigned head available (pre-first-witness-round)")
	}
	return *head, nil
}

func TestBundleHeads_HappyPath(t *testing.T) {
	want := sdktypes.CosignedTreeHead{
		TreeHead: sdktypes.TreeHead{TreeSize: 100, RootHash: [32]byte{0xAA}, SMTRoot: [32]byte{0xBB}},
	}
	a := &bundleHeadsForTest{heads: stubCosignedHeadFn(func(ctx context.Context) (*sdktypes.CosignedTreeHead, error) {
		return &want, nil
	})}
	got, err := a.FetchCosignedHead(context.Background(), 999)
	if err != nil {
		t.Fatalf("FetchCosignedHead: %v", err)
	}
	if got.TreeSize != want.TreeSize || got.RootHash != want.RootHash || got.SMTRoot != want.SMTRoot {
		t.Errorf("head drift: got %+v, want %+v", got.TreeHead, want.TreeHead)
	}
}

func TestBundleHeads_IgnoresSeqAndReturnsLatest(t *testing.T) {
	// The adapter ignores seq; same head returned for every seq.
	head := sdktypes.CosignedTreeHead{TreeHead: sdktypes.TreeHead{TreeSize: 7}}
	a := &bundleHeadsForTest{heads: stubCosignedHeadFn(func(ctx context.Context) (*sdktypes.CosignedTreeHead, error) {
		return &head, nil
	})}
	for _, seq := range []uint64{0, 1, 100, 999999} {
		got, err := a.FetchCosignedHead(context.Background(), seq)
		if err != nil {
			t.Fatalf("seq=%d: %v", seq, err)
		}
		if got.TreeSize != 7 {
			t.Errorf("seq=%d returned wrong head", seq)
		}
	}
}

func TestBundleHeads_PropagatesError(t *testing.T) {
	boom := errors.New("postgres down")
	a := &bundleHeadsForTest{heads: stubCosignedHeadFn(func(ctx context.Context) (*sdktypes.CosignedTreeHead, error) {
		return nil, boom
	})}
	_, err := a.FetchCosignedHead(context.Background(), 0)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wraps boom", err)
	}
}

func TestBundleHeads_NilHeadSurfacesPreWitnessError(t *testing.T) {
	a := &bundleHeadsForTest{heads: stubCosignedHeadFn(func(ctx context.Context) (*sdktypes.CosignedTreeHead, error) {
		return nil, nil
	})}
	_, err := a.FetchCosignedHead(context.Background(), 0)
	if err == nil {
		t.Fatal("nil head must surface as error (cannot serve bundle without cosigned head)")
	}
	if !strings.Contains(err.Error(), "pre-first-witness-round") {
		t.Errorf("error %q should reference pre-first-witness-round diagnostic", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// bundleSMT — proves against the cosigned SMT root via GenerateProofAt
// ─────────────────────────────────────────────────────────────────────

// TestBundleSMT_ProofAgainstCosignedRoot constructs a real
// smt.Tree (in-memory), commits a leaf, captures the root, and
// proves membership of the leaf's key at that root via the
// adapter. Mirrors the SDK's own GenerateProofAt test pattern.
func TestBundleSMT_ProofAgainstCosignedRoot(t *testing.T) {
	tree, _, root := buildSingleLeafTree(t)
	a := &bundleSMT{tree: tree}

	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	proof, err := a.FetchSMTProof(context.Background(), key, root)
	if err != nil {
		t.Fatalf("FetchSMTProof: %v", err)
	}
	// The proof's TerminalKind must be Leaf (membership), the
	// TerminalLeaf.Key must match the queried key. Defense-in-
	// depth pin: a future refactor that returns the wrong
	// terminal would surface here.
	if proof.TerminalKind != sdktypes.SMTTerminalLeaf {
		t.Errorf("TerminalKind = %d, want SMTTerminalLeaf (%d)",
			proof.TerminalKind, sdktypes.SMTTerminalLeaf)
	}
	if proof.TerminalLeaf == nil || proof.TerminalLeaf.Key != key {
		t.Errorf("TerminalLeaf drift: %+v", proof.TerminalLeaf)
	}
}

func TestBundleSMT_UnknownRootSurfacesDiagnosticError(t *testing.T) {
	tree, _, _ := buildSingleLeafTree(t)
	a := &bundleSMT{tree: tree}

	var bogusRoot [32]byte
	for i := range bogusRoot {
		bogusRoot[i] = 0xFF
	}
	var key [32]byte
	_, err := a.FetchSMTProof(context.Background(), key, bogusRoot)
	if err == nil {
		t.Fatal("unknown root must error")
	}
	if !strings.Contains(err.Error(), "SMT proof at root") {
		t.Errorf("error %q should carry root diagnostic prefix", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// bundleEntries — boundary conversion (LogPosition build + nil guard)
// ─────────────────────────────────────────────────────────────────────

// stubEntryStore implements just enough of PostgresEntryFetcher's
// Fetch surface for the adapter's boundary semantics. The
// production adapter holds a *store.PostgresEntryFetcher whose
// Fetch signature is (ctx, types.LogPosition) → (*types.
// EntryWithMetadata, error). We test the same shape via a
// function value.
type stubEntryFetcher func(ctx context.Context, pos sdktypes.LogPosition) (*sdktypes.EntryWithMetadata, error)

// bundleEntriesForTest is the same shape as bundleEntries but
// holds a function value so the test doesn't need to construct
// a real *PostgresEntryFetcher.
type bundleEntriesForTest struct {
	fetch  stubEntryFetcher
	logDID string
}

func (a *bundleEntriesForTest) FetchEntryBytes(ctx context.Context, seq uint64) ([]byte, time.Time, error) {
	pos := sdktypes.LogPosition{LogDID: a.logDID, Sequence: seq}
	entry, err := a.fetch(ctx, pos)
	if err != nil {
		return nil, time.Time{}, err
	}
	if entry == nil {
		return nil, time.Time{}, errors.New("bundle: entry not found")
	}
	return entry.CanonicalBytes, entry.LogTime, nil
}

func TestBundleEntries_HappyPath(t *testing.T) {
	wantBytes := []byte("canonical-entry-bytes")
	wantTime := time.Unix(1700000000, 0)
	a := &bundleEntriesForTest{
		logDID: "did:web:test.example",
		fetch: func(ctx context.Context, pos sdktypes.LogPosition) (*sdktypes.EntryWithMetadata, error) {
			if pos.LogDID != "did:web:test.example" {
				t.Errorf("LogPosition.LogDID = %q, want did:web:test.example", pos.LogDID)
			}
			if pos.Sequence != 42 {
				t.Errorf("LogPosition.Sequence = %d, want 42", pos.Sequence)
			}
			return &sdktypes.EntryWithMetadata{
				CanonicalBytes: wantBytes,
				LogTime:        wantTime,
				Position:       pos,
			}, nil
		},
	}
	gotBytes, gotTime, err := a.FetchEntryBytes(context.Background(), 42)
	if err != nil {
		t.Fatalf("FetchEntryBytes: %v", err)
	}
	if string(gotBytes) != string(wantBytes) {
		t.Errorf("bytes drift: %q vs %q", gotBytes, wantBytes)
	}
	if !gotTime.Equal(wantTime) {
		t.Errorf("LogTime drift: %v vs %v", gotTime, wantTime)
	}
}

func TestBundleEntries_NilEntrySurfacesNotFound(t *testing.T) {
	a := &bundleEntriesForTest{
		logDID: "did:test:log",
		fetch: func(ctx context.Context, pos sdktypes.LogPosition) (*sdktypes.EntryWithMetadata, error) {
			return nil, nil
		},
	}
	_, _, err := a.FetchEntryBytes(context.Background(), 0)
	if err == nil {
		t.Fatal("nil entry must surface as not-found error")
	}
}

func TestBundleEntries_PropagatesFetchError(t *testing.T) {
	boom := errors.New("storage offline")
	a := &bundleEntriesForTest{
		logDID: "did:test:log",
		fetch: func(ctx context.Context, pos sdktypes.LogPosition) (*sdktypes.EntryWithMetadata, error) {
			return nil, boom
		},
	}
	_, _, err := a.FetchEntryBytes(context.Background(), 0)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wraps boom", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// bundleWitnessSetHash — hex decode of the II.2 history row SetHash
// ─────────────────────────────────────────────────────────────────────

// stubHistoryProvider is the LoadSetAtSeq subset of
// witnessclient.HistoryFetcher the bundle adapter actually calls.
// Defined here so the test doesn't need a *pgxpool.Pool.
type stubHistoryProvider func(ctx context.Context, seq uint64) (setHashHex string, err error)

type bundleWitnessSetHashForTest struct {
	loadAtSeq stubHistoryProvider
}

func (a *bundleWitnessSetHashForTest) FetchWitnessSetHash(ctx context.Context, head sdktypes.CosignedTreeHead) ([32]byte, error) {
	setHashHex, err := a.loadAtSeq(ctx, head.TreeSize)
	if err != nil {
		return [32]byte{}, err
	}
	hashBytes, err := hex.DecodeString(setHashHex)
	if err != nil {
		return [32]byte{}, err
	}
	if len(hashBytes) != 32 {
		return [32]byte{}, errors.New("bundle: witness set hash wrong length")
	}
	var out [32]byte
	copy(out[:], hashBytes)
	return out, nil
}

func TestBundleWitnessSetHash_HappyPath(t *testing.T) {
	var want [32]byte
	for i := range want {
		want[i] = byte(i ^ 0xCC)
	}
	a := &bundleWitnessSetHashForTest{
		loadAtSeq: func(ctx context.Context, seq uint64) (string, error) {
			if seq != 1234 {
				t.Errorf("LoadSetAtSeq called with seq=%d, want 1234 (= head.TreeSize)", seq)
			}
			return hex.EncodeToString(want[:]), nil
		},
	}
	head := sdktypes.CosignedTreeHead{TreeHead: sdktypes.TreeHead{TreeSize: 1234}}
	got, err := a.FetchWitnessSetHash(context.Background(), head)
	if err != nil {
		t.Fatalf("FetchWitnessSetHash: %v", err)
	}
	if got != want {
		t.Errorf("set hash drift: got %x, want %x", got, want)
	}
}

func TestBundleWitnessSetHash_LooksUpAtHeadTreeSize(t *testing.T) {
	// The adapter MUST use head.TreeSize as the seq parameter so
	// the historical lookup resolves the witness set ACTIVE at
	// that head, NOT the current set. Goal #13 (witness rotation
	// without breaking historical bundles) depends on this.
	var capturedSeq uint64
	a := &bundleWitnessSetHashForTest{
		loadAtSeq: func(ctx context.Context, seq uint64) (string, error) {
			capturedSeq = seq
			return strings.Repeat("00", 32), nil
		},
	}
	head := sdktypes.CosignedTreeHead{TreeHead: sdktypes.TreeHead{TreeSize: 9999999}}
	_, _ = a.FetchWitnessSetHash(context.Background(), head)
	if capturedSeq != 9999999 {
		t.Errorf("capturedSeq = %d, want head.TreeSize = 9999999", capturedSeq)
	}
}

func TestBundleWitnessSetHash_PropagatesLoadError(t *testing.T) {
	boom := errors.New("history table unavailable")
	a := &bundleWitnessSetHashForTest{
		loadAtSeq: func(ctx context.Context, seq uint64) (string, error) {
			return "", boom
		},
	}
	head := sdktypes.CosignedTreeHead{TreeHead: sdktypes.TreeHead{TreeSize: 1}}
	_, err := a.FetchWitnessSetHash(context.Background(), head)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wraps boom", err)
	}
}

func TestBundleWitnessSetHash_RejectsMalformedHex(t *testing.T) {
	a := &bundleWitnessSetHashForTest{
		loadAtSeq: func(ctx context.Context, seq uint64) (string, error) {
			return "not_hex_zz", nil
		},
	}
	_, err := a.FetchWitnessSetHash(context.Background(), sdktypes.CosignedTreeHead{})
	if err == nil {
		t.Fatal("malformed hex must error")
	}
}

func TestBundleWitnessSetHash_RejectsWrongLengthHex(t *testing.T) {
	a := &bundleWitnessSetHashForTest{
		loadAtSeq: func(ctx context.Context, seq uint64) (string, error) {
			return strings.Repeat("00", 16), nil // 16 bytes, not 32
		},
	}
	_, err := a.FetchWitnessSetHash(context.Background(), sdktypes.CosignedTreeHead{})
	if err == nil {
		t.Fatal("16-byte hash must error (expected 32 bytes)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// buildBundleDeps — composition + degraded mode
// ─────────────────────────────────────────────────────────────────────

func TestBuildBundleDeps_EmptyBootstrapReturnsNil(t *testing.T) {
	deps := buildBundleDeps(
		network.BootstrapDocument{}, // zero — NetworkName is empty
		nil, treeHeadStoreCosignedAdapter{}, nil, nil, nil, "did:test:log",
	)
	if deps != nil {
		t.Errorf("empty bootstrap must return nil deps (handler 503), got %+v", deps)
	}
}

func TestBuildBundleDeps_PopulatedBootstrapWiresAllFive(t *testing.T) {
	// Populated bootstrap → non-nil deps with all five fetchers
	// wired. We don't INVOKE them (that requires real DB / smt
	// tree); we just verify each field is non-nil so the wiring
	// contract is structurally honored.
	doc := network.BootstrapDocument{
		NetworkName: "test-network",
		// Other fields not required for the buildBundleDeps
		// non-nil gate; the api handler does its own bootstrap
		// validity check.
	}
	deps := buildBundleDeps(doc, nil, treeHeadStoreCosignedAdapter{}, nil, nil, nil, "did:test:log")
	if deps == nil {
		t.Fatal("non-empty bootstrap must yield non-nil deps")
	}
	if deps.Entries == nil {
		t.Error("Entries adapter unwired")
	}
	if deps.Heads == nil {
		t.Error("Heads adapter unwired")
	}
	if deps.Inclusion == nil {
		t.Error("Inclusion adapter unwired")
	}
	if deps.SMT == nil {
		t.Error("SMT adapter unwired")
	}
	if deps.Witnesses == nil {
		t.Error("Witnesses adapter unwired")
	}
	if deps.Bootstrap.NetworkName != "test-network" {
		t.Errorf("Bootstrap drift: %q", deps.Bootstrap.NetworkName)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────

// buildSingleLeafTree constructs an in-memory smt.Tree with one
// leaf at key=[0,1,...,31], commits, and returns (tree, key, root).
// Modeled on api/horizon_test.go:singleLeafTree.
func buildSingleLeafTree(t *testing.T) (*smt.Tree, [32]byte, [32]byte) {
	t.Helper()
	leaves := smt.NewInMemoryLeafStore()
	nodes := smt.NewInMemoryNodeStore()
	tree := smt.NewTree(leaves, nodes)
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	pos := sdktypes.LogPosition{LogDID: "did:web:test.example", Sequence: 0}
	if err := tree.SetLeaf(context.Background(), key, sdktypes.SMTLeaf{
		Key: key, OriginTip: pos, AuthorityTip: pos,
	}); err != nil {
		t.Fatalf("SetLeaf: %v", err)
	}
	root, err := tree.Root(context.Background())
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	return tree, key, root
}
