// FILE PATH: witnessclient/head_sync_test.go
//
// Unit tests for the Ledger's cosign client. Splits cleanly into:
//
//   - Constructor tests (no DSN required) — pin the rejection
//     contract for malformed HeadSyncConfig values.
//
//   - End-to-end RequestCosignatures tests (DSN-gated) — pin the
//     happy path (K-of-N collected + persisted) and the
//     quorum-failure error wrapping. Skip cleanly when
//     BASEPROOF_TEST_DSN is unset.
//
// PHYSICS, NOT MOCKS:
//
// The DSN-gated tests use real httptest.NewServer running the
// SDK's cosign.NewWitnessHandler. The Ledger's HeadSync POSTs to
// real HTTP and the witness signs with a real ECDSA key. The
// (head, signature) tuple is persisted into a real Postgres
// tree_heads / tree_head_sigs row pair via store.TreeHeadStore.
package witnessclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/store"
)

// silentLogger discards output; tests assert on return values
// + Postgres state, not log content.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testHeadSyncHTTPClient is the local helper every NewHeadSync call
// in this file uses (except the deliberate-nil rejection test). As
// of baseproof v1.34 NewHeadSync rejects a nil *http.Client (no silent
// fallback to sdklog.DefaultClient); tests must supply one.
func testHeadSyncHTTPClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// testNetID returns a deterministic non-zero NetworkID scoped
// to this test file.
func testNetID() cosign.NetworkID {
	var n cosign.NetworkID
	for i := range n {
		n[i] = byte(0x10 | (i & 0x0F))
	}
	return n
}

// requireDSN returns a connected pgxpool.Pool against
// BASEPROOF_TEST_DSN. Skips the test if the env var is unset —
// matches the P4 + commitment_fetcher pattern.
func requireDSN(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("BASEPROOF_TEST_DSN")
	if dsn == "" {
		t.Skip("BASEPROOF_TEST_DSN not set — skipping HeadSync DB-backed test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := store.RunMigrations(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("RunMigrations: %v", err)
	}
	return pool
}

// resetTreeHeadTables truncates the two persistence tables so
// each DSN-gated test starts from a known-empty state.
func resetTreeHeadTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DELETE FROM tree_head_sigs`); err != nil {
		t.Fatalf("clear tree_head_sigs: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM tree_heads`); err != nil {
		t.Fatalf("clear tree_heads: %v", err)
	}
}

// startWitnessServer spins up an in-process httptest cosign server
// backed by a fresh ECDSA key + the SDK's NewWitnessHandler.
// Cleanup is registered with t.Cleanup.
func startWitnessServer(t *testing.T, netID cosign.NetworkID) *httptest.Server {
	srv, _ := startWitnessServerWithPub(t, netID)
	return srv
}

// startWitnessServerWithPub is startWitnessServer plus the witness's
// public key, for tests that need to verify the returned
// cosignatures (e.g. proving the signature binds ReceiptRoot).
func startWitnessServerWithPub(t *testing.T, netID cosign.NetworkID) (*httptest.Server, types.WitnessPublicKey) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("signatures.GenerateKey: %v", err)
	}
	signer := cosign.NewECDSAWitnessSigner(priv)
	h, err := cosign.NewWitnessHandler(cosign.WitnessHandlerConfig{
		Signer:          signer,
		AllowedNetworks: map[cosign.NetworkID]struct{}{netID: {}},
	})
	if err != nil {
		t.Fatalf("NewWitnessHandler: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(cosign.DefaultCosignPath, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	pub := types.WitnessPublicKey{
		ID:        signer.PubKeyID(),
		PublicKey: signatures.PubKeyBytes(&priv.PublicKey),
		SchemeTag: signatures.SchemeECDSA,
	}
	return srv, pub
}

// ─────────────────────────────────────────────────────────────────
// Constructor tests (no DSN needed; treeStore can be nil because
// NewHeadSync does not call it).
// ─────────────────────────────────────────────────────────────────

// TestNewHeadSync_RejectsNilResolver pins the PRE-11 Phase B fail-loud
// contract: with no on-log EndpointResolver wired there is NO config
// dial-list to fall back to, so construction must fail. (Replaces the
// pre-Phase-B TestNewHeadSync_RejectsEmptyEndpoints, which pinned the
// now-deleted "empty WitnessEndpoints slice → error" behaviour.)
func TestNewHeadSync_RejectsNilResolver(t *testing.T) {
	_, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:  nil,
		QuorumK:           1,
		PerWitnessTimeout: 5 * time.Second,
		NetworkID:         testNetID(),
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("NewHeadSync with nil EndpointResolver: expected error (no config dial-list fallback)")
	}
}

func TestNewHeadSync_RejectsNonPositiveQuorum(t *testing.T) {
	_, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{"http://w1"}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                0,
		PerWitnessTimeout:      5 * time.Second,
		NetworkID:              testNetID(),
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("NewHeadSync with QuorumK=0: expected error")
	}
}

func TestNewHeadSync_RejectsQuorumGreaterThanN(t *testing.T) {
	// SDK's NewWitnessCollector rejects K > N — the Ledger-side
	// builder relies on this for early-fail semantics. Pin the
	// rejection so a refactor that swaps the collector for one
	// that silently accepts impossible quora can't slip past.
	_, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{"http://w1", "http://w2"}}, // N=2
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                3, // K=3 > N
		PerWitnessTimeout:      5 * time.Second,
		NetworkID:              testNetID(),
		HTTPClient:             testHeadSyncHTTPClient(),
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("NewHeadSync with QuorumK > N: expected error")
	}
}

func TestNewHeadSync_DefaultsPerWitnessTimeout(t *testing.T) {
	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{"http://w1"}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                1,
		PerWitnessTimeout:      0, // ← zero
		NetworkID:              testNetID(),
		HTTPClient:             testHeadSyncHTTPClient(),
	}, nil, silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}
	if hs == nil {
		t.Fatal("NewHeadSync returned nil HeadSync")
	}
	// PerWitnessTimeout zero is normalized to a default; we
	// can't read the field directly (unexported), but the
	// constructor accepting zero is itself the contract.
}

// TestNewHeadSync_AcceptsHTTPClient pins the mTLS wiring contract:
// HeadSyncConfig.HTTPClient is the injection point for an mTLS-equipped
// *http.Client (typically built from internal/clienttls). The constructor
// must accept a non-nil HTTPClient without error — the underlying cosign
// WitnessClients are built with cosign.WithHTTPClient(cfg.HTTPClient), so
// the supplied client's TLS posture (cert, root pool) flows through to every
// per-witness HTTPS hop. The round-trip behaviour itself is pinned by
// internal/clienttls's TestFlags_Client_RoundTrip — this test pins the seam.
func TestNewHeadSync_AcceptsHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 7 * time.Second}
	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{"http://w1"}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                1,
		PerWitnessTimeout:      5 * time.Second,
		NetworkID:              testNetID(),
		HTTPClient:             custom,
	}, nil, silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync with HTTPClient: %v", err)
	}
	if hs == nil {
		t.Fatal("NewHeadSync returned nil with HTTPClient set")
	}
}

// TestNewHeadSync_RejectsNilHTTPClient pins the v1.34 fail-closed
// contract: NewHeadSync refuses to manufacture a default *http.Client
// when the caller omits one. Replaces the pre-v1.34
// TestNewHeadSync_NilHTTPClient_UsesDefault which pinned the removed
// silent-fallback behavior. See baseproof v1.34 CHANGELOG.
func TestNewHeadSync_RejectsNilHTTPClient(t *testing.T) {
	_, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{"http://w1"}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                1,
		PerWitnessTimeout:      5 * time.Second,
		NetworkID:              testNetID(),
		HTTPClient:             nil,
	}, nil, silentLogger())
	if err == nil {
		t.Fatal("err = nil, want fail-closed on nil HTTPClient")
	}
	if !strings.Contains(err.Error(), "HTTPClient required") {
		t.Errorf("err = %v, want message mentioning HTTPClient required", err)
	}
}

func TestNewHeadSync_HappyPath(t *testing.T) {
	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{"http://w1", "http://w2", "http://w3"}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                2,
		PerWitnessTimeout:      5 * time.Second,
		NetworkID:              testNetID(),
		HTTPClient:             testHeadSyncHTTPClient(),
	}, nil, silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}
	if hs == nil {
		t.Fatal("NewHeadSync returned nil")
	}
	if hs.Collector() == nil {
		t.Fatal("Collector() is nil; downstream callers (escrow override, rotation) " +
			"depend on this being non-nil for purpose-flexible cosign")
	}
}

func TestRequestCosignatures_NilReceiver(t *testing.T) {
	// The pre-rc5 contract returned a zero CosignedTreeHead with a NIL error —
	// an in-band sentinel on the exact type whose zero fields the SDK rejects,
	// which is how a zero head could travel the publish path unnoticed. The
	// contract is typed now: nothing wired ⇒ builder.ErrNoCosigner, and a nil
	// error always implies a valid cosigned head.
	var hs *HeadSync
	_, err := hs.RequestCosignatures(context.Background(), types.TreeHead{TreeSize: 1})
	if !errors.Is(err, builder.ErrNoCosigner) {
		t.Errorf("nil receiver: got err %v, want builder.ErrNoCosigner (typed no-cosigner condition)", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// DSN-gated end-to-end tests
// ─────────────────────────────────────────────────────────────────

func TestRequestCosignatures_HappyPath_K1(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	srv := startWitnessServer(t, netID)

	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{srv.URL}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                1,
		PerWitnessTimeout:      2 * time.Second,
		NetworkID:              netID,
		HTTPClient:             testHeadSyncHTTPClient(),
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{
		TreeSize: 7777,
		RootHash: [32]byte{0x77},
		SMTRoot:  [32]byte{0x7A}, // non-zero: cosign Validate rejects all-zero SMTRoot
	}
	cosigned, err := hs.RequestCosignatures(ctx, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if cosigned.TreeSize != head.TreeSize {
		t.Errorf("returned head.TreeSize = %d, want %d", cosigned.TreeSize, head.TreeSize)
	}
	if len(cosigned.Signatures) != 1 {
		t.Errorf("len(Signatures) = %d, want 1 (K=1)", len(cosigned.Signatures))
	}

	// Persistence assertion: the head + signature row are present.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount != 1 {
		t.Errorf("persisted sig rows for tree_size=%d: %d, want 1", head.TreeSize, sigCount)
	}
}

func TestRequestCosignatures_QuorumFailure_WrapsErr(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	// Spin up two servers then close one before driving HeadSync.
	// K=2, N=2, Online=1 → ErrQuorumCollectionFailed.
	srvA := startWitnessServer(t, netID)
	srvB := startWitnessServer(t, netID)
	srvB.Close()

	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{srvA.URL, srvB.URL}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                2,
		PerWitnessTimeout:      1 * time.Second,
		NetworkID:              netID,
		HTTPClient:             testHeadSyncHTTPClient(),
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{TreeSize: 8888, RootHash: [32]byte{0x88}, SMTRoot: [32]byte{0x8A}}

	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = hs.RequestCosignatures(ctx2, head)
	if err == nil {
		t.Fatal("RequestCosignatures with K-of-N unmet: expected error, got nil")
	}
	if !errors.Is(err, cosign.ErrQuorumCollectionFailed) {
		t.Errorf("error chain missing ErrQuorumCollectionFailed: %v", err)
	}

	// No row should be persisted on quorum failure — the head/sig
	// inserts run only after Collect succeeds.
	var sigCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tree_head_sigs WHERE tree_size = $1`,
		head.TreeSize,
	).Scan(&sigCount); err != nil {
		t.Fatalf("query tree_head_sigs: %v", err)
	}
	if sigCount != 0 {
		t.Errorf("persisted %d sig rows on quorum failure; want 0 "+
			"(persistence must not run when Collect errs)", sigCount)
	}
}

func TestRequestCosignatures_ExactQuorum_3of5(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	const totalN, quorumK, online = 5, 3, 3

	srvs := make([]*httptest.Server, totalN)
	for i := range srvs {
		srvs[i] = startWitnessServer(t, netID)
	}
	for i := online; i < totalN; i++ {
		srvs[i].Close() // bring N-online offline
	}
	endpoints := make([]string, totalN)
	for i, s := range srvs {
		endpoints[i] = s.URL
	}

	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: endpoints},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                quorumK,
		PerWitnessTimeout:      1 * time.Second,
		NetworkID:              netID,
		HTTPClient:             testHeadSyncHTTPClient(),
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{TreeSize: 9999, RootHash: [32]byte{0x99}, SMTRoot: [32]byte{0x9A}}

	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cosigned, err := hs.RequestCosignatures(ctx2, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(cosigned.Signatures) < quorumK {
		t.Errorf("collected %d signatures, want >= K=%d (collector short-circuits at K)",
			len(cosigned.Signatures), quorumK)
	}
	if len(cosigned.Signatures) > totalN {
		t.Errorf("collected %d signatures, want <= N=%d", len(cosigned.Signatures), totalN)
	}
}

// ─────────────────────────────────────────────────────────────────
// ReceiptRoot binding (baseproof v1.9.x single 104-byte payload)
// ─────────────────────────────────────────────────────────────────

// TestRequestCosignatures_BindsReceiptRoot proves the witness
// cosignature commits ReceiptRoot. Since v1.9.x there is ONE cosign
// payload form (104-byte RootHash‖SMTRoot‖ReceiptRoot‖TreeSize), so
// RequestCosignatures always binds all three roots — there is no
// V1/V2 toggle. We verify the returned cosignature against the
// witness key set, then flip ReceiptRoot and confirm the valid-
// signature count drops to zero: the signature is over a canonical
// message that includes ReceiptRoot, so tampering invalidates it.
func TestRequestCosignatures_BindsReceiptRoot(t *testing.T) {
	pool := requireDSN(t)
	defer pool.Close()
	ctx := context.Background()
	resetTreeHeadTables(t, ctx, pool)

	netID := testNetID()
	srv, pub := startWitnessServerWithPub(t, netID)

	hs, err := NewHeadSync(HeadSyncConfig{
		EndpointResolver:       &fakeEndpointResolver{urls: []string{srv.URL}},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                1,
		PerWitnessTimeout:      2 * time.Second,
		NetworkID:              netID,
		HTTPClient:             testHeadSyncHTTPClient(),
	}, store.NewTreeHeadStore(pool), silentLogger())
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{
		TreeSize:    9002,
		RootHash:    [32]byte{0x90},
		SMTRoot:     [32]byte{0x91},
		ReceiptRoot: [32]byte{0x92},
	}
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cosigned, err := hs.RequestCosignatures(ctx2, head)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(cosigned.Signatures) < 1 {
		t.Fatalf("collected %d signatures, want >= 1", len(cosigned.Signatures))
	}

	keySet, err := cosign.NewWitnessKeySet([]types.WitnessPublicKey{pub}, netID, 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}

	// Sanity: the cosignature verifies against the head as signed.
	if got := cosign.VerifyTreeHeadCosignatures(cosigned, keySet); got < 1 {
		t.Fatalf("valid cosignatures over the signed head = %d, want >= 1", got)
	}

	// Binding proof: flip ReceiptRoot only. If the signature did not
	// commit ReceiptRoot, this tampered head would still verify.
	tampered := cosigned
	tampered.ReceiptRoot = [32]byte{0xEE}
	if got := cosign.VerifyTreeHeadCosignatures(tampered, keySet); got != 0 {
		t.Errorf("valid cosignatures over a ReceiptRoot-tampered head = %d, want 0 "+
			"— the witness signature does NOT bind ReceiptRoot", got)
	}
}
