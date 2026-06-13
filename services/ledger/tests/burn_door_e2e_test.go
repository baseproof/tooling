/*
FILE PATH: tests/burn_door_e2e_test.go

tooling#110 Category-B: the burn ceremony through the REAL door, end to end.
A quorum-signed NetworkBurn → POST /v1/network/burn (api.NewBurnDoorHandler
over the REAL witnessclient.BurnProcessor + ProductionBurnAppender) → real
on-log append through the production checkpoint loop → GET /v1/burn flips
is_burned=true (the declared leg, authoritative). The W1 kill-switch half (an
unauthorized burn POSTed to /v1/entries changes nothing) is proven at unit
altitude by admission.TestVerifyNetworkPayloadEntry_RC10_Burn_AuthorshipGate.

Mirrors rotation_door_e2e_test.go's harness verbatim — the same real
pipeline (WAL → sequencer → Tessera → witness cosign), reusing its package
helpers. Gated on BASEPROOF_TEST_DSN (Postgres); skips otherwise — no Docker.
*/
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/api"
	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

func TestBurnDoor_E2E_QuorumBurnThroughTheRealDoorFlipsV1Burn(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if _, err := pool.Exec(ctx, `UPDATE smt_root_state SET current_root=$1, committed_through_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tile_frontier SET frontier_root=$1, frontier_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset tile_frontier: %v", err)
	}

	// ── The REAL pipeline under the door (rotation_door_e2e's harness) ──
	leafStore := smt.NewInMemoryLeafStore()
	nodeStore := store.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	tree.SetRoot(smt.EmptyHash)
	rootStore := store.NewSMTRootStateStore(pool)
	tileStore := store.NewPosixSMTTileStore(t.TempDir())
	netID := nonZeroTestNetworkID()
	fixture := newWitnessFixture(t, netID, 1) // GENESIS witness, K=1
	headSync, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		EndpointResolver:       staticEndpointResolver{urls: fixture.URLs()},
		EndpointResolverLogDID: "did:test:log",
		QuorumK:                1,
		PerWitnessTimeout:      2 * time.Second,
		NetworkID:              netID,
		HTTPClient:             newTunedHTTPClient(2 * time.Second),
	}, store.NewTreeHeadStore(pool), logger)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}
	merkle := &singleLeafMerkle{}
	recorder := &horizonRecorder{}
	loop := opbuilder.NewCheckpointLoop(
		store.NewSMTCommitCursor(rootStore),
		store.NewPgTileFrontier(pool),
		store.NewBuildTilesEmitter(nodeStore, tileStore),
		merkle, recorder, headSync, nil, 0, logger,
	)
	const logDID = "did:web:ledger.burn-door-e2e.test"
	pipe := &checkpointDrivenPipeline{
		pool: pool, tree: tree, merkle: merkle,
		logDID: logDID, seqByID: map[[32]byte]uint64{},
	}
	ledgerKey, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	genesisSet, err := cosign.NewWitnessKeySet(fixture.PublicKeys(), netID, 1, nil)
	if err != nil {
		t.Fatalf("NewWitnessKeySet: %v", err)
	}
	mgr := quorum.NewManager(genesisSet)
	// The REAL burn appender (subset of the rotation appender: no proof) and
	// the REAL processor + door over it. QuorumManager.Current() is the
	// CurrentSetSource the quorum verifies against.
	burnAppender := witnessclient.NewProductionBurnAppender(
		ledgerKey, logDID, logDID, pipe, pipe, logger,
	).WithPolling(10*time.Millisecond, 30*time.Second)
	proc := witnessclient.NewBurnProcessor(mgr, burnAppender)

	mux := http.NewServeMux()
	mux.Handle("POST /v1/network/burn", api.NewBurnDoorHandler(proc, logger))
	mux.HandleFunc("GET /v1/burn", api.NewBurnHandlerWithDeclared(nil, proc, logDID, logger))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Pre-burn: /v1/burn reports not burned.
	if isBurned(t, srv.URL+"/v1/burn") {
		t.Fatal("pre-burn: /v1/burn must report not burned")
	}

	// ── Mint the quorum-signed burn (K=1, the genesis witness) ──
	b := network.NetworkBurn{NetworkID: [32]byte(netID), ReasonClass: "witness_quorum_compromise"}
	bp := cosign.NewBurnPayloadSHA256(network.BurnContentDigest(b))
	sig, err := cosign.SignECDSA(bp, netID, cosign.HashAlgoSHA256, fixture.PrivateKeys()[0])
	if err != nil {
		t.Fatalf("sign burn: %v", err)
	}
	b.Signatures = []types.WitnessSignature{{
		PubKeyID: fixture.PublicKeys()[0].ID, SchemeTag: signatures.SchemeECDSA, SigBytes: sig,
	}}
	if err := network.VerifyBurn(b, genesisSet); err != nil {
		t.Fatalf("fixture burn must verify under the genesis set: %v", err)
	}
	payload, err := network.EncodeNetworkBurnPayload(b)
	if err != nil {
		t.Fatalf("encode burn: %v", err)
	}

	// Drive the production checkpoint loop while the POST blocks on the
	// real on-log append.
	driveCtx, stopDriving := context.WithCancel(ctx)
	defer stopDriving()
	loopErrs := make(chan error, 16)
	driverDone := make(chan struct{})
	go func() {
		defer close(driverDone)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-driveCtx.Done():
				return
			case <-tick.C:
				if err := loop.CheckpointOnce(driveCtx); err != nil && !errors.Is(err, context.Canceled) {
					select {
					case loopErrs <- err:
					default:
					}
				}
			}
		}
	}()

	// ── SUBMIT THROUGH THE REAL DOOR ──
	resp, err := http.Post(srv.URL+"/v1/network/burn", "application/json", bytes.NewReader(payload))
	stopDriving()
	<-driverDone
	if err != nil {
		t.Fatalf("POST burn: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	select {
	case lerr := <-loopErrs:
		t.Fatalf("the production loop faulted while driving: %v", lerr)
	default:
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("burn door = HTTP %d, want 202: %s", resp.StatusCode, body)
	}

	// ── /v1/burn FLIPS, through the declared (authoritative) leg ──
	if !isBurned(t, srv.URL+"/v1/burn") {
		t.Fatal("post-burn: /v1/burn must report is_burned=true (declared leg)")
	}

	// Terminal: a second burn is refused 409 (burn is monotonic).
	resp2, err := http.Post(srv.URL+"/v1/network/burn", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("a second burn must be 409 (terminal), got %d", resp2.StatusCode)
	}
}

// isBurned GETs /v1/burn and returns its is_burned bool.
func isBurned(t *testing.T, url string) bool {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /v1/burn: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/burn = HTTP %d", resp.StatusCode)
	}
	var v struct {
		IsBurned bool `json:"is_burned"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode /v1/burn: %v", err)
	}
	return v.IsBurned
}
