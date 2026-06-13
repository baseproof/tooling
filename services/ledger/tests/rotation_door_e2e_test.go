/*
FILE PATH: tests/rotation_door_e2e_test.go

DESCRIPTION:

	PRE-6 A1 — the rotation ceremony's round-trip through the REAL DOOR:
	the first time ProcessRotation ever runs through its door under test.
	rotation_appender_e2e_test.go is the template (real checkpoint loop,
	real witness cosign over HTTP, real Postgres witness_sets); the delta
	here is the ENTRY POINT and the CEREMONY:

	  draft (the SDK constructor's inputs, current set = the live genesis
	  roster) → offline consents (ceremony.Endorse via rotationdraft — the
	  byte-identical online signing recipe) → finalize (the SDK coordinator
	  self-verifies) → POST /v1/network/rotation (api.NewRotationHandler
	  over the REAL witnessclient.RotationHandler) → real ProcessRotation
	  (full VerifyRotation against the live set, real on-log append under a
	  real cosigned covering head) → witness_sets FLIPS → the read doors
	  (/v1/network/witnesses/current, /at/{seq}, /{set_hash}) serve the new
	  era, with the genesis era retired but permanently addressable.

	The genesis baseline is seeded exactly as boot seeds it
	(SeedGenesisBaseline — derived from the trust root, never operator
	data), so the era transition is the production shape, not a fixture's.

	Negative pin at the same altitude: re-submitting the SAME finalized
	rotation after the flip is a stale ceremony — the door returns the
	processor's 422 and NOTHING is half-applied (row count, current set,
	and the in-memory keyset all unchanged).

	Gated on BASEPROOF_TEST_DSN (Postgres); skips otherwise.
*/
package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/libs/rotationdraft"
	"github.com/baseproof/tooling/services/ledger/api"
	opbuilder "github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/quorum"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// draftWireKey renders one SDK witness key as the rotation-draft wire shape.
func draftWireKey(k types.WitnessPublicKey) rotationdraft.Key {
	return rotationdraft.Key{
		IDHex:     hex.EncodeToString(k.ID[:]),
		PublicKey: hex.EncodeToString(k.PublicKey),
		SchemeTag: k.SchemeTag,
	}
}

func TestRotationDoor_E2E_CeremonyThroughTheRealDoorFlipsTheEra(t *testing.T) {
	pool := skipIfNoPostgres(t)
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Clean genesis for the loop's singletons (the template's reset).
	if _, err := pool.Exec(ctx, `UPDATE smt_root_state SET current_root=$1, committed_through_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset smt_root_state: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tile_frontier SET frontier_root=$1, frontier_seq=0 WHERE id=1`, smt.EmptyHash[:]); err != nil {
		t.Fatalf("reset tile_frontier: %v", err)
	}

	// ── The REAL pipeline under the door (the template's harness) ──
	leafStore := smt.NewInMemoryLeafStore()
	nodeStore := store.NewTailedNodeStore(smt.NewInMemoryNodeStore())
	tree := smt.NewTree(leafStore, nodeStore)
	tree.SetRoot(smt.EmptyHash)
	rootStore := store.NewSMTRootStateStore(pool)
	tileStore := store.NewPosixSMTTileStore(t.TempDir())

	netID := nonZeroTestNetworkID()
	fixture := newWitnessFixture(t, netID, 1) // the GENESIS witness (K=1)
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
	heads := store.NewTreeHeadStore(pool)

	const logDID = "did:web:ledger.rotation-door-e2e.test"
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
	// ONE manager, shared by the appender and the rotation handler — the
	// production topology (admission, equivocation, and rotation all read
	// the same Current()).
	mgr := quorum.NewManager(genesisSet)

	appender := witnessclient.NewProductionRotationAppender(
		ledgerKey, logDID, logDID, mgr,
		pipe, pipe, heads, merkle, logger,
	).WithPolling(10*time.Millisecond, 30*time.Second)

	// The REAL processor — the single witness_sets writer — and the REAL
	// door over it. Emitter nil = the gossip-disabled deployment shape.
	proc := witnessclient.NewRotationHandler(
		pool, mgr, witnessclient.GenesisCosignSchemeTag,
		"https://ledger.rotation-door-e2e.test", logger,
	).WithAppender(appender)

	// ── The LEDGER SURFACE: write door + read doors, as served ──
	fetcher := witnessclient.NewHistoryFetcher(pool)
	mux := http.NewServeMux()
	mux.Handle("POST /v1/network/rotation", api.NewRotationHandler(proc))
	mux.HandleFunc("GET /v1/network/witnesses/current", api.NewWitnessesCurrentHandler(fetcher))
	mux.HandleFunc("GET /v1/network/witnesses/at/{seq}", api.NewWitnessesAtSeqHandler(fetcher))
	mux.HandleFunc("GET /v1/network/witnesses/{set_hash}", api.NewWitnessesBySetHashHandler(fetcher))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Genesis baseline, seeded exactly as boot seeds it (derived from the
	// trust root). Before it: /current 404s. After it: the genesis era.
	seeded, err := witnessclient.SeedGenesisBaseline(ctx, pool, genesisSet, fixture.PublicKeys(), witnessclient.GenesisCosignSchemeTag)
	if err != nil || !seeded {
		t.Fatalf("SeedGenesisBaseline: seeded=%v err=%v", seeded, err)
	}
	genesisHash := genesisSet.SetHash()
	if got := fetchWitnessView(t, srv.URL+"/v1/network/witnesses/current"); got.SetHash != hex.EncodeToString(genesisHash[:]) {
		t.Fatalf("pre-rotation current = %s, want the genesis baseline %x", got.SetHash, genesisHash[:8])
	}

	// ── THE CEREMONY (production builders end to end) ──
	// The NEW witness's key is generated the way the fixture generates a
	// witness (uncompressed secp256k1; ID = sha256(pubkey bytes)).
	newPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	newSigner := cosign.NewECDSAWitnessSigner(newPriv)
	newKey := types.WitnessPublicKey{
		ID:        newSigner.PubKeyID(),
		PublicKey: signatures.PubKeyBytes(&newPriv.PublicKey),
		SchemeTag: signatures.SchemeECDSA,
	}

	draft := &rotationdraft.Draft{
		SchemaVersion: rotationdraft.DraftFormat,
		NetworkIDHex:  hex.EncodeToString(netID[:]),
		QuorumK:       1,
		CurrentSet:    []rotationdraft.Key{draftWireKey(fixture.PublicKeys()[0])},
		NewSet:        []rotationdraft.Key{draftWireKey(newKey)},
	}
	curConsent, err := draft.SignConsent(fixture.PrivateKeys()[0])
	if err != nil {
		t.Fatalf("current-witness consent: %v", err)
	}
	newConsent, err := draft.SignConsent(newPriv)
	if err != nil {
		t.Fatalf("new-witness consent: %v", err)
	}
	rotation, err := draft.Finalize([]*rotationdraft.Consent{newConsent, curConsent})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	payload, err := witness.EncodeWitnessRotationPayload(rotation)
	if err != nil {
		t.Fatalf("encode rotation payload: %v", err)
	}

	// Drive the production checkpoint loop concurrently — the door's POST
	// blocks across the real on-log append + witness cosign round.
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
	resp, err := http.Post(srv.URL+"/v1/network/rotation", "application/json", bytes.NewReader(payload))
	stopDriving()
	<-driverDone
	if err != nil {
		t.Fatalf("POST rotation: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	select {
	case lerr := <-loopErrs:
		t.Fatalf("the production loop faulted while driving: %v", lerr)
	default:
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("door = HTTP %d, want 202: %s", resp.StatusCode, body)
	}
	var verdict struct {
		Applied         bool `json:"applied"`
		NewWitnessCount int  `json:"new_witness_count"`
	}
	if err := json.Unmarshal(body, &verdict); err != nil || !verdict.Applied || verdict.NewWitnessCount != 1 {
		t.Fatalf("door verdict = %s (err=%v)", body, err)
	}

	// ── THE ERA FLIPS, OBSERVED THROUGH THE READ DOORS ──
	newSet, err := cosign.NewWitnessKeySet([]types.WitnessPublicKey{newKey}, netID, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	newHash := newSet.SetHash()

	current := fetchWitnessView(t, srv.URL+"/v1/network/witnesses/current")
	if current.SetHash != hex.EncodeToString(newHash[:]) {
		t.Fatalf("post-rotation current = %s, want the NEW era %x", current.SetHash, newHash[:8])
	}
	if len(current.Keys) != 1 || current.Keys[0].ID != hex.EncodeToString(newKey.ID[:]) {
		t.Fatalf("the served current roster is not the new set: %+v", current.Keys)
	}

	atView := fetchWitnessView(t, fmt.Sprintf("%s/v1/network/witnesses/at/%d", srv.URL, current.EffectiveSeq))
	if atView.SetHash != hex.EncodeToString(newHash[:]) {
		t.Fatalf("/at/%d = %s, want the new era", current.EffectiveSeq, atView.SetHash)
	}

	// The genesis era is RETIRED, never erased: permanently addressable by
	// its content hash, stamped with the rotation's effective seq.
	genView := fetchWitnessView(t, srv.URL+"/v1/network/witnesses/"+hex.EncodeToString(genesisHash[:]))
	if genView.RetiredSeq == nil || *genView.RetiredSeq != current.EffectiveSeq {
		t.Fatalf("genesis row retired_seq = %v, want %d", genView.RetiredSeq, current.EffectiveSeq)
	}

	// The in-memory swap is observed by every consumer of the manager.
	if liveHash := mgr.Current().SetHash(); liveHash != newHash {
		t.Fatalf("in-memory keyset = %x, want the new era %x", liveHash[:8], newHash[:8])
	}

	// ── NEGATIVE PIN: a stale re-submit is 422 and nothing half-applies ──
	var rowsBefore int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM witness_sets`).Scan(&rowsBefore); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.Post(srv.URL+"/v1/network/rotation", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("stale POST: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("stale re-submit = HTTP %d, want 422: %s", resp2.StatusCode, body2)
	}
	var rowsAfter int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM witness_sets`).Scan(&rowsAfter); err != nil {
		t.Fatal(err)
	}
	if rowsAfter != rowsBefore {
		t.Fatalf("a rejected rotation wrote rows: %d → %d", rowsBefore, rowsAfter)
	}
	if liveHash := mgr.Current().SetHash(); liveHash != newHash {
		t.Fatal("a rejected rotation mutated the in-memory keyset")
	}
	stillCurrent := fetchWitnessView(t, srv.URL+"/v1/network/witnesses/current")
	if stillCurrent.SetHash != hex.EncodeToString(newHash[:]) {
		t.Fatal("a rejected rotation changed the served current era")
	}
}

// fetchWitnessView GETs one /v1/network/witnesses/* endpoint and decodes the
// served view, failing the test on any non-200.
func fetchWitnessView(t *testing.T, url string) api.WitnessSetView {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = HTTP %d: %s", url, resp.StatusCode, body)
	}
	var view api.WitnessSetView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
	return view
}
