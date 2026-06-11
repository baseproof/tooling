/*
FILE PATH: witnessclient/rotation_era_http_test.go

[C6] The era-boundary served-history contract — the ONE test that joins the
genesis-baseline work (SeedGenesisBaseline, #71) to the rc4+ rotation rules
(witnesstest-minted, Step-6-consented, 2K>N) END TO END over the real HTTP
handlers (tier T2: real Postgres, real HistoryFetcher, real api handlers; no
daemon). After a genesis baseline and one consented rotation effective at E:

	/v1/network/witnesses/at/{E-1} → the GENESIS set
	/v1/network/witnesses/at/{E}   → the NEW set (effective_seq inclusive)
	/v1/network/witnesses/current  → the NEW set
	the genesis row's retired_seq == E (the era boundary is recorded)
*/
package witnessclient_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/services/ledger/api"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

func TestRotationEraBoundary_ServedHistory(t *testing.T) {
	t.Parallel()
	pool := requireWitnessDSN(t)
	ctx := context.Background()

	// Era 0: the genesis baseline, exactly as boot seeds it.
	rh, genesis := withHandler(t, pool, 2, 3)
	recorded, err := witnessclient.SeedGenesisBaseline(ctx, pool, genesis.KeySet, genesis.Keys, 0x01)
	if err != nil || !recorded {
		t.Fatalf("SeedGenesisBaseline: recorded=%v err=%v", recorded, err)
	}
	genHash := genesis.KeySet.SetHash()

	// Era 1: a kit-minted (consented, 2K>N) rotation committed at E.
	const e = uint64(42)
	rh.WithAppender(fakeRotationAppender{logDID: "did:web:ledger.test", seq: e})
	next := witnesstest.NewSet(t, historyNetID(), 3, 2)
	if _, err := rh.ProcessRotation(ctx, witnesstest.MintRotation(t, historyNetID(), genesis, next, 2)); err != nil {
		t.Fatalf("ProcessRotation: %v", err)
	}
	newHash := next.KeySet.SetHash()

	// The served surface: the REAL fetcher behind the REAL handlers.
	fetcher := witnessclient.NewHistoryFetcher(pool)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/network/witnesses/current", api.NewWitnessesCurrentHandler(fetcher))
	mux.HandleFunc("GET /v1/network/witnesses/at/{seq}", api.NewWitnessesAtSeqHandler(fetcher))

	get := func(path string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200 (body=%s)", path, rec.Code, rec.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("GET %s decode: %v", path, err)
		}
		return v
	}

	// /at/{E-1}: the genesis era, with its recorded retirement AT the boundary.
	atPrev := get("/v1/network/witnesses/at/41")
	if got := atPrev["set_hash"]; got != hex.EncodeToString(genHash[:]) {
		t.Fatalf("/at/%d set_hash = %v, want the GENESIS set %x", e-1, got, genHash[:8])
	}
	if got, ok := atPrev["retired_seq"].(float64); !ok || uint64(got) != e {
		t.Fatalf("genesis row retired_seq = %v, want %d (the era boundary)", atPrev["retired_seq"], e)
	}

	// /at/{E}: effective_seq is inclusive — the NEW set owns E itself.
	atE := get("/v1/network/witnesses/at/42")
	if got := atE["set_hash"]; got != hex.EncodeToString(newHash[:]) {
		t.Fatalf("/at/%d set_hash = %v, want the NEW set %x", e, got, newHash[:8])
	}

	// /current: the new era is live.
	cur := get("/v1/network/witnesses/current")
	if got := cur["set_hash"]; got != hex.EncodeToString(newHash[:]) {
		t.Fatalf("/current set_hash = %v, want the NEW set %x", got, newHash[:8])
	}
	if cur["retired_seq"] != nil {
		t.Fatalf("/current retired_seq = %v, want null (active)", cur["retired_seq"])
	}
}
