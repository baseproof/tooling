/*
FILE PATH: witnessclient/head_sync_boundary_test.go

The cosigner-boundary contract (tier T1 — no Postgres, no daemons):
RequestCosignatures is the public seam every head crosses on its way to the
witness fleet, so it must reject AT CONSTRUCTION what witnesses would reject
at signature — and report each refusal in the typed class the checkpoint
loop's two-class (fault vs hold) contract branches on. The incident these
pin: a harness-built Merkle-only head (all-zero SMTRoot) burned a full
K-of-N round-trip and surfaced as an opaque transient quorum failure.
*/
package witnessclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/builder"
	"github.com/baseproof/tooling/services/ledger/store"
	"github.com/baseproof/tooling/services/ledger/witnessclient"
)

// TestRequestCosignatures_RefusesInvalidHeadBeforeFanOut [S2]: a head that
// fails the SDK's payload validation (all-zero SMTRoot — the dual-commitment
// guard) is refused LOCALLY: the typed cosign.ErrInvalidPayload class
// surfaces, no witness endpoint is ever contacted, and nothing is persisted
// (the TreeHeadStore rides a nil pool — reaching persistence would panic, so
// a clean typed error doubles as the never-reached proof).
func TestRequestCosignatures_RefusesInvalidHeadBeforeFanOut(t *testing.T) {
	var hits atomic.Int64
	witness := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer witness.Close()

	hs, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		WitnessEndpoints:  []string{witness.URL},
		QuorumK:           1,
		PerWitnessTimeout: time.Second,
		NetworkID:         historyNetID(),
		HTTPClient:        &http.Client{Timeout: time.Second},
	}, store.NewTreeHeadStore(nil), nil)
	if err != nil {
		t.Fatalf("NewHeadSync: %v", err)
	}

	head := types.TreeHead{
		TreeSize: 1,
		RootHash: [32]byte{0xAA, 0x01}, // populated Merkle half
		// SMTRoot deliberately all-zero: the harness-incident shape.
	}
	_, err = hs.RequestCosignatures(context.Background(), head)
	if !errors.Is(err, cosign.ErrInvalidPayload) {
		t.Fatalf("want the deterministic cosign.ErrInvalidPayload class, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("invalid head fanned out to the witness %d time(s); the seam must refuse before any round-trip", n)
	}
}

// TestRequestCosignatures_NoCollectorIsTyped [S3]: "nothing wired" is the
// typed builder.ErrNoCosigner condition — never a zero-valued CosignedTreeHead
// with a nil error (the in-band sentinel that let zero heads travel).
func TestRequestCosignatures_NoCollectorIsTyped(t *testing.T) {
	var hs *witnessclient.HeadSync // nil receiver: the read-only / trimmed-rig shape
	_, err := hs.RequestCosignatures(context.Background(), types.TreeHead{TreeSize: 1})
	if !errors.Is(err, builder.ErrNoCosigner) {
		t.Fatalf("nil HeadSync: want builder.ErrNoCosigner, got %v", err)
	}
}

// TestNewHeadSync_ResolverWithoutLogDIDRefused [F2]: wiring the on-log
// endpoint resolver without a log DID is a construction error — previously it
// silently disabled discovery and fell back to the legacy config canary (the
// silent-URL-substitution posture the resolver exists to close), surfacing
// only as a log line at collect time.
func TestNewHeadSync_ResolverWithoutLogDIDRefused(t *testing.T) {
	_, err := witnessclient.NewHeadSync(witnessclient.HeadSyncConfig{
		EndpointResolver:  staticResolver{},
		WitnessEndpoints:  []string{"https://witness.example"}, // canary present — must NOT mask the error
		QuorumK:           1,
		PerWitnessTimeout: time.Second,
		NetworkID:         historyNetID(),
		HTTPClient:        &http.Client{Timeout: time.Second},
	}, store.NewTreeHeadStore(nil), nil)
	if err == nil {
		t.Fatal("a wired resolver with an empty EndpointResolverLogDID must refuse construction")
	}
}

type staticResolver struct{}

func (staticResolver) WitnessEndpoints(context.Context, string) ([]string, error) {
	return []string{"https://resolved.example"}, nil
}
