package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkgossip "github.com/baseproof/baseproof/gossip"
)

// ── handler: response shape + status mapping ────────────────────────────────

type fakeBurnSource struct {
	burned bool
	err    error
}

func (f fakeBurnSource) IsBurned(context.Context, string) (bool, error) { return f.burned, f.err }

func callBurn(t *testing.T, src BurnSource) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	NewBurnHandler(src, "did:web:me.example", nil)(rec, httptest.NewRequest(http.MethodGet, "/v1/burn", nil))
	return rec
}

func decodeBurn(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		IsBurned bool `json:"is_burned"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body.IsBurned
}

func TestBurnHandler_NotBurned(t *testing.T) {
	if decodeBurn(t, callBurn(t, fakeBurnSource{burned: false})) {
		t.Error("want is_burned=false")
	}
}

func TestBurnHandler_Burned(t *testing.T) {
	if !decodeBurn(t, callBurn(t, fakeBurnSource{burned: true})) {
		t.Error("want is_burned=true")
	}
}

// A source error is a 503 (status unknown) — NOT a silent is_burned=false (which
// would let a producer mint a clean proof when the truth is unavailable).
func TestBurnHandler_SourceError503(t *testing.T) {
	rec := callBurn(t, fakeBurnSource{err: errors.New("store down")})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// A nil source (gossip disabled) honestly reports not-burned.
func TestBurnHandler_NilSource(t *testing.T) {
	if decodeBurn(t, callBurn(t, nil)) {
		t.Error("nil source must report is_burned=false")
	}
}

// ── GossipBurnSource: equivocation-finding detection over the store ─────────

// fakeStore is a minimal sdkgossip.Store; only Iterate is exercised (kind-filtered).
type fakeStore struct{ events []sdkgossip.SignedEvent }

func (f *fakeStore) Iterate(_ context.Context, flt sdkgossip.Filter, fn func(sdkgossip.SignedEvent) error) error {
	for _, ev := range f.events {
		if flt.Kind != nil && ev.Kind != *flt.Kind {
			continue
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
	return nil
}
func (f *fakeStore) Append(context.Context, sdkgossip.SignedEvent) error { return nil }
func (f *fakeStore) Head(context.Context, string) ([32]byte, uint64, error) {
	return [32]byte{}, 0, nil
}
func (f *fakeStore) Get(context.Context, [32]byte) (sdkgossip.SignedEvent, error) {
	return sdkgossip.SignedEvent{}, nil
}
func (f *fakeStore) Stats(context.Context) (sdkgossip.StoreStats, error) {
	return sdkgossip.StoreStats{}, nil
}
func (f *fakeStore) Close(context.Context) error { return nil }
func (f *fakeStore) IterSince(context.Context, sdkgossip.IterCursor, int) ([]sdkgossip.SignedEvent, sdkgossip.IterCursor, error) {
	var zero sdkgossip.IterCursor
	return nil, zero, nil
}
func (f *fakeStore) LatestSTH(context.Context, string) (sdkgossip.SignedEvent, bool, error) {
	return sdkgossip.SignedEvent{}, false, nil
}

// equivEvent builds a stored KindEquivocationFinding event targeting `target`
// (round-trips through DecodeWireBody, the same decode the source uses).
func equivEvent(t *testing.T, target string) sdkgossip.SignedEvent {
	t.Helper()
	body, err := json.Marshal(sdkgossip.WireEquivocationFinding{TargetLogDID: target})
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	return sdkgossip.SignedEvent{Kind: sdkgossip.KindEquivocationFinding, Body: body}
}

func TestGossipBurnSource_BurnedWhenTargeted(t *testing.T) {
	store := &fakeStore{events: []sdkgossip.SignedEvent{
		equivEvent(t, "did:web:other.example"),
		equivEvent(t, "did:web:me.example"), // a finding naming THIS log
	}}
	burned, err := NewGossipBurnSource(store).IsBurned(context.Background(), "did:web:me.example")
	if err != nil || !burned {
		t.Fatalf("want burned, got %v (err %v)", burned, err)
	}
}

func TestGossipBurnSource_NotBurnedForOtherLog(t *testing.T) {
	store := &fakeStore{events: []sdkgossip.SignedEvent{equivEvent(t, "did:web:other.example")}}
	burned, err := NewGossipBurnSource(store).IsBurned(context.Background(), "did:web:me.example")
	if err != nil || burned {
		t.Fatalf("a finding against another log must not burn me: got %v (err %v)", burned, err)
	}
}

func TestGossipBurnSource_EmptyAndNil(t *testing.T) {
	if b, _ := NewGossipBurnSource(&fakeStore{}).IsBurned(context.Background(), "did:web:me.example"); b {
		t.Error("empty store ⇒ not burned")
	}
	if b, _ := NewGossipBurnSource(nil).IsBurned(context.Background(), "did:web:me.example"); b {
		t.Error("nil store ⇒ not burned")
	}
}
