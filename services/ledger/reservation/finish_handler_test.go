package reservation_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/reservation"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

func TestFinishHandler(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/artifacts/{cid}/finish", reservation.NewFinishHandler(h.mgr))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	post := func(cid string) int {
		resp, err := ts.Client().Post(ts.URL+"/v1/artifacts/"+cid+"/finish", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// committed (bytes present), then idempotent.
	data := []byte("finish me")
	cid, _ := h.reserve(t, data, "")
	if err := h.content.Push(ctx, cid, data); err != nil {
		t.Fatal(err)
	}
	if code := post(cid.String()); code != http.StatusOK {
		t.Fatalf("finish present: got %d want 200", code)
	}
	if code := post(cid.String()); code != http.StatusOK {
		t.Fatalf("idempotent finish: got %d want 200", code)
	}

	// not found (a valid CID string that was never reserved)
	absent := storage.Compute([]byte("never reserved")).String()
	if code := post(absent); code != http.StatusNotFound {
		t.Fatalf("absent: got %d want 404", code)
	}

	// incomplete (reserved, bytes never uploaded)
	cid2, _ := h.reserve(t, []byte("never uploaded"), "")
	if code := post(cid2.String()); code != http.StatusConflict {
		t.Fatalf("incomplete: got %d want 409", code)
	}
}

func TestReaper_Run(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	data := []byte("abandoned")
	cid, _ := h.reserve(t, data, "")
	_ = h.content.Push(ctx, cid, data)
	// Advance the (injected) clock so the reservation is expired before the
	// reaper starts; the closure is set once, before the goroutine launches.
	h.clk = h.clk.Add(11 * time.Minute)

	r := reservation.NewReaper(h.mgr, time.Millisecond, 100, discardLogger())
	go r.Run(ctx)

	waitFor(t, time.Second, func() bool {
		got, _ := h.store.Get(ctx, cid.String())
		return got.Status == reservation.StatusExpired
	})
}
