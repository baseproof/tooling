package reservation_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/baseproof/baseproof/crypto/artifact"
	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
	"github.com/baseproof/tooling/services/ledger/reservation"
)

// harness wires the Manager against the in-memory fakes + a fake clock, so the
// whole lifecycle is deterministic and DB-free.
type harness struct {
	mgr     *reservation.Manager
	store   *reservation.MemoryStore
	content *storage.InMemoryContentStore
	pub     ed25519.PublicKey
	clk     time.Time
}

func newHarness(t *testing.T, validator artifact.ContentValidator) *harness {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := &harness{
		store:   reservation.NewMemoryStore(),
		content: storage.NewInMemoryContentStore(),
		pub:     pub,
		clk:     time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
	}
	h.mgr = reservation.NewManager(reservation.Config{
		Store: h.store, Content: h.content, Validator: validator,
		SignKey: priv, NetworkID: "netA", TTL: 10 * time.Minute,
		Now: func() time.Time { return h.clk },
	})
	return h
}

// reserve stages a reservation for the given bytes (keyed by their CID) and
// returns the CID + the upload token.
func (h *harness) reserve(t *testing.T, data []byte, mime string) (storage.CID, string) {
	t.Helper()
	cid := storage.Compute(data)
	tok, err := h.mgr.Reserve(context.Background(), reservation.ReserveRequest{
		ContentDigest: cid.String(), ArtifactCID: cid.String(),
		MIMEType: mime, MaxSize: 1 << 20, Owner: "did:court:5",
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	return cid, tok
}

func TestManager_ReserveIssuesValidToken(t *testing.T) {
	h := newHarness(t, nil)
	data := []byte("exhibit bytes")
	cid, tok := h.reserve(t, data, "")

	parsed, err := artifactstore.ParseAndVerifyUploadToken(tok, h.pub)
	if err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
	if parsed.ArtifactCID != cid.String() || parsed.NetworkID != "netA" {
		t.Fatalf("token fields: %+v", parsed)
	}
	r, err := h.store.Get(context.Background(), cid.String())
	if err != nil || r.Status != reservation.StatusPendingUpload {
		t.Fatalf("reservation not PENDING: %+v err=%v", r, err)
	}
}

func TestManager_ReserveDuplicateIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	data := []byte("same bytes, same cid")
	cid, _ := h.reserve(t, data, "") // first reservation
	// A second reservation for the same content address collides on the key.
	_, err := h.mgr.Reserve(context.Background(), reservation.ReserveRequest{
		ArtifactCID: cid.String(), MaxSize: 1 << 20, Owner: "did:court:5",
	})
	if !errors.Is(err, reservation.ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}
}

func TestManager_FinishSuccess(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	data := []byte("the uploaded artifact")
	cid, _ := h.reserve(t, data, "")
	// Upload lands in the store.
	if err := h.content.Push(ctx, cid, data); err != nil {
		t.Fatal(err)
	}
	r, err := h.mgr.Finish(ctx, cid.String())
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if r.Status != reservation.StatusCommitted {
		t.Fatalf("status = %s, want committed", r.Status)
	}
}

func TestManager_FinishIncomplete(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	cid, _ := h.reserve(t, []byte("never uploaded"), "")
	// Bytes absent.
	if _, err := h.mgr.Finish(ctx, cid.String()); !errors.Is(err, reservation.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	r, _ := h.store.Get(ctx, cid.String())
	if r.Status != reservation.StatusPendingUpload {
		t.Fatalf("status = %s, want still pending (no commit on incomplete)", r.Status)
	}
}

func TestManager_FinishRejectsBadMIME(t *testing.T) {
	// The validator is the SDK mechanism, built from deployment config (accepted
	// types + deny-unknown) — no on-log policy, just verification code.
	reg := artifact.BuildRegistry([]string{"application/pdf"}, true)
	h := newHarness(t, reg)
	ctx := context.Background()

	notPDF := []byte("this is not a pdf")
	cid, _ := h.reserve(t, notPDF, "application/pdf")
	if err := h.content.Push(ctx, cid, notPDF); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Finish(ctx, cid.String()); !errors.Is(err, reservation.ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
	r, _ := h.store.Get(ctx, cid.String())
	if r.Status != reservation.StatusRejected {
		t.Fatalf("status = %s, want rejected (never committed)", r.Status)
	}
}

func TestManager_FinishAcceptsGoodMIME(t *testing.T) {
	reg := artifact.BuildRegistry([]string{"application/pdf"}, true)
	h := newHarness(t, reg)
	ctx := context.Background()

	pdf := []byte("%PDF-1.7\nbody")
	cid, _ := h.reserve(t, pdf, "application/pdf")
	if err := h.content.Push(ctx, cid, pdf); err != nil {
		t.Fatal(err)
	}
	if r, err := h.mgr.Finish(ctx, cid.String()); err != nil || r.Status != reservation.StatusCommitted {
		t.Fatalf("valid PDF should commit: status=%s err=%v", r.Status, err)
	}
}

func TestManager_FinishIdempotent(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	data := []byte("commit me once")
	cid, _ := h.reserve(t, data, "")
	_ = h.content.Push(ctx, cid, data)
	if _, err := h.mgr.Finish(ctx, cid.String()); err != nil {
		t.Fatalf("first finish: %v", err)
	}
	r, err := h.mgr.Finish(ctx, cid.String()) // again
	if err != nil {
		t.Fatalf("second finish should be a no-op, got %v", err)
	}
	if r.Status != reservation.StatusCommitted {
		t.Fatalf("status = %s", r.Status)
	}
}

func TestManager_ReapExpiresAndGCs(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	data := []byte("abandoned")
	cid, _ := h.reserve(t, data, "")
	_ = h.content.Push(ctx, cid, data) // bytes staged but never finished

	// Before expiry: nothing to reap.
	if n, _ := h.mgr.Reap(ctx, 100); n != 0 {
		t.Fatalf("pre-expiry reap = %d, want 0", n)
	}
	// Advance past the 10m TTL.
	h.clk = h.clk.Add(11 * time.Minute)
	n, err := h.mgr.Reap(ctx, 100)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if n != 1 {
		t.Fatalf("reaped = %d, want 1", n)
	}
	r, _ := h.store.Get(ctx, cid.String())
	if r.Status != reservation.StatusExpired {
		t.Fatalf("status = %s, want expired", r.Status)
	}
	// Staged bytes GC'd.
	if ok, _ := h.content.Exists(ctx, cid); ok {
		t.Fatalf("staged bytes not GC'd after reap")
	}
}

// No commit-after-expire: once reaped, FINISH cannot resurrect the reservation.
func TestManager_FinishAfterExpireFails(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	data := []byte("too late")
	cid, _ := h.reserve(t, data, "")
	_ = h.content.Push(ctx, cid, data)

	h.clk = h.clk.Add(11 * time.Minute)
	if _, err := h.mgr.Reap(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Finish(ctx, cid.String()); err == nil {
		t.Fatal("finish after expire should fail (no commit-after-expire)")
	}
	r, _ := h.store.Get(ctx, cid.String())
	if r.Status != reservation.StatusExpired {
		t.Fatalf("status = %s, want expired", r.Status)
	}
}
