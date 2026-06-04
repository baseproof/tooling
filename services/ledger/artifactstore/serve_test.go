package artifactstore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/artifactstore"
)

func testServer(t *testing.T, opts ...artifactstore.Option) *httptest.Server {
	t.Helper()
	store := artifactstore.NewStore(artifactstore.NewMemoryBackend())
	srv := artifactstore.NewServer(store, slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// TestServer_HTTPContentStoreRoundTrip is the in-process<->service flip proof:
// the SDK's HTTPContentStore CLIENT drives the full lifecycle against our SERVER.
func TestServer_HTTPContentStoreRoundTrip(t *testing.T) {
	ts := testServer(t)
	ctx := context.Background()

	client, err := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{
		BaseURL: ts.URL,
		Client:  ts.Client(),
	})
	if err != nil {
		t.Fatalf("NewHTTPContentStore: %v", err)
	}

	data := []byte("hello service mode")
	cid := storage.Compute(data)

	if ok, err := client.Exists(ctx, cid); err != nil || ok {
		t.Fatalf("Exists before push: ok=%v err=%v", ok, err)
	}
	if err := client.Push(ctx, cid, data); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if ok, err := client.Exists(ctx, cid); err != nil || !ok {
		t.Fatalf("Exists after push: ok=%v err=%v", ok, err)
	}
	got, err := client.Fetch(ctx, cid) // HTTPContentStore verifies-on-read
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch")
	}
	if err := client.Pin(ctx, cid); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if err := client.Delete(ctx, cid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if ok, _ := client.Exists(ctx, cid); ok {
		t.Fatalf("Exists after delete should be false")
	}
}

func upload(t *testing.T, ts *httptest.Server, cid storage.CID, data []byte, mime, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/artifacts", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Artifact-CID", cid.String())
	if mime != "" {
		req.Header.Set("X-Artifact-MIME", mime)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestServer_UploadToken exercises the Phase-4 accounting boundary.
func TestServer_UploadToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ts := testServer(t, artifactstore.WithUploadVerification(pub, "netA"))

	data := []byte("accounted upload")
	cid := storage.Compute(data)
	mkTok := func(t artifactstore.UploadToken) string {
		s, err := artifactstore.SignUploadToken(t, priv)
		if err != nil {
			panic(err)
		}
		return s
	}
	valid := artifactstore.UploadToken{
		NetworkID: "netA", ArtifactCID: cid.String(), MaxSize: 1 << 20,
		ExpiresAt: time.Now().Add(time.Minute).UnixMicro(),
	}

	if code := upload(t, ts, cid, data, "", mkTok(valid)); code != http.StatusCreated {
		t.Fatalf("valid token: got %d want 201", code)
	}
	if code := upload(t, ts, cid, data, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d want 401", code)
	}
	expired := valid
	expired.ExpiresAt = time.Now().Add(-time.Minute).UnixMicro()
	if code := upload(t, ts, cid, data, "", mkTok(expired)); code != http.StatusUnauthorized {
		t.Fatalf("expired token: got %d want 401", code)
	}
	wrongCID := valid
	wrongCID.ArtifactCID = storage.Compute([]byte("other")).String()
	if code := upload(t, ts, cid, data, "", mkTok(wrongCID)); code != http.StatusForbidden {
		t.Fatalf("wrong-CID token: got %d want 403", code)
	}
	wrongNet := valid
	wrongNet.NetworkID = "netB"
	if code := upload(t, ts, cid, data, "", mkTok(wrongNet)); code != http.StatusForbidden {
		t.Fatalf("wrong-network token (relay): got %d want 403", code)
	}
	// verify-on-write: bytes that don't hash to the declared CID.
	if code := upload(t, ts, storage.Compute([]byte("declared")), []byte("actual-different"), "", mkTok(artifactstore.UploadToken{
		NetworkID: "netA", ArtifactCID: storage.Compute([]byte("declared")).String(), MaxSize: 1 << 20,
		ExpiresAt: time.Now().Add(time.Minute).UnixMicro(),
	})); code != http.StatusUnprocessableEntity {
		t.Fatalf("verify-on-write mismatch: got %d want 422", code)
	}
}

// NOTE: MIME validation is no longer a store concern (the store is
// content-agnostic); it moved to the ledger FINISH gate. The upload handler
// ignores any X-Artifact-MIME header. See reservation.Manager + the on-log
// content-type policy resolver.

// TestServer_RestrictedPosture: anonymous fetch is gated by the hook.
func TestServer_RestrictedPosture(t *testing.T) {
	ctx := context.Background()
	data := []byte("sealed exhibit")
	cid := storage.Compute(data)

	// DenyAll: GET is forbidden even for present content.
	denied := testServer(t, artifactstore.WithPosture(artifactstore.PostureRestricted),
		artifactstore.WithAuthorizationHook(artifactstore.DenyAllHook{}))
	if code := upload(t, denied, cid, data, "", ""); code != http.StatusCreated {
		t.Fatalf("upload to restricted: got %d", code)
	}
	resp, err := denied.Client().Get(denied.URL + "/v1/artifacts/" + cid.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted GET under DenyAll: got %d want 403", resp.StatusCode)
	}

	// AllowAll restricted: resolve issues a credential.
	allowed := testServer(t, artifactstore.WithPosture(artifactstore.PostureRestricted),
		artifactstore.WithAuthorizationHook(artifactstore.AllowAllHook{}))
	_ = upload(t, allowed, cid, data, "", "")
	rc, err := storage.NewHTTPRetrievalProvider(storage.HTTPRetrievalProviderConfig{BaseURL: allowed.URL, Client: allowed.Client()})
	if err != nil {
		t.Fatalf("NewHTTPRetrievalProvider: %v", err)
	}
	cred, err := rc.Resolve(ctx, cid, time.Minute)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cred.Method != storage.MethodDirect || cred.URL == "" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}
