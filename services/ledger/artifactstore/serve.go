/*
FILE PATH:

	artifactstore/serve.go

DESCRIPTION:

	Phase 5 — the /v1/artifacts HTTP SERVER (the counterpart of the SDK's
	storage.HTTPContentStore CLIENT). It maps the frozen baseproof#97 wire contract
	onto a Store, so the consumer flips in-process <-> service by swapping a
	direct *Store for an HTTPContentStore{baseURL} pointed here — byte-identical
	consuming code.

	It also hosts the Phase 4 accounting boundary and the Phase 6 postures:
	  - Upload (POST /v1/artifacts): optional ledger-signed bearer token
	    (verify-on-write CID, MaxSize cap, NetworkID scope). Content-type / MIME
	    validation is NOT done here — the store is content-agnostic; that gate
	    lives at the ledger FINISH boundary (reservation.Manager).
	  - PUBLIC posture: anonymous GET-by-CID (the #190 commitment-sidecar path).
	  - RESTRICTED posture: GET-by-CID and resolve gated by the AuthorizationHook
	    -> a short-lived RetrievalCredential.

KEY ARCHITECTURAL DECISIONS:
  - Wire-exact: POST /v1/artifacts (X-Artifact-CID), GET/HEAD/DELETE
    /v1/artifacts/{cid}, POST .../pin, GET .../resolve?expiry= — matching
    storage.HTTPContentStore / HTTPRetrievalProvider verbatim.
  - The store is a dumb executor; the token verify (with the ledger's PUBLIC
    key) and the AuthorizationHook are INJECTED — no ledger-internal import, so
    the module stays portable.
  - Verify-on-write: an upload's bytes must hash to the declared CID, else 422
    (REJECTED) — the producer-CID invariant at the HTTP boundary.
*/
package artifactstore

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/baseproof/storage"
)

// DefaultMaxUpload bounds an upload body when no token caps it (100 MiB,
// matching the SDK HTTPContentStore read limit).
const DefaultMaxUpload int64 = 100 << 20

// Server serves the /v1/artifacts contract over a Store.
type Server struct {
	store     *Store
	posture   Posture
	authHook  AuthorizationHook
	retrieval storage.RetrievalProvider
	uploadKey ed25519.PublicKey // nil => uploads are NOT token-gated (public posture)
	networkID string            // hex; when set, a token's NetworkID must match
	maxUpload int64
	logger    *slog.Logger
}

// Option configures a Server.
type Option func(*Server)

// WithPosture sets PUBLIC (default) or RESTRICTED.
func WithPosture(p Posture) Option { return func(s *Server) { s.posture = p } }

// WithAuthorizationHook gates restricted fetch / resolve / delete.
func WithAuthorizationHook(h AuthorizationHook) Option { return func(s *Server) { s.authHook = h } }

// WithRetrievalProvider issues resolve credentials (signed URLs). Default: a
// direct provider returning the relative fetch path.
func WithRetrievalProvider(rp storage.RetrievalProvider) Option {
	return func(s *Server) { s.retrieval = rp }
}

// WithUploadVerification enables the token-gated upload protocol: uploads MUST
// carry a bearer token signed by the matching private key and (when networkID is
// non-empty) scoped to networkID.
func WithUploadVerification(pub ed25519.PublicKey, networkID string) Option {
	return func(s *Server) { s.uploadKey = pub; s.networkID = networkID }
}

// WithMaxUpload overrides the absolute upload body cap.
func WithMaxUpload(n int64) Option { return func(s *Server) { s.maxUpload = n } }

// NewServer builds a Server over store.
func NewServer(store *Store, logger *slog.Logger, opts ...Option) *Server {
	s := &Server{
		store:     store,
		posture:   PosturePublic,
		authHook:  AllowAllHook{},
		retrieval: directRetrieval{},
		maxUpload: DefaultMaxUpload,
		logger:    logger,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Handler returns the mux for the /v1/artifacts contract.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/artifacts", s.handleUpload)
	mux.HandleFunc("GET /v1/artifacts/{cid}", s.handleFetch)
	mux.HandleFunc("HEAD /v1/artifacts/{cid}", s.handleExists)
	mux.HandleFunc("POST /v1/artifacts/{cid}/pin", s.handlePin)
	mux.HandleFunc("DELETE /v1/artifacts/{cid}", s.handleDelete)
	mux.HandleFunc("GET /v1/artifacts/{cid}/resolve", s.handleResolve)
	return mux
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid, err := storage.ParseCID(r.Header.Get("X-Artifact-CID"))
	if err != nil {
		http.Error(w, "invalid or missing X-Artifact-CID", http.StatusBadRequest)
		return
	}

	maxSize := s.maxUpload
	if s.uploadKey != nil {
		tok, tokErr := ParseAndVerifyUploadToken(bearer(r), s.uploadKey)
		if tokErr != nil {
			http.Error(w, "invalid upload token", http.StatusUnauthorized)
			return
		}
		if tok.Expired(time.Now()) {
			http.Error(w, "upload token expired", http.StatusUnauthorized)
			return
		}
		if tok.ArtifactCID != cid.String() {
			http.Error(w, "token does not authorize this CID", http.StatusForbidden)
			return
		}
		if s.networkID != "" && tok.NetworkID != s.networkID {
			http.Error(w, "token network mismatch", http.StatusForbidden)
			return
		}
		if tok.MaxSize > 0 && tok.MaxSize < maxSize {
			maxSize = tok.MaxSize
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxSize+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > maxSize {
		http.Error(w, "upload exceeds max size", http.StatusRequestEntityTooLarge)
		return
	}

	// Verify-on-write (producer-CID at the HTTP boundary): the bytes MUST hash
	// to the declared CID.
	if !cid.Verify(body) {
		http.Error(w, "bytes do not match declared CID", http.StatusUnprocessableEntity)
		return
	}

	// NOTE: the artifact store is a content-AGNOSTIC byte executor (the SDK
	// storage-seam doctrine: it knows only CID -> opaque bytes). MIME / content-
	// type validation is a DOMAIN concern and lives at the ledger's authoritative
	// FINISH gate (reservation.Manager), governed by the on-log content-type
	// policy — not here. Keeping it out of the store preserves portability and
	// avoids a second, drifting definition of "is this a PDF".
	if err := s.store.Push(ctx, cid, body); err != nil {
		s.logger.Error("artifact upload push failed", "cid", cid.String(), "error", err)
		http.Error(w, "store push failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid, err := storage.ParseCID(r.PathValue("cid"))
	if err != nil {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	if s.posture == PostureRestricted {
		if err = s.authHook.Authorize(ctx, r, cid); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	data, err := s.store.Fetch(ctx, cid)
	if errors.Is(err, storage.ErrContentNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, storage.ErrIntegrityViolation) {
		s.logger.Error("artifact fetch integrity violation", "cid", cid.String())
		http.Error(w, "integrity violation", http.StatusBadGateway)
		return
	}
	if err != nil {
		http.Error(w, "fetch failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (s *Server) handleExists(w http.ResponseWriter, r *http.Request) {
	cid, err := storage.ParseCID(r.PathValue("cid"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ok, err := s.store.Exists(r.Context(), cid)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if ok {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) handlePin(w http.ResponseWriter, r *http.Request) {
	cid, err := storage.ParseCID(r.PathValue("cid"))
	if err != nil {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	err = s.store.Pin(r.Context(), cid)
	if errors.Is(err, storage.ErrContentNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "pin failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid, err := storage.ParseCID(r.PathValue("cid"))
	if err != nil {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	// Delete is destructive — always gated by the hook (a real deployment checks
	// the witnessed ArtifactDestruction custody authority).
	if err := s.authHook.Authorize(ctx, r, cid); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.store.Delete(ctx, cid); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cid, err := storage.ParseCID(r.PathValue("cid"))
	if err != nil {
		http.Error(w, "invalid cid", http.StatusBadRequest)
		return
	}
	if err = s.authHook.Authorize(ctx, r, cid); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	expiry := time.Duration(0)
	if v := r.URL.Query().Get("expiry"); v != "" {
		if secs, convErr := strconv.Atoi(v); convErr == nil && secs > 0 {
			expiry = time.Duration(secs) * time.Second
		}
	}
	cred, err := s.retrieval.Resolve(ctx, cid, expiry)
	if err != nil {
		http.Error(w, "resolve failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"method": cred.Method,
		"url":    cred.URL,
		"expiry": cred.Expiry,
	})
}

// bearer extracts the token from an "Authorization: Bearer <token>" header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return strings.TrimSpace(h)
}

// directRetrieval is the default RetrievalProvider: a credential-free relative
// fetch path. Deployments inject a presigning provider for restricted buckets.
type directRetrieval struct{}

func (directRetrieval) Resolve(_ context.Context, cid storage.CID, _ time.Duration) (*storage.RetrievalCredential, error) {
	return &storage.RetrievalCredential{
		Method: storage.MethodDirect,
		URL:    "/v1/artifacts/" + cid.String(),
		Expiry: nil,
	}, nil
}
