/*
FILE PATH: libs/networkbundle/serve.go

DESCRIPTION:

	GET /v1/network/bundle — the generic serving half of the network bundle,
	relocated from the judicial-network's manifesthttp (the domain half — the
	jurisdiction projection — stays with its owner and is injected here as
	the Compile closure; the platform ledger injects its own introspection
	composer the same way). One handler, every network: drift detection and
	caching semantics can never diverge between serves.

	TWO SOURCES, ONE TRUTH RULE:

	  - The ON-LOG manifest (the latest entry citing the manifest anchor
	    schema — resolved via the ledger's GET /v1/query/schema_ref/{pos},
	    fetched raw, strict-decoded, and HASH-VERIFIED: the payload bytes
	    must re-canonicalize to themselves) is what the network has DECLARED.
	    When an anchor is configured and a published manifest resolves, its
	    exact on-log bytes are served.
	  - The COMPILED projection (the injected Compile closure) is what the
	    network ENFORCES. The handler compares the two on every serve: a
	    mismatch is DRIFT — declared ≠ enforced — surfaced loudly (ERROR log
	    + X-Manifest-Enforced-Match: false), never hidden.
	  - Until an anchor is configured (or before the first publication), the
	    compiled projection is served, marked X-Manifest-Published: false.

	Response headers: ETag = sha256 of the served canonical bytes (with
	If-None-Match → 304), X-Manifest-Published, X-Manifest-Position
	(<log-did>@<seq> when published), X-Manifest-Enforced-Match.

	The bare GET (no ?destination) returns the envelope: the format tag, the
	served destination DIDs, and whether an anchor is configured.

	Serve UNAUTHENTICATED: the manifest is the network's public consumption
	contract.
*/
package networkbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	sdkenv "github.com/baseproof/baseproof/core/envelope"
)

// maxManifestBytes caps a fetched on-log manifest entry (DoS guard; the
// ledger's own entry cap is 1 MiB).
const maxManifestBytes = 1 << 20

// ErrUnknownDestination is returned by a Compile closure when the destination
// is not one this network serves; the handler answers 404.
var ErrUnknownDestination = errors.New("networkbundle: unknown destination")

// ServeConfig wires the handler. Compile is the network owner's composer —
// the ENFORCED projection for one destination (a domain injects its
// jurisdiction projection; the platform ledger injects its introspection
// composer). Compile must be deterministic for the life of the process: the
// handler caches its result per destination.
type ServeConfig struct {
	Compile      func(destination string) (*Manifest, error) // ErrUnknownDestination ⇒ 404
	Destinations func() []string

	// Anchor is the manifest anchor schema position "<log-did>@<seq>".
	// Empty ⇒ unpublished mode: the compiled projection is served with
	// X-Manifest-Published: false.
	Anchor string

	// LedgerBaseURL + Client resolve the published manifest from the ledger
	// (schema_ref query + raw entry fetch). Required when Anchor is set.
	LedgerBaseURL string
	Client        *http.Client

	Logger *slog.Logger
}

type serveHandler struct {
	cfg       ServeConfig
	anchorRaw string // "<log-did>@<seq>" as configured (path segment for schema_ref)

	mu       sync.Mutex
	compiled map[string]*servable // per-destination compiled projection (deterministic per boot)
}

// servable is one ready-to-serve manifest form.
type servable struct {
	body []byte
	hash [32]byte
}

// NewServeHandler validates the wiring and returns the GET /v1/network/bundle
// handler.
func NewServeHandler(cfg ServeConfig) (http.Handler, error) {
	if cfg.Compile == nil || cfg.Destinations == nil {
		return nil, fmt.Errorf("networkbundle: serve: Compile and Destinations are required")
	}
	if cfg.Anchor != "" {
		if cfg.LedgerBaseURL == "" {
			return nil, fmt.Errorf("networkbundle: serve: Anchor is set but LedgerBaseURL is empty (cannot resolve the published manifest)")
		}
		at := strings.LastIndex(cfg.Anchor, "@")
		if at <= 0 {
			return nil, fmt.Errorf("networkbundle: serve: Anchor %q must be <log-did>@<seq>", cfg.Anchor)
		}
		if _, err := strconv.ParseUint(cfg.Anchor[at+1:], 10, 64); err != nil {
			return nil, fmt.Errorf("networkbundle: serve: Anchor sequence in %q: %v", cfg.Anchor, err)
		}
	}
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &serveHandler{cfg: cfg, anchorRaw: cfg.Anchor, compiled: map[string]*servable{}}, nil
}

func (h *serveHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dest := r.URL.Query().Get("destination")
	if dest == "" {
		h.serveEnvelope(w)
		return
	}

	comp, err := h.compiledFor(dest)
	if errors.Is(err, ErrUnknownDestination) {
		writeJSONError(w, http.StatusNotFound,
			fmt.Sprintf("unknown destination %q (this network serves no bundle for it)", dest))
		return
	}
	if err != nil {
		h.cfg.Logger.Error("manifest: compiled projection failed", "destination", dest, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "compiled manifest projection failed")
		return
	}

	// Published resolution (anchor configured): the on-log declaration wins
	// the serve; the compiled projection is the enforcement reference it is
	// compared against.
	if h.anchorRaw != "" {
		pub, pos, rErr := h.resolvePublished(r, dest)
		if rErr != nil {
			// Loud, not fatal: the network keeps serving its enforced contract.
			h.cfg.Logger.Error("manifest: published resolution failed — serving the compiled projection",
				"destination", dest, "anchor", h.anchorRaw, "error", rErr)
			w.Header().Set("X-Manifest-Resolve-Error", rErr.Error())
			h.serve(w, r, comp, "false", "", "")
			return
		}
		if pub != nil {
			match := "true"
			if pub.hash != comp.hash {
				match = "false"
				h.cfg.Logger.Error("manifest DRIFT: the published manifest does not match the enforced projection",
					"destination", dest, "position", pos,
					"published_hash", hex.EncodeToString(pub.hash[:8]),
					"enforced_hash", hex.EncodeToString(comp.hash[:8]))
			}
			h.serve(w, r, pub, "true", pos, match)
			return
		}
		// Anchor configured but nothing published yet for this destination.
		h.serve(w, r, comp, "false", "", "")
		return
	}
	h.serve(w, r, comp, "false", "", "")
}

// serve writes one manifest form with the contract headers (ETag /
// If-None-Match, published flag, on-log position, enforced-match).
func (h *serveHandler) serve(w http.ResponseWriter, r *http.Request, s *servable, published, position, match string) {
	etag := `"` + hex.EncodeToString(s.hash[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Manifest-Published", published)
	if position != "" {
		w.Header().Set("X-Manifest-Position", position)
	}
	if match != "" {
		w.Header().Set("X-Manifest-Enforced-Match", match)
	}
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.body)
}

// serveEnvelope answers the bare GET: what this endpoint serves and for whom.
func (h *serveHandler) serveEnvelope(w http.ResponseWriter) {
	dids := append([]string(nil), h.cfg.Destinations()...)
	sort.Strings(dids)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"format":            ManifestFormat,
		"exchanges":         dids,
		"anchor_configured": h.anchorRaw != "",
		"usage":             "GET /v1/network/bundle?destination=<exchange-did>",
	})
}

// compiledFor builds (once per destination) the enforced projection.
func (h *serveHandler) compiledFor(dest string) (*servable, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.compiled[dest]; ok {
		return s, nil
	}
	m, err := h.cfg.Compile(dest)
	if err != nil {
		return nil, err
	}
	body, err := m.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	s := &servable{body: body, hash: sha256.Sum256(body)}
	h.compiled[dest] = s
	return s, nil
}

// resolvePublished finds the LATEST on-log manifest for dest: the highest-
// sequence entry citing the anchor schema whose payload strict-decodes to a
// manifest for dest AND hash-verifies (the payload bytes re-canonicalize to
// themselves — a non-canonical or tampered payload is skipped loudly).
// Returns (nil, "", nil) when nothing valid is published yet.
func (h *serveHandler) resolvePublished(r *http.Request, dest string) (*servable, string, error) {
	ctx := r.Context()
	url := strings.TrimRight(h.cfg.LedgerBaseURL, "/") + "/v1/query/schema_ref/" + h.anchorRaw
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := h.cfg.Client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("schema_ref query: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("schema_ref query HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}
	var out struct {
		Entries []struct {
			SequenceNumber uint64 `json:"sequence_number"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", fmt.Errorf("schema_ref response: %w", err)
	}
	seqs := make([]uint64, 0, len(out.Entries))
	for _, e := range out.Entries {
		seqs = append(seqs, e.SequenceNumber)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] > seqs[j] }) // newest first

	logDID := h.anchorRaw[:strings.LastIndex(h.anchorRaw, "@")]
	for _, seq := range seqs {
		payload, fErr := h.fetchEntryPayload(r, seq)
		if fErr != nil {
			h.cfg.Logger.Warn("manifest: candidate entry fetch failed", "seq", seq, "error", fErr)
			continue
		}
		m, dErr := DecodeManifest(payload)
		if dErr != nil {
			h.cfg.Logger.Warn("manifest: candidate entry is not a valid manifest", "seq", seq, "error", dErr)
			continue
		}
		if m.Exchange != dest {
			continue // a manifest for a different exchange citing the same anchor
		}
		// Hash-verify: the served bytes must BE the canonical form.
		recanon, cErr := m.CanonicalBytes()
		if cErr != nil || !bytes.Equal(recanon, payload) {
			h.cfg.Logger.Warn("manifest: candidate payload is not canonical — skipping", "seq", seq)
			continue
		}
		return &servable{body: payload, hash: sha256.Sum256(payload)},
			fmt.Sprintf("%s@%d", logDID, seq), nil
	}
	return nil, "", nil
}

// fetchEntryPayload GETs /v1/entries/{seq}/raw and returns the entry's domain
// payload (the manifest bytes) after envelope deserialization.
func (h *serveHandler) fetchEntryPayload(r *http.Request, seq uint64) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/entries/%d/raw", strings.TrimRight(h.cfg.LedgerBaseURL, "/"), seq)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	wire, _ := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("raw entry HTTP %d", resp.StatusCode)
	}
	entry, err := sdkenv.Deserialize(wire)
	if err != nil {
		return nil, fmt.Errorf("deserialize entry: %w", err)
	}
	return entry.DomainPayload, nil
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
