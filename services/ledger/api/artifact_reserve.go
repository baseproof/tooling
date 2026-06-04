/*
FILE PATH: api/artifact_reserve.go

POST /v1/artifacts/reserve — the RESERVE step of the artifact-upload protocol
(RESERVE -> token -> UPLOAD -> FINISH, ledger#193).

This is the DEDICATED home for artifact-genesis submissions. Unlike the generic
/v1/entries endpoint — which is deliberately domain-agnostic and never parses a
domain payload — this endpoint's whole job is to understand an artifact-genesis
entry: it decodes the signed declaration (storage.ArtifactGenesis), admits the
entry through the shared admission pipeline (admitEntry), stages an upload
reservation keyed by the artifact's content address, and returns the signed
upload token alongside the SCT.

Putting the parsing here keeps the Domain/Protocol Separation Principle intact:
the generic submission path stays payload-blind; the artifact-aware logic lives
in the endpoint that exists for it.
*/
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/baseproof/baseproof/core/envelope"
	sdksct "github.com/baseproof/baseproof/crypto/sct"
	"github.com/baseproof/baseproof/exchange/policy"
	"github.com/baseproof/baseproof/storage"

	"github.com/baseproof/tooling/services/ledger/apitypes"
	"github.com/baseproof/tooling/services/ledger/reservation"
)

// ArtifactReserver stages an artifact upload reservation and returns a signed
// upload token. Implemented by *reservation.Manager.
type ArtifactReserver interface {
	Reserve(ctx context.Context, req reservation.ReserveRequest) (string, error)
}

// artifactReserveResponse is the 202 body: the inlined SCT plus the upload token.
// The token is omitted only when the reservation could not be staged (the entry
// is still durably admitted; the field's absence signals "no token issued").
type artifactReserveResponse struct {
	*sdksct.SignedCertificateTimestamp
	UploadToken string `json:"upload_token,omitempty"`
}

// NewArtifactReserveHandler creates the POST /v1/artifacts/reserve handler. The
// request body is a signed artifact-genesis entry; the handler admits it through
// the same pipeline as /v1/entries (admitEntry) and then stages the reservation.
// reserver is REQUIRED.
func NewArtifactReserveHandler(deps *SubmissionDeps, reserver ArtifactReserver) http.HandlerFunc {
	if deps == nil {
		panic("api: SubmissionDeps must be non-nil")
	}
	if reserver == nil {
		panic("api: ArtifactReserver must be non-nil")
	}
	freshness := deps.FreshnessTolerance
	if freshness <= 0 {
		freshness = policy.FreshnessInteractive
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Validate this IS an artifact-genesis entry BEFORE admission, so a
		// request to the wrong endpoint is a clean 400 with nothing admitted.
		raw, err := io.ReadAll(io.LimitReader(r.Body, deps.MaxEntrySize+512))
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassMalformedBody, http.StatusBadRequest, "failed to read request body")
			return
		}
		entry, err := envelope.Deserialize(raw)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassEnvelopeRejected, http.StatusBadRequest,
				fmt.Sprintf("deserialize: %s", err))
			return
		}
		g, err := storage.DecodeArtifactGenesisPayload(entry.DomainPayload)
		if err != nil {
			writeTypedError(ctx, w, apitypes.ErrorClassEnvelopeRejected, http.StatusBadRequest,
				fmt.Sprintf("this endpoint requires an artifact-genesis entry: %s", err))
			return
		}

		// Re-supply the buffered body to the shared admission pipeline.
		r.Body = io.NopCloser(bytes.NewReader(raw))
		sct, _, ok := admitEntry(ctx, deps, w, r, freshness)
		if !ok {
			return // admitEntry already wrote the typed error
		}

		// Stage the reservation. The entry is already durable (its signed MIME
		// claim is on the log), so a reservation failure is logged, not fatal:
		// the response carries the SCT with no token.
		contentDigest := ""
		if !g.ContentDigest.IsZero() {
			contentDigest = g.ContentDigest.String()
		}
		token, rerr := reserver.Reserve(ctx, reservation.ReserveRequest{
			ArtifactCID:   g.ArtifactCID.String(),
			ContentDigest: contentDigest,
			MIMEType:      g.MIMEType,
			MaxSize:       g.MaxSize,
			Owner:         g.Owner,
		})
		if rerr != nil {
			deps.Logger.Warn("artifact reservation failed (entry is durable; no upload token issued)",
				"artifact_cid", g.ArtifactCID.String(), "error", rerr)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(artifactReserveResponse{
			SignedCertificateTimestamp: sct,
			UploadToken:                token,
		})
	}
}
