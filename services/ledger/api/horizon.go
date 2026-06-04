/*
FILE PATH: api/horizon.go

The serveable horizon — the latest witness-cosigned tree head the ledger has
published. The builder writes it post-commit, gated on the SMT proof substrate
for that root being durable (builder/loop.go Step 8b/9), so a PUBLISHED horizon
is, by construction, one whose SMT nodes/tiles are present: every membership
proof anchored on it resolves.

This is the read-front anchor:

  - GET /v1/tree/horizon serves the published CosignedTreeHead verbatim (the
    exact bytes the builder published; CDN-frontable). The client MUST re-verify
    the K-of-N cosignature against an out-of-band witness key set — the ledger
    is a dumb sequencer and cannot certify its own validity (crypto/cosign.Verify
    / VerifyTreeHeadCosignatures).

  - NewSMTProofHandler (proofs.go) anchors proofs on the horizon's SMTRoot
    instead of the live mutable root, closing the fetch-head-then-fetch-proof
    race: the proof and the head are bound to the same root, and the head is
    witness-cosigned.

The horizon is the file the builder publishes via
tessera.PublishCosignedCheckpoint (<TesseraStorageDir>/cosigned-checkpoint, the
full types.CosignedTreeHead JSON with SMTRoot + signatures). It is read through
the same TileBackend that serves the c2sp tiles, so no Postgres read sits on
this path. Distinct from the c2sp `checkpoint` (origin-signed, RFC6962 root
only, no SMTRoot).
*/
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/services/ledger/apitypes"
)

// cosignedCheckpointObject is the storage key the builder publishes the K-of-N
// CosignedTreeHead to (tessera.AppenderOptions.PublicCheckpointPath =
// <TesseraStorageDir>/cosigned-checkpoint) and the TileBackend reads back.
const cosignedCheckpointObject = "cosigned-checkpoint"

// HorizonReader reads the latest published cosigned tree head — the read-front
// anchor. A nil HorizonReader on SMTDeps makes proofs fall back to the live
// committed root (legacy behaviour).
type HorizonReader interface {
	// ReadHorizon returns the parsed head AND the raw published bytes (so the
	// proof handler can bundle the exact bytes a client re-verifies). Returns a
	// wrapped os.ErrNotExist before the first checkpoint is published.
	ReadHorizon(ctx context.Context) (head *types.CosignedTreeHead, raw []byte, err error)
}

// tileBackendHorizon reads the cosigned checkpoint through a TileBackend.
type tileBackendHorizon struct {
	backend TileBackend
}

// NewTileBackendHorizon wires a HorizonReader over the TileBackend that holds
// the published cosigned-checkpoint object — the POSIX backend rooted at the
// Tessera storage dir in production, where PublishCosignedCheckpoint writes.
func NewTileBackendHorizon(backend TileBackend) HorizonReader {
	return &tileBackendHorizon{backend: backend}
}

func (h *tileBackendHorizon) ReadHorizon(ctx context.Context) (*types.CosignedTreeHead, []byte, error) {
	raw, err := h.backend.ReadTileByPath(ctx, cosignedCheckpointObject)
	if err != nil {
		// os.ErrNotExist propagates verbatim so the caller can distinguish
		// pre-genesis (no checkpoint yet → 503) from a real read fault.
		return nil, nil, err
	}
	var w types.WireCosignedTreeHead
	if uErr := json.Unmarshal(raw, &w); uErr != nil {
		return nil, nil, fmt.Errorf("api/horizon: decode cosigned checkpoint: %w", uErr)
	}
	head, cErr := w.ToCosignedTreeHead()
	if cErr != nil {
		return nil, nil, fmt.Errorf("api/horizon: decode cosigned checkpoint: %w", cErr)
	}
	return &head, raw, nil
}

// NewCosignedCheckpointHandler returns the GET /v1/tree/horizon handler — the
// published CosignedTreeHead (SMTRoot + K-of-N witness signatures) served
// verbatim. CDN-frontable; the client re-verifies the quorum out-of-band. A nil
// backend is a graceful 503 so a misconfigured deployment never panics.
func NewCosignedCheckpointHandler(reader HorizonReader, logger *slog.Logger) http.HandlerFunc {
	if reader == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			writeTypedError(r.Context(), w, apitypes.ErrorClassHorizonUnavailable,
				http.StatusServiceUnavailable, "horizon backend not configured")
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		head, raw, err := reader.ReadHorizon(r.Context())
		if errors.Is(err, os.ErrNotExist) {
			// Fresh network before the first quorum-finalized checkpoint. 503 (not a
			// cacheable 404) so a CDN edge never pins "no checkpoint" forever.
			writeTypedError(r.Context(), w, apitypes.ErrorClassNotFound,
				http.StatusServiceUnavailable, "no cosigned checkpoint published yet")
			return
		}
		if err != nil {
			logger.ErrorContext(r.Context(), "horizon read failed", "error", err)
			writeTypedError(r.Context(), w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, fmt.Sprintf("horizon read failed: %s", err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, head.TreeSize))
		// The horizon advances every cosign cycle; short max-age lets a CDN front
		// it while keeping staleness bounded (mirrors /checkpoint). Reader serves
		// from POSIX or shared S3 behind the same HorizonReader interface.
		w.Header().Set("Cache-Control", "public, max-age=2")
		http.ServeContent(w, r, cosignedCheckpointObject, time.Time{}, bytes.NewReader(raw))
	}
}
