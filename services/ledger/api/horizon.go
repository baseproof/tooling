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
	"strconv"
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
	head, err := decodeCosignedCheckpoint(raw)
	if err != nil {
		return nil, nil, err
	}
	return head, raw, nil
}

// decodeCosignedCheckpoint parses the published wire shape (lowercase-hex
// WireCosignedTreeHead) into a CosignedTreeHead. Shared by ReadHorizon (latest)
// and ReadCheckpointAt (per-size archive).
func decodeCosignedCheckpoint(raw []byte) (*types.CosignedTreeHead, error) {
	var w types.WireCosignedTreeHead
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("api/horizon: decode cosigned checkpoint: %w", err)
	}
	head, err := w.ToCosignedTreeHead()
	if err != nil {
		return nil, fmt.Errorf("api/horizon: decode cosigned checkpoint: %w", err)
	}
	return &head, nil
}

// checkpointArchiveObject is the storage key for the per-tree_size archived
// cosigned head — the never-overwritten copy the builder writes beside the latest
// cosigned-checkpoint (tessera checkpointArchiveDir = "checkpoints"). MUST match
// the tessera writer and store/horizon_s3.go checkpointArchiveKey.
func checkpointArchiveObject(size uint64) string {
	return "checkpoints/" + strconv.FormatUint(size, 10)
}

// CheckpointArchiveReader reads a cosigned head at a SPECIFIC tree size from the
// per-size archive (object store) — the PG-free path for historical heads and the
// cold-seq inclusion anchor (1.1a). tileBackendHorizon and store.S3HorizonReader
// both implement it.
type CheckpointArchiveReader interface {
	ReadCheckpointAt(ctx context.Context, size uint64) (head *types.CosignedTreeHead, raw []byte, err error)
}

// ReadCheckpointAt reads the archived cosigned head at the given tree size from
// the object store — PG-free. Returns a wrapped os.ErrNotExist when that size was
// never archived (pre-archive history, or a size that was never a cosigned head).
func (h *tileBackendHorizon) ReadCheckpointAt(ctx context.Context, size uint64) (*types.CosignedTreeHead, []byte, error) {
	raw, err := h.backend.ReadTileByPath(ctx, checkpointArchiveObject(size))
	if err != nil {
		return nil, nil, err
	}
	head, err := decodeCosignedCheckpoint(raw)
	if err != nil {
		return nil, nil, err
	}
	return head, raw, nil
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

// NewCheckpointArchiveHandler returns GET /v1/tree/checkpoint/{size} — the
// cosigned head (SMTRoot + K-of-N witness sigs) archived at a SPECIFIC tree size,
// served verbatim from the object store (PG-free). The auditor's anchor for
// cold-seq inclusion: fetch the covering cosigned head, then verify the entry's
// inclusion against it. A nil reader is a graceful 503.
//
// Negative-answer discipline (cf. 1.3f): checkpoints publish at cosign-cycle
// boundaries, not every size, so a size with no archived checkpoint is a GENUINE
// 404 — while a transient read fault is a 500. A 404 never masquerades a backend
// hiccup as definitive absence.
func NewCheckpointArchiveHandler(reader CheckpointArchiveReader, logger *slog.Logger) http.HandlerFunc {
	if reader == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			writeTypedError(r.Context(), w, apitypes.ErrorClassHorizonUnavailable,
				http.StatusServiceUnavailable, "checkpoint archive not configured")
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		size, perr := strconv.ParseUint(r.PathValue("size"), 10, 64)
		if perr != nil || size == 0 {
			writeTypedError(ctx, w, apitypes.ErrorClassInvalidQueryParam,
				http.StatusBadRequest, "invalid tree size")
			return
		}
		head, raw, err := reader.ReadCheckpointAt(ctx, size)
		if errors.Is(err, os.ErrNotExist) {
			writeTypedError(ctx, w, apitypes.ErrorClassNotFound,
				http.StatusNotFound, fmt.Sprintf("no cosigned checkpoint archived at tree size %d", size))
			return
		}
		if err != nil {
			logger.ErrorContext(ctx, "checkpoint archive read failed", "size", size, "error", err)
			writeTypedError(ctx, w, apitypes.ErrorClassReadProjectionFailed,
				http.StatusInternalServerError, fmt.Sprintf("checkpoint archive read failed: %s", err))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, head.TreeSize))
		// Archived checkpoints are immutable per size → cache hard.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, checkpointArchiveObject(size), time.Time{}, bytes.NewReader(raw))
	}
}
