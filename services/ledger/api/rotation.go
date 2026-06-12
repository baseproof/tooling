/*
FILE PATH: api/rotation.go

DESCRIPTION:

	POST /v1/network/rotation — the public inbound door for an
	operator-driven witness rotation (PRE-6c). The body is a finalized
	BP-ENTRY-WITNESS-ROTATION-PAYLOAD-V1 (the bytes the CLI's
	`network rotation finalize` produces from collected consents); the door
	decodes it and feeds the SINGLE ProcessRotation chokepoint, which runs
	the SDK's full cryptographic recipe (set-hash rebind, scheme
	enforcement, OLD K-of-N quorum, optional NEW dual-sign), commits the
	on-log rotation entry, and swaps the in-memory set.

	THE DOOR MINTS NO TRUST. The finalized rotation is self-authorizing —
	the consents ARE the authority — so this endpoint is public (no auth
	invention) but DoS-bounded: a size-capped body, a context deadline, and
	a structural decode before ProcessRotation ever runs. An invalid
	rotation is a Domain Violation (422, a dimensional counter), never a
	System Fault. There is exactly ONE witness_sets writer (ProcessRotation);
	this door is its front, not a second one.
*/
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
)

// maxRotationBody caps the inbound rotation payload (the on-log entry itself
// is bounded to 65,535 bytes; the JSON form is modestly larger — 256 KiB is
// a generous DoS bound).
const maxRotationBody = 256 << 10

// RotationProcessor is the single chokepoint the door feeds — satisfied by
// *witnessclient.RotationHandler.ProcessRotation. Injected (not imported) so
// api stays free of the witnessclient dependency and the door is unit-testable
// with a stub.
type RotationProcessor interface {
	ProcessRotation(ctx context.Context, rotation types.WitnessRotation) ([]types.WitnessPublicKey, error)
}

// NewRotationHandler returns the POST /v1/network/rotation handler. A nil
// processor ⇒ the door is not mounted (a node without the rotation pipeline
// wired — dev/integration — serves no rotation endpoint, matching the
// fail-closed posture of the rest of the rotation surface).
func NewRotationHandler(proc RotationProcessor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRotationBody))
		if err != nil {
			writeRotationError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}

		// Structural decode BEFORE the processor — a malformed payload is a
		// 422 Domain Violation at the front door, never an internal fault.
		rotation, err := witness.DecodeWitnessRotationPayload(body)
		if err != nil {
			writeRotationError(w, http.StatusUnprocessableEntity, "decode rotation: "+err.Error())
			return
		}
		if verr := witness.ValidateWitnessRotation(rotation); verr != nil {
			writeRotationError(w, http.StatusUnprocessableEntity, "invalid rotation: "+verr.Error())
			return
		}

		// The single chokepoint: full crypto recipe + persist + swap + emit.
		newSet, err := proc.ProcessRotation(r.Context(), rotation)
		if err != nil {
			// A verify/quorum failure is the SUBMITTER's problem (the consents
			// did not satisfy the current set) — a Domain Violation, 422.
			writeRotationError(w, http.StatusUnprocessableEntity, "rotation rejected: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"applied":           true,
			"new_witness_count": len(newSet),
		})
	})
}

func writeRotationError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// errRotationUnwired documents the nil-processor posture for callers.
var errRotationUnwired = errors.New("api: rotation processor not wired")

var _ = errRotationUnwired
