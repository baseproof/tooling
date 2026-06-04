/*
FILE PATH:

	reservation/finish_handler.go

DESCRIPTION:

	The FINISH endpoint — POST /v1/artifacts/{cid}/finish. The client calls it once
	the upload has landed; the handler runs Manager.Finish (Exists completeness
	oracle + MIME validation + CAS to committed) and maps the outcome to a status
	code:

	  200 committed | 409 incomplete (retry) | 422 rejected | 404 not found.

	Keyed by the artifact CID (the reservation's primary key), not an entry
	sequence — the genesis entry's sequence is assigned asynchronously after the
	reservation was already staged.
*/
package reservation

import (
	"encoding/json"
	"errors"
	"net/http"
)

// NewFinishHandler returns the http.HandlerFunc for POST /v1/artifacts/{cid}/finish.
// Register it on a mux with the "{cid}" path wildcard.
func NewFinishHandler(mgr *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cid := r.PathValue("cid")
		if cid == "" {
			http.Error(w, "missing cid", http.StatusBadRequest)
			return
		}
		res, err := mgr.Finish(r.Context(), cid)
		switch {
		case errors.Is(err, ErrNotFound):
			http.Error(w, "no such reservation", http.StatusNotFound)
		case errors.Is(err, ErrIncomplete):
			writeJSON(w, http.StatusConflict, map[string]any{
				"status": string(res.Status), "reason": "incomplete: artifact bytes not present; resume upload then retry",
			})
		case errors.Is(err, ErrRejected):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"status": string(StatusRejected), "reason": "content validation failed",
			})
		case err != nil:
			http.Error(w, "finish failed", http.StatusInternalServerError)
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"status":       string(res.Status),
				"artifact_cid": res.ArtifactCID,
			})
		}
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
