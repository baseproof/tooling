package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/baseproof/tooling/services/ledger/admission"
	"github.com/baseproof/tooling/services/ledger/apitypes"
)

// NewAdmissionPolicyHandler publishes the current admission policy — whether
// write authorization is required + the cost regime — mirroring the
// /v1/difficulty endpoint. The policy is a deterministic projection of on-log
// BP-ENTRY-ADMISSION-POLICY-V1 entries plus genesis, so any client or auditor can
// independently re-derive it from the log. Nil-safe (503 when unconfigured).
func NewAdmissionPolicyHandler(resolver admission.AdmissionPolicyResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if resolver == nil {
			writeTypedError(r.Context(), w, apitypes.ErrorClassDBQueryFailed,
				http.StatusServiceUnavailable, "admission policy resolver not configured")
			return
		}
		pol, err := resolver.Current(r.Context())
		if err != nil {
			writeTypedError(r.Context(), w, apitypes.ErrorClassDBQueryFailed,
				http.StatusInternalServerError, "admission policy resolution failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=5")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gating_required": pol.GatingRequired,
			"cost_mode":       string(pol.CostMode),
			"flat_units":      pol.FlatUnits,
			"timestamp":       time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}
