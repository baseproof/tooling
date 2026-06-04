package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/tooling/services/ledger/admission"
)

type errPolicyResolver struct{ err error }

func (e errPolicyResolver) Current(context.Context) (authz.AdmissionPolicy, error) {
	return authz.AdmissionPolicy{}, e.err
}

func TestNewAdmissionPolicyHandler(t *testing.T) {
	// nil resolver → 503.
	rec := httptest.NewRecorder()
	NewAdmissionPolicyHandler(nil)(rec, httptest.NewRequest(http.MethodGet, "/v1/admission/policy", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("nil resolver: code %d, want 503", rec.Code)
	}

	// Valid → 200 + the resolved policy.
	res := admission.StaticAdmissionPolicy{Policy: authz.AdmissionPolicy{
		GatingRequired: true, CostMode: authz.CostModeFlat, FlatUnits: 7,
	}}
	rec = httptest.NewRecorder()
	NewAdmissionPolicyHandler(res)(rec, httptest.NewRequest(http.MethodGet, "/v1/admission/policy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid: code %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["gating_required"] != true || body["cost_mode"] != "flat" || body["flat_units"].(float64) != 7 {
		t.Errorf("body mismatch: %v", body)
	}

	// Resolver error → 500.
	rec = httptest.NewRecorder()
	NewAdmissionPolicyHandler(errPolicyResolver{err: errors.New("boom")})(rec, httptest.NewRequest(http.MethodGet, "/v1/admission/policy", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("error resolver: code %d, want 500", rec.Code)
	}
}
