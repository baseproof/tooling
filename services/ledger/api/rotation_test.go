/*
FILE PATH: api/rotation_test.go

DESCRIPTION:

	Pins POST /v1/network/rotation's contract: a finalized rotation flows
	through the structural door into the SINGLE ProcessRotation chokepoint
	(a stub here — the real processor's recipe is pinned in witnessclient),
	and the failure taxonomy is exact:

	  - a malformed / structurally-invalid body is a 422 Domain Violation at
	    the FRONT door — the processor is never reached;
	  - a processor rejection (the consents did not satisfy the current set)
	    is a 422 Domain Violation — the submitter's problem, not a 500;
	  - a valid, accepted rotation returns 202 with the new witness count;
	  - the body is size-bounded (DoS immunity).
*/
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/api"
)

// stubProcessor records calls and returns a configurable verdict.
type stubProcessor struct {
	called  int
	newSet  []types.WitnessPublicKey
	err     error
	gotHash [32]byte
}

func (s *stubProcessor) ProcessRotation(_ context.Context, r types.WitnessRotation) ([]types.WitnessPublicKey, error) {
	s.called++
	s.gotHash = r.CurrentSetHash
	return s.newSet, s.err
}

// validRotationBody builds a structurally valid rotation via the SDK's OWN
// encoder (tests are consumers — no hand-assembled wire).
func validRotationBody(t *testing.T) []byte {
	t.Helper()
	r := types.WitnessRotation{
		CurrentSetHash: [32]byte{0x01},
		NewSet:         []types.WitnessPublicKey{{ID: [32]byte{0x02}, PublicKey: []byte{0x04, 0xAA}, SchemeTag: 1}},
		SchemeTagOld:   1,
		SchemeTagNew:   1,
		CurrentSignatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0x03}, SchemeTag: 1, SigBytes: []byte{0xBB, 0xCC}},
		},
		NewSignatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0x02}, SchemeTag: 1, SigBytes: []byte{0xDD, 0xEE}},
		},
	}
	b, err := witness.EncodeWitnessRotationPayload(r)
	if err != nil {
		t.Fatalf("SDK encode: %v", err)
	}
	return b
}

func post(t *testing.T, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/network/rotation", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRotationDoor_ValidRotationReachesTheChokepoint(t *testing.T) {
	proc := &stubProcessor{newSet: []types.WitnessPublicKey{{}, {}}}
	h := api.NewRotationHandler(proc)

	rec := post(t, h, validRotationBody(t))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("code = %d, want 202: %s", rec.Code, rec.Body)
	}
	if proc.called != 1 {
		t.Fatalf("ProcessRotation called %d times, want 1", proc.called)
	}
	if proc.gotHash != ([32]byte{0x01}) {
		t.Errorf("the decoded rotation did not reach the processor intact")
	}
	var out struct {
		Applied         bool `json:"applied"`
		NewWitnessCount int  `json:"new_witness_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Applied || out.NewWitnessCount != 2 {
		t.Errorf("response = %+v", out)
	}
}

func TestRotationDoor_MalformedBodyIs422_ProcessorUntouched(t *testing.T) {
	proc := &stubProcessor{}
	h := api.NewRotationHandler(proc)

	for _, body := range [][]byte{
		[]byte("{not json"),
		[]byte(`{"kind":"BP-ENTRY-WITNESS-ROTATION-PAYLOAD-V1"}`), // decodes-ish but structurally empty
	} {
		rec := post(t, h, body)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("malformed body: code = %d, want 422 (%s)", rec.Code, rec.Body)
		}
	}
	if proc.called != 0 {
		t.Fatalf("the chokepoint must NEVER be reached by a structurally-invalid body (called %d)", proc.called)
	}
}

func TestRotationDoor_ProcessorRejectionIs422_NotInternalError(t *testing.T) {
	proc := &stubProcessor{err: witness.ErrWitnessRotationZeroSetHash} // any verify-class error
	h := api.NewRotationHandler(proc)

	rec := post(t, h, validRotationBody(t))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a processor rejection is the submitter's Domain Violation (422), got %d", rec.Code)
	}
	if proc.called != 1 {
		t.Fatal("the structural door passed it through; the processor must have been consulted")
	}
}

func TestRotationDoor_BodyIsSizeBounded(t *testing.T) {
	proc := &stubProcessor{}
	h := api.NewRotationHandler(proc)
	// A megabyte of junk must not be read into memory unbounded — it is
	// truncated by the LimitReader and then fails structural decode (422).
	rec := post(t, h, []byte(strings.Repeat("A", 1<<20)))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("oversize junk should be bounded then rejected, got %d", rec.Code)
	}
	if proc.called != 0 {
		t.Fatal("oversize junk must never reach the chokepoint")
	}
}
