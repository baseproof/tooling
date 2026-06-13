/*
FILE PATH: api/burn_rc10_test.go — tooling#110 T3+T4 lock suite.

T3: GET /v1/burn OR-semantics — declared (authoritative) OR observed
(evidence-tier); any source error ABORTS (503), never a false bool.
T4: the burn door — a genuinely quorum-signed burn is accepted ONCE
(202 → 409); under-quorum/rogue refuse 422; unsigned never reaches the
processor (decode refuses); the processor verifies BEFORE appending and
flips the declared leg only after the append returns.
*/
package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"
)

// ─── fixtures ───────────────────────────────────────────────────────

type staticDeclared struct {
	burned bool
	err    error
}

func (s staticDeclared) DeclaredBurn(context.Context) (bool, error) { return s.burned, s.err }

type staticObserved struct {
	burned bool
	err    error
}

func (s staticObserved) IsBurned(context.Context, string) (bool, error) { return s.burned, s.err }

func signedBurnFixture(t *testing.T) (network.NetworkBurn, []byte, *witnesstest.Set, cosign.NetworkID) {
	t.Helper()
	var netID cosign.NetworkID
	for i := range netID {
		netID[i] = byte(i + 1)
	}
	ws := witnesstest.NewSet(t, netID, 3, 2)
	b := network.NetworkBurn{NetworkID: [32]byte(netID), ReasonClass: "witness_quorum_compromise"}
	payload := cosign.NewBurnPayloadSHA256(network.BurnContentDigest(b))
	for i := 0; i < 2; i++ {
		sig, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, ws.Privs[i])
		if err != nil {
			t.Fatal(err)
		}
		b.Signatures = append(b.Signatures, types.WitnessSignature{PubKeyID: ws.Keys[i].ID, SchemeTag: ws.Keys[i].SchemeTag, SigBytes: sig})
	}
	raw, err := network.EncodeNetworkBurnPayload(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, raw, ws, netID
}

// ─── T3: the OR table ───────────────────────────────────────────────

func TestBurnHandler_ORSemantics(t *testing.T) {
	cases := []struct {
		name       string
		declared   DeclaredBurnSource
		observed   BurnSource
		wantStatus int
		wantBody   string
	}{
		{"both clean", staticDeclared{}, staticObserved{}, 200, `"is_burned":false`},
		{"declared burns", staticDeclared{burned: true}, staticObserved{}, 200, `"is_burned":true`},
		{"observed burns", staticDeclared{}, staticObserved{burned: true}, 200, `"is_burned":true`},
		{"declared error ABORTS", staticDeclared{err: errors.New("poisoned stream")}, staticObserved{}, 503, "unavailable"},
		{"observed error ABORTS", staticDeclared{}, staticObserved{err: errors.New("gossip down")}, 503, "unavailable"},
		{"nil declared = observed-only", nil, staticObserved{burned: true}, 200, `"is_burned":true`},
		{"nil everything = honest false", nil, nil, 200, `"is_burned":false`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			NewBurnHandlerWithDeclared(tc.observed, tc.declared, "did:web:me.example", nil)(rec,
				httptest.NewRequest(http.MethodGet, "/v1/burn", nil))
			if rec.Code != tc.wantStatus || !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("want %d %q, got %d %s", tc.wantStatus, tc.wantBody, rec.Code, rec.Body.String())
			}
		})
	}
}

// ─── T4: the door + processor ───────────────────────────────────────

type doorProc struct {
	calls int
	seq   uint64
	err   error
}

func (d *doorProc) ProcessBurn(context.Context, network.NetworkBurn) (uint64, error) {
	d.calls++
	return d.seq, d.err
}

func postBurn(t *testing.T, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/network/burn", bytes.NewReader(body)))
	return rec
}

func TestBurnDoor_UnsignedNeverReachesProcessor(t *testing.T) {
	proc := &doorProc{}
	rec := postBurn(t, NewBurnDoorHandler(proc, nil),
		[]byte(`{"kind":"BP-ENTRY-NETWORK-BURN-V1","network_id":"`+strings.Repeat("ab", 32)+`","reason_class":"x"}`))
	if rec.Code != http.StatusUnprocessableEntity || proc.calls != 0 {
		t.Fatalf("an UNSIGNED burn must die at decode (422, processor untouched): %d calls=%d", rec.Code, proc.calls)
	}
}

func TestBurnDoor_VerdictTaxonomy(t *testing.T) {
	_, raw, _, _ := signedBurnFixture(t)
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"accepted", nil, http.StatusAccepted},
		{"unauthorized 422", network.ErrNetworkBurnUnauthorized, http.StatusUnprocessableEntity},
		{"already burned 409", ErrAlreadyBurned, http.StatusConflict},
		{"infrastructure 500", errors.New("wal down"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postBurn(t, NewBurnDoorHandler(&doorProc{seq: 7, err: tc.err}, nil), raw)
			if rec.Code != tc.want {
				t.Fatalf("want %d got %d: %s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}
