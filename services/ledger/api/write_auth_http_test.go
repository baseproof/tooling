package api

// write_auth_http_test.go — gate-5 (the JN "gating" axis) enforced over the REAL
// /v1/entries HTTP path, no Postgres. A gated network MUST refuse any write that
// does not carry a valid detached WriteAuthorization signed by an on-log admission
// authority (the JN) — that is how "gating by the network" makes a submission
// conform to domain logic, ORTHOGONAL to the payment axis (here the request is
// authenticated = the credit path, so Mode-B PoW is skipped; both paths still
// require this signature).
//
// This drives the real SubmissionHandler (wrapped in the real Auth middleware) and
// asserts: an authenticated submission with NO write-authorization → 403, with an
// UNAUTHORIZED signer's authorization → 403 (fail-closed). A valid JN-signed
// authorization is accepted by the gate (VerifyWriteAuthorization == nil — the same
// call the handler makes at step 8b); the full 202 admit is the platform-e2e
// (Postgres/builder) tier.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/baseproof/tooling/services/ledger/admission"
	"github.com/baseproof/tooling/services/ledger/api/middleware"
)

const gateLogDID = "did:web:court.example"

// stubAdmissionKeyset is the on-log admission-authority set the gate resolves.
type stubAdmissionKeyset struct{ set [][20]byte }

func (s stubAdmissionKeyset) Current(context.Context) ([][20]byte, error) { return s.set, nil }

// alwaysAuth marks every Bearer token valid — the credit/authenticated path
// (so the PoW gate is skipped), leaving gate-5 as the sole admission decision.
type alwaysAuth struct{}

func (alwaysAuth) LookupSession(context.Context, string) (string, time.Time, error) {
	return "did:web:exchange.test", time.Now().Add(time.Hour), nil
}

// jnAuthority mints a JN admission key + its EOA address.
func jnAuthority(t *testing.T) (*secp256k1.PrivateKey, [20]byte) {
	t.Helper()
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr, err := signatures.AddressFromPubkey(k.PubKey().SerializeUncompressed())
	if err != nil {
		t.Fatal(err)
	}
	return k, addr
}

// freshSignedEntry builds a fresh, validly-signed entity bound to gateLogDID, and
// returns its wire bytes + canonical identity (what the WriteAuthorization binds).
func freshSignedEntry(t *testing.T) ([]byte, [32]byte) {
	t.Helper()
	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID: kp.DID, Destination: gateLogDID, EventTime: time.Now().UTC().UnixMicro(),
	}, []byte("gated-domain-entry"))
	if err != nil {
		t.Fatal(err)
	}
	signHash := sha256.Sum256(envelope.SigningPayload(unsigned))
	sig, err := signatures.SignEntry(signHash, kp.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Signatures = []envelope.Signature{{SignerDID: kp.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	if err := unsigned.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := envelope.Serialize(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	id, err := envelope.EntryIdentity(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	return raw, id
}

// gatedHandler wires the REAL SubmissionHandler with gate-5 ON (GatingRequired) +
// the supplied admission-authority keyset, behind the real Auth middleware.
func gatedHandler(t *testing.T, keyset admission.AdmissionKeyset) http.Handler {
	t.Helper()
	signerPriv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	deps := &SubmissionDeps{
		LogDID:           gateLogDID,
		LedgerDID:        "did:web:ledger.test",
		LedgerSignerPriv: signerPriv,
		MaxEntrySize:     1 << 20,
		Admission:        AdmissionConfig{EpochWindowSeconds: 3600, EpochAcceptanceWindow: 1},
		// Gate-5 ON: the network's policy requires a write authorization.
		AdmissionPolicy:      admission.StaticAdmissionPolicy{Policy: authz.AdmissionPolicy{GatingRequired: true, CostMode: authz.CostModeUncharged}},
		AdmissionAuthorities: keyset,
		FreshnessTolerance:   time.Hour,
		Logger:               slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	return middleware.Auth(alwaysAuth{}, NewSubmissionHandler(deps))
}

func postEntry(h http.Handler, raw []byte, writeAuthB64 string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/entries", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer credit-session") // authenticated ⇒ skip PoW
	if writeAuthB64 != "" {
		req.Header.Set(admission.WriteAuthHeader, writeAuthB64)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func encodeWriteAuth(t *testing.T, sk *secp256k1.PrivateKey, id [32]byte) string {
	t.Helper()
	var anchor [32]byte // the auditor re-derives the anchor; the gate verifies the signature
	wa, err := authz.SignWriteAuthorization(sk.ToECDSA(), gateLogDID, id, anchor)
	if err != nil {
		t.Fatal(err)
	}
	b, err := wa.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestSubmission_Gate5_HTTP proves gate-5 is enforced on the real /v1/entries path.
func TestSubmission_Gate5_HTTP(t *testing.T) {
	jnKey, jnAddr := jnAuthority(t)
	keyset := stubAdmissionKeyset{set: [][20]byte{jnAddr}}
	h := gatedHandler(t, keyset)

	// assertGate5Reject checks the response is a 403 from GATE-5 specifically (the
	// "write authorization" message), not an earlier 403 (PoW/destination) — so the
	// test can't pass for the wrong reason.
	assertGate5Reject := func(label string, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := rec.Body.String()
		if rec.Code != http.StatusForbidden || !strings.Contains(body, "write authorization") {
			t.Fatalf("%s: status=%d body=%q — want 403 with a gate-5 'write authorization' rejection", label, rec.Code, body)
		}
	}

	// 1) Authenticated (credit) submission with NO write-authorization → gate-5 403.
	raw, id := freshSignedEntry(t)
	assertGate5Reject("no write-auth (gating is a must)", postEntry(h, raw, ""))

	// 2) Write-authorization from an UNAUTHORIZED signer (not in the keyset) → gate-5 403.
	otherKey, _ := jnAuthority(t)
	assertGate5Reject("unauthorized signer (fail-closed)", postEntry(h, raw, encodeWriteAuth(t, otherKey, id)))

	// 3) A valid JN-signed write-authorization is ACCEPTED by the gate — the SAME
	//    call the handler makes at step 8b. (The full 202 admit needs the
	//    builder/WAL pipeline = the platform-e2e tier.)
	enc := encodeWriteAuth(t, jnKey, id)
	if err := admission.VerifyWriteAuthorization(context.Background(), enc, id, gateLogDID, keyset); err != nil {
		t.Fatalf("a valid JN write-authorization was REJECTED by the gate: %v", err)
	}

}
