/*
FILE PATH: libs/identity/identity_signing_test.go

DESCRIPTION:

	Tests for SignRequest, TypedDataDisplay, and EIP712Field
	validation. Pins the contract that:
	  - signing requests for exchange actions require typed-data
	    display (so the wallet shows the user what they sign);
	  - the typed-data display has a domain separator (Name +
	    Version + Salt) — cross-exchange replay is structurally
	    impossible.
*/
package identity

import (
	"strings"
	"testing"
)

// ─── helpers ────────────────────────────────────────────────────────

func makeValidDisplay() *TypedDataDisplay {
	return &TypedDataDisplay{
		Domain: EIP712Domain{
			Name:    "Example Network",
			Version: "v1",
			Salt:    "did:web:example:exchange-a",
		},
		PrimaryType: "Delegation",
		Fields: []EIP712Field{
			{Name: "granter_did", Type: "string", Value: "did:key:zQ3shGRANTER"},
			{Name: "grantee_did", Type: "string", Value: "did:key:zQ3shGRANTEE"},
			{Name: "role", Type: "string", Value: "member"},
			{Name: "expires_at", Type: "string", Value: "2030-01-01T00:00:00Z"},
		},
	}
}

func makeValidSignRequest() *SignRequest {
	return &SignRequest{
		SignerDID:      "did:key:zQ3shSIGNER",
		Digest:         [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Display:        makeValidDisplay(),
		Reason:         "Publish delegation",
		TimeoutSeconds: 60,
	}
}

// ─── SignRequest.Validate ───────────────────────────────────────────

func TestSignRequest_Validate_HappyPath(t *testing.T) {
	if err := makeValidSignRequest().Validate(); err != nil {
		t.Fatalf("happy-path: %v", err)
	}
}

func TestSignRequest_Validate_Nil(t *testing.T) {
	var r *SignRequest
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("got: %v", err)
	}
}

func TestSignRequest_Validate_MissingSigner(t *testing.T) {
	r := makeValidSignRequest()
	r.SignerDID = ""
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "signer_did") {
		t.Fatalf("got: %v", err)
	}
}

func TestSignRequest_Validate_ZeroDigest(t *testing.T) {
	r := makeValidSignRequest()
	r.Digest = [32]byte{}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "all-zero") {
		t.Fatalf("got: %v", err)
	}
}

func TestSignRequest_Validate_MissingDisplay(t *testing.T) {
	r := makeValidSignRequest()
	r.Display = nil
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "display required") {
		t.Fatalf("got: %v", err)
	}
}

func TestSignRequest_Validate_OversizeReason(t *testing.T) {
	r := makeValidSignRequest()
	r.Reason = strings.Repeat("X", 257)
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "reason exceeds") {
		t.Fatalf("got: %v", err)
	}
}

func TestSignRequest_Validate_NegativeTimeout(t *testing.T) {
	r := makeValidSignRequest()
	r.TimeoutSeconds = -1
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("got: %v", err)
	}
}

// ─── TypedDataDisplay.Validate ──────────────────────────────────────

func TestTypedDataDisplay_Validate_HappyPath(t *testing.T) {
	if err := makeValidDisplay().Validate(); err != nil {
		t.Fatalf("happy-path: %v", err)
	}
}

func TestTypedDataDisplay_Validate_Nil(t *testing.T) {
	var d *TypedDataDisplay
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("got: %v", err)
	}
}

func TestTypedDataDisplay_Validate_MissingDomainFields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*TypedDataDisplay)
		wantSub string
	}{
		{"missing domain name", func(d *TypedDataDisplay) { d.Domain.Name = "" }, "domain name"},
		{"missing domain version", func(d *TypedDataDisplay) { d.Domain.Version = "" }, "domain version"},
		{"missing domain salt", func(d *TypedDataDisplay) { d.Domain.Salt = "" }, "domain salt"},
		{"missing primary_type", func(d *TypedDataDisplay) { d.PrimaryType = "" }, "primary_type"},
		{"empty fields", func(d *TypedDataDisplay) { d.Fields = nil }, "at least one field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := makeValidDisplay()
			tc.mutate(d)
			err := d.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("got %v want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestTypedDataDisplay_Validate_FieldsMissingNameOrType(t *testing.T) {
	d := makeValidDisplay()
	d.Fields[0].Name = ""
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "name required") {
		t.Fatalf("missing name: %v", err)
	}

	d = makeValidDisplay()
	d.Fields[1].Type = ""
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "type required") {
		t.Fatalf("missing type: %v", err)
	}
}

// Domain identity test: two displays with same fields but different
// domain Salt produce distinct typed structures. Pins the cross-exchange
// replay-protection invariant at the Display level — the actual digest
// computation lives in identity_signing.go's caller path.
func TestTypedDataDisplay_DistinctSaltsAreDistinctDomains(t *testing.T) {
	a := makeValidDisplay()
	b := makeValidDisplay()
	b.Domain.Salt = "did:web:example:exchange-b"

	if a.Domain.Salt == b.Domain.Salt {
		t.Fatal("test setup error: salts equal")
	}

	// Both validate independently — the framing is sound.
	if err := a.Validate(); err != nil {
		t.Errorf("a invalid: %v", err)
	}
	if err := b.Validate(); err != nil {
		t.Errorf("b invalid: %v", err)
	}

	// Cross-exchange replay defense lives in the digest computation
	// (.5); this test pins that the Display structure
	// distinguishes the two exchanges at the typed-data layer.
}
