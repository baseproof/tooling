/*
FILE PATH: admission/network_payload_validator_rc10_test.go

v0.0.5-rc1 (rc10) adoption — Tier C tests for the seven registry-expansion
arms of VerifyNetworkPayloadEntry.

# WHAT THIS LOCKS

  - Six STRUCTURAL arms (exchange genesis, destination provision/amend/
    retire, delegation grant, credential attestation): the SDK's validating
    decoder runs at the front door; a malformed payload is a 422 with the
    SDK's field-level text visible; a valid payload passes.
  - The burn AUTHORSHIP arm: an externally-submitted burn record is refused
    OUTRIGHT — even a fully quorum-signed, SDK-valid one — because the burn
    projection is a cache of the log and the burn ceremony's door
    (baseproof/tooling#110) is the only legitimate author. Same rebuild-law
    class as the rotation arm.

Same conventions as the v1.32.0 suite: the SDK's real encoders mint the
valid payloads (no mocks — the L4 contract IS that the SDK runs), and
refusals assert both the typed sentinel and the operator-visible text.
*/
package admission_test

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/credential"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/delegation"
	"github.com/baseproof/baseproof/exchange"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness/witnesstest"

	"github.com/baseproof/tooling/services/ledger/admission"
)

func entryWith(t *testing.T, payload []byte, err error) *envelope.Entry {
	t.Helper()
	if err != nil {
		t.Fatalf("SDK encoder refused a payload this test believes valid: %v", err)
	}
	return &envelope.Entry{DomainPayload: payload}
}

// requireStructuralRefusal asserts the typed sentinel AND that the SDK's
// field-level text survives to the operator.
func requireStructuralRefusal(t *testing.T, raw []byte, wantText string) {
	t.Helper()
	err := admission.VerifyNetworkPayloadEntry(&envelope.Entry{DomainPayload: raw})
	if !errors.Is(err, admission.ErrNetworkPayloadInvalid) {
		t.Fatalf("want ErrNetworkPayloadInvalid, got: %v", err)
	}
	if !strings.Contains(err.Error(), wantText) {
		t.Fatalf("the SDK's structural text must reach the operator; want %q in: %v", wantText, err)
	}
}

func TestVerifyNetworkPayloadEntry_RC10_ValidPayloadsAccepted(t *testing.T) {
	var nid [32]byte
	nid[0] = 0xab

	cases := []struct {
		name string
		raw  []byte
		err  error
	}{
		{name: "exchange genesis"},
		{name: "destination provision"},
		{name: "destination amend"},
		{name: "destination retire"},
		{name: "delegation grant"},
		{name: "credential attestation"},
	}
	cases[0].raw, cases[0].err = exchange.EncodeExchangeGenesisPayload(exchange.ExchangeGenesis{
		ExchangeDID: "did:web:exchange.example", NetworkID: nid, DisplayName: "Davidson County"})
	cases[1].raw, cases[1].err = exchange.EncodeDestinationProvisionPayload(exchange.DestinationProvision{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: "did:web:exchange.example",
		Endpoints: map[string]string{"filing": "https://circuit-1.davidson.example/file"}})
	cases[2].raw, cases[2].err = exchange.EncodeDestinationAmendPayload(exchange.DestinationAmend{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: "did:web:exchange.example",
		Endpoints: map[string]string{"filing": "https://circuit-1.davidson.example/file2"}})
	cases[3].raw, cases[3].err = exchange.EncodeDestinationRetirePayload(exchange.DestinationRetire{
		DestinationRef: "tn/davidson/circuit-1", ExchangeDID: "did:web:exchange.example"})
	cases[4].raw, cases[4].err = delegation.EncodeDelegationGrantPayload(delegation.DelegationGrant{
		OriginRef: "did:web:exchange.example", Subject: "tn/davidson/circuit-1",
		Delegate: "did:pkh:eip155:1:0xabc", Role: "clerk", Scope: []string{"filing"},
		NotBefore: 10, NotAfter: 99999})
	cases[5].raw, cases[5].err = credential.EncodeCredentialAttestationPayload(credential.CredentialAttestation{
		Issuer: "did:web:bar.example", Subject: "did:pkh:eip155:1:0xabc",
		CredentialKey: "bar_license", ValueHash: sha256.Sum256([]byte("salted")),
		NotBefore: 10, NotAfter: 99999})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := admission.VerifyNetworkPayloadEntry(entryWith(t, tc.raw, tc.err)); err != nil {
				t.Fatalf("a valid %s must pass the firewall: %v", tc.name, err)
			}
		})
	}
}

func TestVerifyNetworkPayloadEntry_RC10_StructuralRefusals(t *testing.T) {
	// One canonical violation per family, each a DIFFERENT SDK refusal —
	// proving the arm runs the real validator, not a presence check.
	t.Run("genesis: empty exchange_did", func(t *testing.T) {
		requireStructuralRefusal(t,
			[]byte(`{"kind":"BP-ENTRY-EXCHANGE-GENESIS-V1","exchange_did":"","network_id":"`+strings.Repeat("ab", 32)+`"}`),
			"exchange_did")
	})
	t.Run("provision: non-https endpoint", func(t *testing.T) {
		requireStructuralRefusal(t,
			[]byte(`{"kind":"BP-ENTRY-DESTINATION-PROVISION-V1","destination_ref":"d","exchange_did":"x","endpoints":{"filing":"http://insecure.example"}}`),
			"https")
	})
	t.Run("amend: empty endpoints", func(t *testing.T) {
		requireStructuralRefusal(t,
			[]byte(`{"kind":"BP-ENTRY-DESTINATION-AMEND-V1","destination_ref":"d","exchange_did":"x"}`),
			"endpoints")
	})
	t.Run("retire: missing exchange_did", func(t *testing.T) {
		requireStructuralRefusal(t,
			[]byte(`{"kind":"BP-ENTRY-DESTINATION-RETIRE-V1","destination_ref":"d"}`),
			"exchange_did")
	})
	t.Run("grant: inverted validity window", func(t *testing.T) {
		requireStructuralRefusal(t,
			[]byte(`{"kind":"BP-ENTRY-DELEGATION-GRANT-V1","origin_ref":"o","subject":"s","delegate":"d","not_before":50,"not_after":10}`),
			"not_before")
	})
	t.Run("attestation: empty credential_key", func(t *testing.T) {
		requireStructuralRefusal(t,
			[]byte(`{"kind":"BP-ENTRY-CREDENTIAL-ATTESTATION-V1","issuer":"i","subject":"s","credential_key":"","value_hash":"`+strings.Repeat("cd", 32)+`"}`),
			"credential_key")
	})
}

// TestVerifyNetworkPayloadEntry_RC10_Burn_AuthorshipGate is the strong half
// of the rc10 firewall: a burn that the SDK itself would call VALID — real
// K-of-N witness cosignatures over the real content digest — is still
// refused at this door, because authorship (the ceremony's appender), not
// validity, is the admission criterion. Mirrors the rotation arm's test.
func TestVerifyNetworkPayloadEntry_RC10_Burn_AuthorshipGate(t *testing.T) {
	var netID cosign.NetworkID
	for i := range netID {
		netID[i] = byte(i + 1)
	}
	ws := witnesstest.NewSet(t, netID, 3, 2)
	b := network.NetworkBurn{
		NetworkID:    [32]byte(netID),
		ReasonClass:  "witness_quorum_compromise",
		EvidenceRefs: []string{"gossip:event:equivocation-abc"},
	}
	payload := cosign.NewBurnPayloadSHA256(network.BurnContentDigest(b))
	for i := 0; i < 2; i++ {
		sig, err := cosign.SignECDSA(payload, netID, cosign.HashAlgoSHA256, ws.Privs[i])
		if err != nil {
			t.Fatalf("sign burn: %v", err)
		}
		b.Signatures = append(b.Signatures, types.WitnessSignature{
			PubKeyID: ws.Keys[i].ID, SchemeTag: ws.Keys[i].SchemeTag, SigBytes: sig,
		})
	}
	// Prove the fixture is what we claim: the SDK verifies this burn.
	if err := network.VerifyBurn(b, ws.KeySet); err != nil {
		t.Fatalf("fixture must be a genuinely valid quorum-signed burn: %v", err)
	}
	raw, err := network.EncodeNetworkBurnPayload(b)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	gateErr := admission.VerifyNetworkPayloadEntry(&envelope.Entry{DomainPayload: raw})
	if !errors.Is(gateErr, admission.ErrNetworkPayloadInvalid) {
		t.Fatalf("a VALID quorum-signed external burn must still refuse (authorship, not validity): %v", gateErr)
	}
	if !strings.Contains(gateErr.Error(), "burn ceremony") || !strings.Contains(gateErr.Error(), "tooling#110") {
		t.Fatalf("the rejection must name the authorship rule and the ceremony door: %v", gateErr)
	}

	// Kind alone decides — a malformed burn-kind body gets the same refusal
	// with no decode spent on it.
	bad := []byte(`{"kind":"BP-ENTRY-NETWORK-BURN-V1"}`)
	if err := admission.VerifyNetworkPayloadEntry(&envelope.Entry{DomainPayload: bad}); !errors.Is(err, admission.ErrNetworkPayloadInvalid) {
		t.Fatalf("a malformed burn-kind payload must refuse: %v", err)
	}
}

// TestVerifyNetworkPayloadEntry_RC10_ErrorWraps locks the two-layer
// errors.Is contract for a new arm (sentinel + SDK error text), mirroring
// the v1.32.0 ErrorWraps test.
func TestVerifyNetworkPayloadEntry_RC10_ErrorWraps(t *testing.T) {
	raw := []byte(`{"kind":"BP-ENTRY-DESTINATION-PROVISION-V1","destination_ref":"","exchange_did":"x","endpoints":{"a":"https://h.example"}}`)
	err := admission.VerifyNetworkPayloadEntry(&envelope.Entry{DomainPayload: raw})
	if !errors.Is(err, admission.ErrNetworkPayloadInvalid) {
		t.Fatalf("typed sentinel lost: %v", err)
	}
	if !strings.Contains(err.Error(), "destination_ref") {
		t.Fatalf("SDK field text lost: %v", err)
	}
}
