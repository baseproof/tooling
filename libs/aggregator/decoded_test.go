package aggregator

import (
	"encoding/hex"
	"testing"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/clitools"
)

func TestDecode_RootEntity(t *testing.T) {
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:test",
		Payload:     mustJSON(t, map[string]any{"docket_number": "2027-CR-001"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d, err := Decode("test-log", rawFrom(t, 7, entry))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.LogDID != "test-log" || d.Sequence != 7 {
		t.Errorf("logDID/seq = %q/%d, want test-log/7", d.LogDID, d.Sequence)
	}
	if d.SignerDID != "did:web:test" {
		t.Errorf("signer = %q", d.SignerDID)
	}
	if d.TargetRootSeq != nil {
		t.Error("root entity should have nil TargetRootSeq")
	}
	if d.Payload["docket_number"] != "2027-CR-001" {
		t.Errorf("payload not preserved: %v", d.Payload)
	}
}

func TestDecode_Amendment(t *testing.T) {
	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: "did:web:exchange.test",
		SignerDID:   "did:web:test",
		TargetRoot:  types.LogPosition{LogDID: "test", Sequence: 10},
		Payload:     mustJSON(t, map[string]any{"status": "disposed"}),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	d, err := Decode("test-log", rawFrom(t, 11, entry))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.TargetRootSeq == nil || *d.TargetRootSeq != 10 {
		t.Errorf("TargetRootSeq = %v, want 10", d.TargetRootSeq)
	}
	if d.AuthorityPath != "same_signer" {
		t.Errorf("authority = %q, want same_signer", d.AuthorityPath)
	}
}

func TestDecode_FailClosed(t *testing.T) {
	if _, err := Decode("l", clitools.RawEntry{CanonicalHex: "not-hex"}); err == nil {
		t.Error("expected error on non-hex canonical")
	}
	if _, err := Decode("l", clitools.RawEntry{CanonicalHex: hex.EncodeToString([]byte("garbage"))}); err == nil {
		t.Error("expected error on undeserializable bytes")
	}
}
