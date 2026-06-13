package cli

// via_gate_test.go — the gated write path (model #1 in-band cosigners over the
// through-gate submit). submitViaGate multi-signs the entry, POSTs it to the
// write gate's /v1/entries/submit, and resolves the sequence from the LEDGER's
// /v1/entries-hash. The gate stub captures the posted wire so we assert it
// carried the primary PLUS every inline cosigner signature — the exact bundle
// the gate's cosignature policy then gates. No docker: httptest stands in for
// the gate + ledger read surface.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/baseproof/tooling/libs/loadgen"
)

func TestSubmitViaGate(t *testing.T) {
	var gotWire []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/entries/submit":
			gotWire, _ = io.ReadAll(r.Body)
			h := sha256.Sum256(gotWire)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]string{"canonical_hash": hex.EncodeToString(h[:])})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/entries-hash/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"sequence_number": uint64(42)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	logDID := "did:web:court.example"
	b := &ClientBundle{Endpoint: srv.URL, WriteEndpoint: srv.URL, LogDID: logDID}

	primaryKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	primary := loadgen.Identity{DID: primaryKP.DID, Priv: primaryKP.PrivateKey}
	cosignKP, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	cosigners := []loadgen.Identity{{DID: cosignKP.DID, Priv: cosignKP.PrivateKey}}

	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: logDID, SignerDID: primary.DID, Payload: []byte("gated-domain-entry"),
		EventTime: time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		t.Fatal(err)
	}

	seq, err := submitViaGate(context.Background(), srv.Client(), b, entry, primary, cosigners, 5*time.Second, false)
	if err != nil {
		t.Fatalf("submitViaGate: %v", err)
	}
	if seq != 42 {
		t.Fatalf("seq = %d, want 42 (resolved from the ledger read surface)", seq)
	}

	// The wire the gate received MUST carry the primary + the inline cosigner sig —
	// that is exactly the multi-sig bundle the gate's cosignature policy gates.
	got, err := envelope.Deserialize(gotWire)
	if err != nil {
		t.Fatalf("deserialize posted wire: %v", err)
	}
	if len(got.Signatures) != 1+len(cosigners) {
		t.Fatalf("posted entry carried %d signatures, want %d (primary + %d cosigner)",
			len(got.Signatures), 1+len(cosigners), len(cosigners))
	}
	if got.Signatures[0].SignerDID != primary.DID {
		t.Errorf("Signatures[0] = %s, want the primary %s", got.Signatures[0].SignerDID, primary.DID)
	}
}

func TestParseLogPos(t *testing.T) {
	const def = "did:web:home"
	cases := []struct {
		in      string
		wantLog string
		wantSeq uint64
		wantErr bool
	}{
		{"did:web:court@5", "did:web:court", 5, false},
		{"@7", def, 7, false}, // bare @seq ⇒ this network's log
		{"no-at-sign", "", 0, true},
		{"did:web:court@notnum", "", 0, true},
	}
	for _, c := range cases {
		pos, err := parseLogPos(c.in, def)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseLogPos(%q): want error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLogPos(%q): %v", c.in, err)
			continue
		}
		if pos.LogDID != c.wantLog || pos.Sequence != c.wantSeq {
			t.Errorf("parseLogPos(%q) = %s@%d, want %s@%d", c.in, pos.LogDID, pos.Sequence, c.wantLog, c.wantSeq)
		}
	}
}
