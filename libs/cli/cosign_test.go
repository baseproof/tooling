/*
FILE PATH: libs/cli/cosign_test.go

DESCRIPTION:

	PRE-5 acceptance, end to end against a gated stub network:

	  - the full relay scene: primary drafts (rule derived from the
	    DOOR-VERIFIED manifest) → file relay → countersigner renders and
	    signs → submit clears the gate, and the POSTED WIRE is exactly the
	    in-band multi-sig model the gate already verifies (N signatures over
	    the SAME payload — asserted by deserializing the gate's capture);
	  - TAMPERED DRAFT refused at render (digest pin), before any signing;
	  - a tampered COLLECTED SIGNATURE refused at render (cryptographic
	    verification — no blind countersigning);
	  - INCOMPLETE MIX refused client-side at submit, with zero bytes ever
	    reaching the gate (the relay never wastes the gate's time on what it
	    can prove incomplete — and the gate re-verifies regardless);
	  - wrong-role countersign refused; duplicate signer refused;
	  - an operation with no Signing rule refuses to draft (plain submit's
	    job).
*/
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkenv "github.com/baseproof/baseproof/core/envelope"

	"github.com/baseproof/tooling/libs/networkbundle"
	"github.com/baseproof/tooling/libs/policy"
)

// gatedNet extends the bundle stub with a manifest carrying cosignature-ruled
// operations and the write gate's submit route, capturing posted wire bytes.
type gatedNet struct {
	*bundleNet
	gateURL  string
	captured [][]byte
}

func newGatedNet(t *testing.T) *gatedNet {
	t.Helper()
	n := newBundleNet(t)
	g := &gatedNet{bundleNet: n}

	// The manifest: one ruled operation (sealing-class: approver must
	// countersign) and one rule-free operation.
	m := &networkbundle.Manifest{
		Format:   networkbundle.ManifestFormat,
		Network:  networkbundle.NetworkRef{NetworkID: n.nidHex, Name: "gated-stub"},
		Exchange: n.dest,
		Operations: []networkbundle.Operation{
			networkbundle.NewOperation("record_seal",
				&policy.CosignatureRule{
					EventType:           "record_seal",
					AllowedFilerRoles:   []policy.FilerRole{"operator"},
					RequiredSignerRoles: []string{"approver"},
					MinSignerCosigners:  1,
					IntraExchangeOnly:   true,
				}, nil, networkbundle.OpOverlay{PrimaryRole: "registrar"}),
			networkbundle.NewOperation("record_note", nil, nil, networkbundle.OpOverlay{}),
		},
	}
	var err error
	g.manifest, err = m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	gate := http.NewServeMux()
	gate.HandleFunc("POST /v1/entries/submit", func(w http.ResponseWriter, r *http.Request) {
		wire, _ := readBody(r)
		g.captured = append(g.captured, wire)
		h := sha256.Sum256(wire)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"canonical_hash": hex.EncodeToString(h[:])})
	})
	gsrv := httptest.NewServer(gate)
	t.Cleanup(gsrv.Close)
	g.gateURL = gsrv.URL
	return g
}

func gatedClientBundle(t *testing.T, g *gatedNet) string {
	t.Helper()
	return writeBundle(t, ClientBundle{
		NetworkID: g.nidHex, Endpoint: g.url, LogDID: "did:web:stub-log",
		QuorumK: 1, BootstrapHash: g.nidHex, WriteEndpoint: g.gateURL,
	})
}

func loadReq(t *testing.T, path string) *CosignRequest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r CosignRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func TestCosignRelay_FullScene(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	ctx := context.Background()
	g := newGatedNet(t)
	cb := gatedClientBundle(t, g)
	primary, counter := signerKeyFile(t), signerKeyFile(t)
	reqPath := filepath.Join(t.TempDir(), "seal.cosign.json")

	// 1) The primary drafts: rule derived from the door-verified manifest;
	//    the primary's own signature is collected[0].
	if err := RunCosign(ctx, []string{"draft", "--bundle", cb,
		"--operation", "record_seal", "--payload", `{"record_id":"r-1","action":"seal"}`,
		"--signer-key", primary, "--out", reqPath}); err != nil {
		t.Fatalf("draft: %v", err)
	}
	req := loadReq(t, reqPath)
	if req.Signing == nil || req.Signing.EventType != "record_seal" || len(req.Collected) != 1 {
		t.Fatalf("draft artifact = %+v", req)
	}
	if req.Collected[0].Role != "registrar" {
		t.Fatalf("primary role must default to the operation's primary_role: %+v", req.Collected[0])
	}

	// 2) Incomplete submit: refused CLIENT-SIDE, zero bytes reach the gate.
	err := RunCosign(ctx, []string{"submit", "--bundle", cb, reqPath})
	if err == nil || !strings.Contains(err.Error(), "incomplete mix") {
		t.Fatalf("incomplete mix must refuse client-side: %v", err)
	}
	if len(g.captured) != 0 {
		t.Fatal("an incomplete relay must never reach the gate")
	}

	// 3) Wrong-role countersign refused by the embedded rule.
	err = RunCosign(ctx, []string{"sign", "--signer-key", counter, "--role", "intruder", reqPath})
	if err == nil || !strings.Contains(err.Error(), "required_signer_roles") {
		t.Fatalf("wrong role must refuse: %v", err)
	}

	// 4) The countersigner renders + signs (render verifies the primary's
	//    signature cryptographically before adding their own).
	if err := RunCosign(ctx, []string{"sign", "--signer-key", counter, "--role", "approver", reqPath}); err != nil {
		t.Fatalf("countersign: %v", err)
	}

	// 5) Duplicate signer refused.
	err = RunCosign(ctx, []string{"sign", "--signer-key", counter, "--role", "approver", reqPath})
	if err == nil || !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("duplicate signer must refuse: %v", err)
	}

	// 6) Submit clears the gate; the posted wire IS model #1: two signatures
	//    over the SAME payload, primary first.
	out, err := captureStdout(t, func() error {
		return RunCosign(ctx, []string{"submit", "--bundle", cb, "--output=json", reqPath})
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	_ = decodeEnvelope(t, out, "cosign-submit")
	if len(g.captured) != 1 {
		t.Fatalf("gate captured %d submissions, want 1", len(g.captured))
	}
	entry, err := sdkenv.Deserialize(g.captured[0])
	if err != nil {
		t.Fatalf("posted wire must be a valid entry: %v", err)
	}
	if len(entry.Signatures) != 2 {
		t.Fatalf("posted entry carried %d signatures, want 2 (primary + approver)", len(entry.Signatures))
	}
	if entry.Signatures[0].SignerDID != req.Collected[0].SignerDID {
		t.Fatal("the primary must sign first in the assembled wire")
	}
	if string(entry.DomainPayload) != `{"record_id":"r-1","action":"seal"}` {
		t.Fatal("payload must ride the relay byte-exactly")
	}
}

func TestCosignRelay_TamperRefusedAtRender(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	ctx := context.Background()
	g := newGatedNet(t)
	cb := gatedClientBundle(t, g)
	key := signerKeyFile(t)
	reqPath := filepath.Join(t.TempDir(), "seal.cosign.json")

	if err := RunCosign(ctx, []string{"draft", "--bundle", cb,
		"--operation", "record_seal", "--payload", `{"record_id":"r-2"}`,
		"--signer-key", key, "--out", reqPath}); err != nil {
		t.Fatal(err)
	}

	// Tamper the DRAFT (payload swap): digest pin must refuse at render —
	// show, sign, and submit all go through the same door.
	req := loadReq(t, reqPath)
	req.Draft.PayloadB64 = base64.StdEncoding.EncodeToString([]byte(`{"record_id":"EVIL"}`))
	if err := writeCosignRequest(reqPath, req); err != nil {
		t.Fatal(err)
	}
	for _, verb := range [][]string{
		{"show", reqPath},
		{"sign", "--signer-key", signerKeyFile(t), "--role", "approver", reqPath},
		{"submit", "--bundle", cb, reqPath},
	} {
		if err := RunCosign(ctx, verb); err == nil || !strings.Contains(err.Error(), "TAMPERED draft") {
			t.Fatalf("%v must refuse a tampered draft: %v", verb[0], err)
		}
	}
	if len(g.captured) != 0 {
		t.Fatal("a tampered draft must never reach the gate")
	}
}

func TestCosignRelay_ForgedCollectedSignatureRefused(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	ctx := context.Background()
	g := newGatedNet(t)
	cb := gatedClientBundle(t, g)
	key := signerKeyFile(t)
	reqPath := filepath.Join(t.TempDir(), "seal.cosign.json")

	if err := RunCosign(ctx, []string{"draft", "--bundle", cb,
		"--operation", "record_seal", "--payload", `{"record_id":"r-3"}`,
		"--signer-key", key, "--out", reqPath}); err != nil {
		t.Fatal(err)
	}
	// Corrupt the primary's collected signature: render must catch it
	// cryptographically — no countersigner ever signs beside a forgery.
	req := loadReq(t, reqPath)
	sig, _ := base64.StdEncoding.DecodeString(req.Collected[0].SignatureB64)
	sig[7] ^= 0x01
	req.Collected[0].SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	if err := writeCosignRequest(reqPath, req); err != nil {
		t.Fatal(err)
	}
	err := RunCosign(ctx, []string{"show", reqPath})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a forged collected signature must refuse at render: %v", err)
	}
}

func TestCosignDraft_RuleFreeOperationRefused(t *testing.T) {
	t.Setenv("BASEPROOF_CONFIG_DIR", t.TempDir())
	g := newGatedNet(t)
	cb := gatedClientBundle(t, g)
	err := RunCosign(context.Background(), []string{"draft", "--bundle", cb,
		"--operation", "record_note", "--payload", `{}`,
		"--signer-key", signerKeyFile(t), "--out", filepath.Join(t.TempDir(), "x.json")})
	if err == nil || !strings.Contains(err.Error(), "requires no cosignature mix") {
		t.Fatalf("a rule-free operation must refuse to draft: %v", err)
	}
}
