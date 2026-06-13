/*
FILE PATH: libs/cli/burn_cmd_test.go

tooling#110 Category-A proof: the `network burn` verb chain driven end-to-end
IN PROCESS (httptest, no PG, no Docker). draft → consent (×K) → finalize →
submit, against an httptest server serving the live witness set and the burn
door. The finalize self-verify (make-invalid-unconstructible) and the submit
local re-verify (refuse-by-name before POST) are the two doctrine properties
this pins.
*/
package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/types"
)

// burnKey is one witness: an ECDSA private key plus the WitnessPublicKey the
// served set advertises. ID = sha256(pubkey) — the SAME derivation the
// consent verb performs, so a cosignature maps to its set member.
type burnKey struct {
	priv *ecdsa.PrivateKey
	pub  types.WitnessPublicKey
}

func genBurnKey(t *testing.T) burnKey {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	return burnKey{
		priv: priv,
		pub:  types.WitnessPublicKey{ID: sha256.Sum256(pub), PublicKey: pub, SchemeTag: signatures.SchemeECDSA},
	}
}

// burnTestServer mounts /v1/network/witnesses/current (the live set) and a
// burn door that records the posted payload and returns 202.
func burnTestServer(t *testing.T, keys []burnKey) (*httptest.Server, *[]byte) {
	t.Helper()
	pubs := make([]types.WitnessPublicKey, len(keys))
	for i, k := range keys {
		pubs[i] = k.pub
	}
	var posted []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/network/witnesses/current", serveWitnessCurrent(pubs...))
	mux.HandleFunc("/v1/network/burn", func(w http.ResponseWriter, r *http.Request) {
		posted, _ = readAllLimited(r)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"burned","sequence":7}`))
	})
	return httptest.NewServer(mux), &posted
}

func readAllLimited(r *http.Request) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func TestNetworkBurnVerb_FullPipeline(t *testing.T) {
	ctx := context.Background()
	// K=2 of 3. The network id is arbitrary but must match the bundle and the
	// set the consents bind to; build keys whose set we both serve and sign.
	keys := []burnKey{genBurnKey(t), genBurnKey(t), genBurnKey(t)}
	srv, posted := burnTestServer(t, keys)
	defer srv.Close()

	// The served set hash binds to the network — but the burn payload's
	// NetworkID is the bundle's. Use a fixed 32-byte id; the witness set is
	// constructed with that NetworkID inside liveWitnessKeySet, so VerifyBurn
	// binds consistently.
	nid := strings.Repeat("ab", 32)
	bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 2})

	dir := t.TempDir()
	draftPath := filepath.Join(dir, "draft.json")
	c0Path := filepath.Join(dir, "c0.json")
	c1Path := filepath.Join(dir, "c1.json")
	finalPath := filepath.Join(dir, "burn.bin")

	// draft
	if err := burnDraftCmd(ctx, []string{
		"--bundle", bp, "--reason-class", "witness_quorum_compromise",
		"--evidence", "gossip:event:abc", "--out", draftPath, "--output", "json",
	}); err != nil {
		t.Fatalf("draft: %v", err)
	}

	// consent ×2 — each witness signs the draft with its own key.
	writeKeyFile := func(t *testing.T, k burnKey) string {
		t.Helper()
		raw := privScalarHex(t, k.priv)
		p := filepath.Join(dir, "key-"+raw[:8]+".hex")
		if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for i, out := range []string{c0Path, c1Path} {
		if err := burnConsentCmd(ctx, []string{
			"--draft", draftPath, "--key-file", writeKeyFile(t, keys[i]), "--out", out, "--output", "json",
		}); err != nil {
			t.Fatalf("consent %d: %v", i, err)
		}
	}

	// finalize — self-verifies through VerifyBurn against the live set.
	if err := burnFinalizeCmd(ctx, []string{
		"--bundle", bp, "--draft", draftPath, "--consent", c0Path, "--consent", c1Path,
		"--out", finalPath, "--output", "json",
	}); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// submit --dry-run: verifies locally, must NOT post.
	if err := burnSubmitCmd(ctx, []string{"--bundle", bp, "--in", finalPath, "--dry-run", "--output", "json"}); err != nil {
		t.Fatalf("submit dry-run: %v", err)
	}
	if *posted != nil {
		t.Fatal("dry-run must NOT post to the door")
	}

	// submit for real: posts the finalized bytes; the door records them.
	if err := burnSubmitCmd(ctx, []string{"--bundle", bp, "--in", finalPath, "--output", "json"}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if *posted == nil {
		t.Fatal("submit must post the finalized burn to the door")
	}
	// The posted bytes ARE the finalized payload.
	want, _ := os.ReadFile(finalPath)
	if hex.EncodeToString(*posted) != hex.EncodeToString(want) {
		t.Fatal("posted bytes differ from the finalized payload")
	}
}

// TestNetworkBurnVerb_UnderQuorum_Unconstructible: finalize with K-1 consents
// is REFUSED — the verb cannot mint an under-quorum burn (assembly shares the
// verifier). The doctrine's make-invalid-unconstructible, at CLI altitude.
func TestNetworkBurnVerb_UnderQuorum_Unconstructible(t *testing.T) {
	ctx := context.Background()
	keys := []burnKey{genBurnKey(t), genBurnKey(t), genBurnKey(t)}
	srv, _ := burnTestServer(t, keys)
	defer srv.Close()
	nid := strings.Repeat("ab", 32)
	bp := writeBundle(t, ClientBundle{NetworkID: nid, Endpoint: srv.URL, LogDID: "did:web:x", QuorumK: 2})

	dir := t.TempDir()
	draftPath := filepath.Join(dir, "draft.json")
	c0Path := filepath.Join(dir, "c0.json")
	if err := burnDraftCmd(ctx, []string{"--bundle", bp, "--reason-class", "x", "--out", draftPath, "--output", "json"}); err != nil {
		t.Fatal(err)
	}
	kf := filepath.Join(dir, "k0.hex")
	if err := os.WriteFile(kf, []byte(privScalarHex(t, keys[0].priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := burnConsentCmd(ctx, []string{"--draft", draftPath, "--key-file", kf, "--out", c0Path, "--output", "json"}); err != nil {
		t.Fatal(err)
	}
	// Only ONE consent for a K=2 set — finalize must refuse to assemble.
	err := burnFinalizeCmd(ctx, []string{"--bundle", bp, "--draft", draftPath, "--consent", c0Path, "--out", filepath.Join(dir, "b.bin"), "--output", "json"})
	if err == nil || !strings.Contains(err.Error(), "refused to assemble") {
		t.Fatalf("under-quorum finalize must refuse: %v", err)
	}
}

func privScalarHex(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	d := priv.D.Bytes()
	out := make([]byte, 32) // left-pad to 32
	copy(out[32-len(d):], d)
	return hex.EncodeToString(out)
}
