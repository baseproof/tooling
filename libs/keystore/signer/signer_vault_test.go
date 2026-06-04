/*
FILE PATH: libs/keystore/signer/signer_vault_test.go

DESCRIPTION:

	Sanity test that the keys/v1.Signer adapter composes correctly
	against the Vault Transit backend (not just MemoryKeyStore). The
	vault package's fakeVault httptest server is exercised end-to-end:
	Generate → Adapter.Sign → RecoverSecp256k1 yields the stored
	pubkey, exactly the same way it does for the in-memory backend.
	This confirms the wire-shape translation works regardless of
	custody backend.
*/
package signer_test

import (
	"bytes"
	stdlibecdsa "crypto/ecdsa"
	"crypto/ed25519"
	stdliberand "crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	sdksigs "github.com/baseproof/baseproof/crypto/signatures"

	"github.com/baseproof/tooling/libs/keystore/signer"
	vaultks "github.com/baseproof/tooling/libs/keystore/vault"
)

// fakeVault here is a duplicate of vault_fakeserver_test.go's mock,
// used through the public vault.New entry point so we drive the
// adapter end-to-end against a Vault-shaped HTTP server. This file
// is intentionally not in the vault package (so it tests the
// adapter's external API, not the keystore's internals).
type fakeVault struct {
	secKeys map[string]*secp256k1.PrivateKey
	edKeys  map[string]ed25519.PrivateKey
}

func newFakeVault() *httptest.Server {
	fv := &fakeVault{
		secKeys: map[string]*secp256k1.PrivateKey{},
		edKeys:  map[string]ed25519.PrivateKey{},
	}
	return httptest.NewServer(http.HandlerFunc(fv.serve))
}

func (fv *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != "tok" {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rotate"):
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleRead(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/sign/"):
		fv.handleSign(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (fv *fakeVault) handleCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	var body struct{ Type string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Type == "ecdsa-p256k1" {
		priv, _ := secp256k1.GeneratePrivateKey()
		fv.secKeys[name] = priv
	} else if body.Type == "ed25519" {
		_, priv, _ := ed25519.GenerateKey(stdliberand.Reader)
		fv.edKeys[name] = priv
	}
	w.WriteHeader(http.StatusNoContent)
}

func (fv *fakeVault) handleRead(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	priv, ok := fv.secKeys[name]
	if !ok {
		http.Error(w, "no key", 404)
		return
	}
	spki := struct {
		Algo struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PubKey asn1.BitString
	}{}
	spki.Algo.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	spki.Algo.Parameters = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	spki.PubKey = asn1.BitString{Bytes: priv.PubKey().SerializeUncompressed(), BitLength: 8 * 65}
	der, _ := asn1.Marshal(spki)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"latest_version": 1,
			"keys":           map[string]any{"1": map[string]any{"public_key": pemStr}},
		},
	})
}

func (fv *fakeVault) handleSign(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
	var body struct{ Input string }
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	digest, _ := base64.StdEncoding.DecodeString(body.Input)
	priv, ok := fv.secKeys[name]
	if !ok {
		http.Error(w, "no key", 404)
		return
	}
	stdPriv := &stdlibecdsa.PrivateKey{
		PublicKey: stdlibecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     new(big.Int).SetBytes(priv.PubKey().SerializeUncompressed()[1:33]),
			Y:     new(big.Int).SetBytes(priv.PubKey().SerializeUncompressed()[33:65]),
		},
		D: new(big.Int).SetBytes(priv.Serialize()),
	}
	rr, ss, _ := stdlibecdsa.Sign(stdliberand.Reader, stdPriv, digest)
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{rr, ss})
	sig := "vault:v1:" + base64.StdEncoding.EncodeToString(der)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{"signature": sig},
	})
}

func TestAdapter_OverVault_RecoversPubkey(t *testing.T) {
	srv := newFakeVault()
	defer srv.Close()
	ks, err := vaultks.New(vaultks.Config{
		Address: srv.URL, Token: "tok", HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	const did = "did:web:state:tn:davidson:judge"
	info, err := ks.Generate(did, "signing")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	a, err := signer.New(ks, did)
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig, err := a.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	recovered, err := sdksigs.RecoverSecp256k1(digest, sig)
	if err != nil {
		t.Fatalf("RecoverSecp256k1: %v", err)
	}
	if !bytes.Equal(recovered, info.PublicKey) {
		t.Errorf("recovered pubkey via vault-backed adapter != generated pubkey")
	}
}
