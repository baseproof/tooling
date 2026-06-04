/*
FILE PATH: libs/keystore/vault/vault_fakeserver_test.go

DESCRIPTION:

	Mock Vault Transit server for unit tests. Implements the subset
	of /v1/transit endpoints the keystore exercises (create / read /
	sign / rotate / config / delete) with REAL secp256k1 + Ed25519
	keys so the recovery-byte selection in packCompact round-trips
	through actual ASN.1 marshal/unmarshal.

	Versioning is real: a key starts at v1, rotate appends v2 / v3 /
	..., the read endpoint reports latest_version + every version's
	pubkey, sign honors the optional "key_version" body field, and
	config sets min_encryption_version so subsequent signs targeting
	retired versions fail with a 400. This matches Vault Transit's
	HTTP contract closely enough that the staged-rotation tests
	exercise the real wire shape we depend on.
*/
package vault

import (
	stdlibecdsa "crypto/ecdsa"
	"crypto/ed25519"
	stdliberand "crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// fakeKey holds one secp256k1 (or ed25519) versioned key. versions
// is 1-indexed: versions[0] is v1, versions[1] is v2, etc. minEnc
// is the floor for sign requests — signs targeting a version <
// minEnc return HTTP 400 (Vault's "minimum encryption version
// violated" error).
type fakeSecpKey struct {
	versions []*secp256k1.PrivateKey
	minEnc   int
}

type fakeEdKey struct {
	versions []ed25519.PrivateKey
	minEnc   int
}

// fakeVault holds one secp256k1 + one ed25519 key per name and
// answers create / read / sign / rotate / config / delete the way
// Vault Transit does — including key versioning + min_encryption_version
// enforcement.
type fakeVault struct {
	t *testing.T

	mu      sync.Mutex
	secKeys map[string]*fakeSecpKey
	edKeys  map[string]*fakeEdKey
}

func newFakeVault(t *testing.T) *httptest.Server {
	fv := &fakeVault{
		t:       t,
		secKeys: map[string]*fakeSecpKey{},
		edKeys:  map[string]*fakeEdKey{},
	}
	return httptest.NewServer(http.HandlerFunc(fv.serve))
}

func (fv *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("X-Vault-Token"); got != "test-token" {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/") && strings.HasSuffix(r.URL.Path, "/rotate"):
		fv.handleRotate(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/") && strings.HasSuffix(r.URL.Path, "/config"):
		fv.handleConfig(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleCreate(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleRead(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/transit/keys/"):
		fv.handleDelete(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/transit/sign/"):
		fv.handleSign(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (fv *fakeVault) handleCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	var body struct {
		Type string `json:"type"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	fv.mu.Lock()
	defer fv.mu.Unlock()
	switch body.Type {
	case "ecdsa-p256k1":
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fv.secKeys[name] = &fakeSecpKey{versions: []*secp256k1.PrivateKey{priv}, minEnc: 1}
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(stdliberand.Reader)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fv.edKeys[name] = &fakeEdKey{versions: []ed25519.PrivateKey{priv}, minEnc: 1}
	default:
		http.Error(w, "unknown type", 400)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRead returns latest_version + a "keys" map indexed by
// version-as-string-decimal — matching the Vault Transit shape
// fetchPublicKey / fetchLatestVersionAndKey decode.
func (fv *fakeVault) handleRead(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	fv.mu.Lock()
	defer fv.mu.Unlock()
	if sk, ok := fv.secKeys[name]; ok {
		keys := map[string]any{}
		for i, priv := range sk.versions {
			der, err := marshalSecpSPKI(priv)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			keys[fmt.Sprintf("%d", i+1)] = map[string]any{"public_key": pemStr}
		}
		resp := map[string]any{
			"data": map[string]any{
				"latest_version":         len(sk.versions),
				"min_encryption_version": sk.minEnc,
				"keys":                   keys,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	if ek, ok := fv.edKeys[name]; ok {
		keys := map[string]any{}
		for i, priv := range ek.versions {
			der, err := x509.MarshalPKIXPublicKey(priv.Public().(ed25519.PublicKey))
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			keys[fmt.Sprintf("%d", i+1)] = map[string]any{"public_key": pemStr}
		}
		resp := map[string]any{
			"data": map[string]any{
				"latest_version":         len(ek.versions),
				"min_encryption_version": ek.minEnc,
				"keys":                   keys,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	http.Error(w, "no key", 404)
}

// marshalSecpSPKI hand-rolls the SubjectPublicKeyInfo for secp256k1
// (crypto/x509 doesn't know the curve).
func marshalSecpSPKI(priv *secp256k1.PrivateKey) ([]byte, error) {
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
	return asn1.Marshal(spki)
}

// handleSign honors the optional "key_version" body field. version
// == 0 (or omitted) means "use latest". A version < min_encryption_version
// gets a 400 — mirroring Vault's enforcement after CommitRotation.
func (fv *fakeVault) handleSign(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
	var body struct {
		Input      string `json:"input"`
		KeyVersion int    `json:"key_version"`
	}
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	digest, _ := base64.StdEncoding.DecodeString(body.Input)
	fv.mu.Lock()
	defer fv.mu.Unlock()
	if sk, ok := fv.secKeys[name]; ok {
		v := body.KeyVersion
		if v == 0 {
			v = len(sk.versions)
		}
		if v < 1 || v > len(sk.versions) {
			http.Error(w, "bad version", 400)
			return
		}
		if v < sk.minEnc {
			http.Error(w, "minimum encryption version violated", 400)
			return
		}
		priv := sk.versions[v-1]
		stdPriv := &stdlibecdsa.PrivateKey{
			PublicKey: stdlibecdsa.PublicKey{
				Curve: secp256k1.S256(),
				X:     new(big.Int).SetBytes(priv.PubKey().SerializeUncompressed()[1:33]),
				Y:     new(big.Int).SetBytes(priv.PubKey().SerializeUncompressed()[33:65]),
			},
			D: new(big.Int).SetBytes(priv.Serialize()),
		}
		rr, ss, err := stdlibecdsa.Sign(stdliberand.Reader, stdPriv, digest)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		der, _ := asn1.Marshal(struct{ R, S *big.Int }{rr, ss})
		sig := fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(der))
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": sig}})
		return
	}
	if ek, ok := fv.edKeys[name]; ok {
		v := body.KeyVersion
		if v == 0 {
			v = len(ek.versions)
		}
		if v < 1 || v > len(ek.versions) {
			http.Error(w, "bad version", 400)
			return
		}
		if v < ek.minEnc {
			http.Error(w, "minimum encryption version violated", 400)
			return
		}
		priv := ek.versions[v-1]
		out := ed25519.Sign(priv, digest)
		sig := fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(out))
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": sig}})
		return
	}
	http.Error(w, "no key", 404)
}

// handleRotate appends a new version. Matches Vault Transit's
// behavior: the new version becomes the latest pointer; previous
// versions remain available for explicit-version reads + signs
// (subject to min_encryption_version).
func (fv *fakeVault) handleRotate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/"), "/rotate")
	fv.mu.Lock()
	defer fv.mu.Unlock()
	if sk, ok := fv.secKeys[name]; ok {
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		sk.versions = append(sk.versions, priv)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ek, ok := fv.edKeys[name]; ok {
		_, priv, err := ed25519.GenerateKey(stdliberand.Reader)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ek.versions = append(ek.versions, priv)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "no key", 404)
}

// handleConfig updates min_encryption_version. Vault treats missing
// fields as no-op; we only honor min_encryption_version here.
func (fv *fakeVault) handleConfig(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/"), "/config")
	var body struct {
		MinEncryptionVersion *int `json:"min_encryption_version"`
	}
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	fv.mu.Lock()
	defer fv.mu.Unlock()
	if sk, ok := fv.secKeys[name]; ok {
		if body.MinEncryptionVersion != nil {
			v := *body.MinEncryptionVersion
			if v < 1 || v > len(sk.versions) {
				http.Error(w, "bad min_encryption_version", 400)
				return
			}
			sk.minEnc = v
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ek, ok := fv.edKeys[name]; ok {
		if body.MinEncryptionVersion != nil {
			v := *body.MinEncryptionVersion
			if v < 1 || v > len(ek.versions) {
				http.Error(w, "bad min_encryption_version", 400)
				return
			}
			ek.minEnc = v
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Error(w, "no key", 404)
}

func (fv *fakeVault) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/transit/keys/")
	fv.mu.Lock()
	delete(fv.secKeys, name)
	delete(fv.edKeys, name)
	fv.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// newKS spins up a fakeVault and returns a wired KeyStore + the
// httptest.Server so callers can defer Close.
func newKS(t *testing.T) (*KeyStore, *httptest.Server) {
	srv := newFakeVault(t)
	ks, err := New(Config{Address: srv.URL, Token: "test-token", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ks, srv
}
