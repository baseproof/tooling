package blskey_test

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/blskey"
)

func TestGenerate_RoundTripPEM_PreservesIdentity(t *testing.T) {
	priv, pub, err := blskey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := blskey.PubKeyID(pub)

	priv2, err := blskey.DecodePEM(blskey.EncodePEM(priv))
	if err != nil {
		t.Fatalf("Decode(Encode): %v", err)
	}
	// The loaded scalar must derive the SAME G2 key (same on-log identity).
	if got := blskey.PubKeyID(blskey.PubKey(priv2)); got != want {
		t.Fatalf("PEM round-trip changed identity: got %x want %x", got, want)
	}
}

// TestPubKeyID_MatchesSigner is the load-bearing binding: the PubKeyID this
// package derives equals the one crypto/cosign.NewBLSWitnessSigner signs
// under, so a key loaded here is resolvable to the cosignatures it produces.
func TestPubKeyID_MatchesSigner(t *testing.T) {
	priv, pub, err := blskey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signerID := cosign.NewBLSWitnessSigner(priv).PubKeyID()
	if got := blskey.PubKeyID(pub); got != signerID {
		t.Fatalf("PubKeyID drift vs signer: pkg=%x signer=%x", got, signerID)
	}
	if got := blskey.PubKeyID(blskey.PubKey(priv)); got != signerID {
		t.Fatalf("PubKey(priv) derivation drift: %x vs %x", got, signerID)
	}
}

func TestDecodePEM_FailClosed(t *testing.T) {
	good := blskey.EncodePEM(mustPriv(t))
	cases := map[string][]byte{
		"no PEM block":  []byte("not a pem file"),
		"wrong type":    pem.EncodeToMemory(&pem.Block{Type: "BASEPROOF SECP256K1 PRIVATE KEY", Bytes: make([]byte, 32)}),
		"short scalar":  pem.EncodeToMemory(&pem.Block{Type: blskey.PEMType, Bytes: make([]byte, 31)}),
		"non-canonical": pem.EncodeToMemory(&pem.Block{Type: blskey.PEMType, Bytes: bytes.Repeat([]byte{0xFF}, 32)}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := blskey.DecodePEM(data); err == nil {
				t.Fatalf("%s: want error, got nil", name)
			}
		})
	}
	// Sanity: the good encoding decodes.
	if _, err := blskey.DecodePEM(good); err != nil {
		t.Fatalf("good PEM must decode: %v", err)
	}
}

func TestEndpointDeclaration_ValidAndPoPVerifies(t *testing.T) {
	priv, pub, err := blskey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	endpoints := map[string]string{"BaseproofWitness": "https://witness-1.example.org/v1/cosign"}

	d, err := blskey.EndpointDeclaration(priv, endpoints)
	if err != nil {
		t.Fatalf("EndpointDeclaration: %v", err)
	}
	if d.SchemeTag != signatures.SchemeBLS {
		t.Errorf("SchemeTag = %d, want SchemeBLS", d.SchemeTag)
	}
	if d.PubKeyID != blskey.PubKeyID(pub) {
		t.Errorf("declaration PubKeyID mismatch")
	}
	// The PoP it carries is the one cosign.NewWitnessKeySet will demand.
	if err := signatures.VerifyBLSPoPBytes(d.PublicKey, d.ProofOfPossession); err != nil {
		t.Fatalf("declared PoP must verify: %v", err)
	}
	// Encode/decode round-trips through the SDK wire form (Validate-clean).
	raw, err := network.EncodeWitnessEndpointDeclarationPayload(d)
	if err != nil {
		t.Fatalf("Encode declaration: %v", err)
	}
	got, err := network.DecodeWitnessEndpointDeclarationPayload(raw)
	if err != nil {
		t.Fatalf("Decode declaration: %v", err)
	}
	if got.PubKeyID != d.PubKeyID || got.SchemeTag != d.SchemeTag {
		t.Fatalf("declaration round-trip drift")
	}
}

func TestLoadPEM_FileRoundTrip(t *testing.T) {
	priv := mustPriv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "witness.bls.pem")
	if err := os.WriteFile(path, blskey.EncodePEM(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := blskey.LoadPEM(path)
	if err != nil {
		t.Fatalf("LoadPEM: %v", err)
	}
	if blskey.PubKeyID(blskey.PubKey(got)) != blskey.PubKeyID(blskey.PubKey(priv)) {
		t.Fatal("LoadPEM changed identity")
	}
	if _, err := blskey.LoadPEM(filepath.Join(dir, "absent.pem")); err == nil {
		t.Fatal("LoadPEM(missing file) must error")
	}
}

func TestEndpointDeclaration_EmptyEndpoints_Rejected(t *testing.T) {
	if _, err := blskey.EndpointDeclaration(mustPriv(t), nil); err == nil {
		t.Fatal("endpoint-less declaration must be rejected")
	}
}

func mustPriv(t *testing.T) *fr.Element {
	t.Helper()
	priv, _, err := blskey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return priv
}
