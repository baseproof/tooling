// Command declare-witness-endpoint — the BP-ENTRY-WITNESS-ENDPOINT-V1 producer
// (PRE-12 witness enrollment; the kind previously had no submitting producer).
//
// A witness SELF-DECLARES its dial endpoint on-log: it builds a
// WitnessEndpointDeclaration (its PubKeyID + endpoint URL), signs the entry's
// SigningPayload with its OWN secp256k1 key — the attestation — and submits it
// to the network's ledger. The ledger's admission gate (PRE-12 step 4h) admits
// it iff the attestation VERIFIES, the witness PubKeyID is AUTHORIZED (genesis
// witness set ∪ rotations), and the signer IS the declared witness (BIND). So a
// hijack — declaring someone else's endpoints — is unconstructible: an attacker
// holds no witness key. The ledger's by-kind resolver then serves these
// endpoints as the SOLE witness dial-list (LEDGER_WITNESS_ENDPOINTS is deleted).
//
// This is the "sign offline, a collector submits" genesis-endorse shape. At
// genesis, run it once per genesis witness to seed the on-log endpoint set
// (scripts/declare-genesis-witness-endpoints.sh). After a key rotation or an
// endpoint move, the witness re-runs it; the new declaration supersedes the old
// by log position (make-before-break).
//
// SCOPE: did:key ECDSA witnesses (the genesis topology). BLS witnesses attest
// via a PurposeWitnessEndpoint cosign signature carried in the payload, verified
// by the single existing cosign BLS verifier — the item-6 follow-up, never a
// second entry verifier.
//
// Usage:
//
//	declare-witness-endpoint \
//	  -url https://ledger.example -log-did did:baseproof:network:self \
//	  -key witness-signer.hex -public-url https://witness-1.example \
//	  [-service-type BaseproofWitness] [-schema "did:...:seq"] [-token tok]
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/baseproof/baseproof/core/envelope"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/baseproof/tooling/libs/cli"
	"github.com/baseproof/tooling/services/ledger/internal/retryhttp"
)

// defaultWitnessServiceType is the W3C service-type key the witness cosigner's
// resolver reads (network.ResolveWitnessKeyAt / the dial-list projection).
const defaultWitnessServiceType = "BaseproofWitness"

func main() {
	var (
		ledgerURL   = flag.String("url", "", "the network's ledger base URL (REQUIRED)")
		logDID      = flag.String("log-did", "", "the network's log DID — the entry Destination (REQUIRED)")
		keyFile     = flag.String("key", "", "the WITNESS's secp256k1 key file (raw 32-byte hex scalar) — the self-declaration identity (REQUIRED)")
		publicURL   = flag.String("public-url", "", "the witness's https dial endpoint (REQUIRED)")
		serviceType = flag.String("service-type", defaultWitnessServiceType, "the W3C service-type key for the endpoint")
		schema      = flag.String("schema", "", `optional witness-endpoint schema position "did:...:seq" (set only if the network's admission requires one; resolution itself is by-kind)`)
		retiredAt   = flag.Uint64("retired-at", 0, "optional sequence at/after which this endpoint no longer applies (>0)")
		token       = flag.String("token", "", "admission bearer token (gated networks)")
	)
	flag.Parse()
	for name, v := range map[string]string{
		"-url": *ledgerURL, "-log-did": *logDID, "-key": *keyFile, "-public-url": *publicURL,
	} {
		if v == "" {
			log.Fatalf("declare-witness-endpoint: %s is required", name)
		}
	}

	priv, witnessDID, pubKeyID, err := loadWitnessSigner(*keyFile)
	if err != nil {
		log.Fatalf("declare-witness-endpoint: key: %v", err)
	}

	var schemaPos *types.LogPosition
	if *schema != "" {
		p, perr := parseSchemaPos(*schema)
		if perr != nil {
			log.Fatalf("declare-witness-endpoint: -schema: %v", perr)
		}
		schemaPos = &p
	}
	var ra *uint64
	if *retiredAt > 0 {
		ra = retiredAt
	}

	_, wire, err := buildSignedWitnessDeclaration(priv, witnessDID, pubKeyID, *logDID, *serviceType, *publicURL, ra, schemaPos)
	if err != nil {
		log.Fatalf("declare-witness-endpoint: build: %v", err)
	}

	hc := retryhttp.Client(30*time.Second, nil)
	hash, err := cli.SubmitWire(context.Background(), hc, *ledgerURL, *token, wire)
	if err != nil {
		log.Fatalf("declare-witness-endpoint: %v", err)
	}
	fmt.Printf("declare-witness-endpoint: ACCEPTED (canonical_hash=%s)\n  witness    = %s\n  pub_key_id = %x\n  endpoint   = %s (%s)\n",
		hash, witnessDID, pubKeyID, *publicURL, *serviceType)
	fmt.Println("  NEXT: the ledger's by-kind resolver serves this endpoint to the witness cosigner (LEDGER_WITNESS_ENDPOINTS is deleted).")
}

// buildSignedWitnessDeclaration assembles a WitnessEndpointDeclarationV1 entry
// SELF-SIGNED by the witness (the attestation over SigningPayload). The witness
// is Signatures[0] == Header.SignerDID, and the declaration's PubKeyID is the
// witness's own canonical PubKeyID — so the keystone authorizer's BIND
// (signer PubKeyID == declaration PubKeyID) holds by construction. Factored out
// so a test proves the producer→verifier loop without a live ledger.
func buildSignedWitnessDeclaration(
	priv *ecdsa.PrivateKey,
	witnessDID string,
	pubKeyID [32]byte,
	logDID, serviceType, url string,
	retiredAt *uint64,
	schemaPos *types.LogPosition,
) (*envelope.Entry, []byte, error) {
	decl := network.WitnessEndpointDeclaration{
		PubKeyID:  pubKeyID,
		Endpoints: map[string]string{serviceType: url},
		RetiredAt: retiredAt,
	}
	payload, err := network.EncodeWitnessEndpointDeclarationPayload(decl)
	if err != nil {
		return nil, nil, fmt.Errorf("SDK refused the declaration: %w", err)
	}
	header := envelope.ControlHeader{
		SignerDID:   witnessDID,
		Destination: logDID,
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	if schemaPos != nil {
		header.SchemaRef = schemaPos
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		return nil, nil, fmt.Errorf("build entry: %w", err)
	}
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := sdksigs.SignEntry(signingHash, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("sign: %w", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: witnessDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	wire, err := envelope.Serialize(entry)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize: %w", err)
	}
	return entry, wire, nil
}

// loadWitnessSigner reads a raw-hex secp256k1 scalar (the LEDGER_SIGNER_KEY_FILE
// dialect genesis-ceremony writes) and derives the witness's did:key + canonical
// PubKeyID (witness.KeysFromDIDs — the same derivation the authorizer uses).
func loadWitnessSigner(path string) (*ecdsa.PrivateKey, string, [32]byte, error) {
	var zero [32]byte
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", zero, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		return nil, "", zero, fmt.Errorf("%q: not a 32-byte hex scalar", path)
	}
	priv := secp.PrivKeyFromBytes(raw)
	didKey := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, priv.PubKey().SerializeCompressed())
	keys, err := witness.KeysFromDIDs([]string{didKey})
	if err != nil || len(keys) != 1 {
		return nil, "", zero, fmt.Errorf("derive PubKeyID: %v", err)
	}
	return priv.ToECDSA(), didKey, keys[0].ID, nil
}

// parseSchemaPos parses "did:...:seq" — the LAST colon-separated token is the
// sequence (DIDs contain colons).
func parseSchemaPos(s string) (types.LogPosition, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return types.LogPosition{}, fmt.Errorf("want \"did:...:seq\", got %q", s)
	}
	var seq uint64
	if _, err := fmt.Sscanf(s[i+1:], "%d", &seq); err != nil {
		return types.LogPosition{}, fmt.Errorf("sequence %q: %w", s[i+1:], err)
	}
	return types.LogPosition{LogDID: s[:i], Sequence: seq}, nil
}
