// Command declare-anchor-target — the BP-ENTRY-ANCHOR-TARGET-V1 producer
// (PR-4d; the kind previously had no producer anywhere, tooling#94).
//
// One shot: bind a CONSTITUTIONAL anchor target (a parent NetworkID from
// GenesisAnchoringPolicy.Targets — the immutable WHICH) to its current
// liveness data (LogDID + admission/read URLs — the amendable WHERE) as an
// on-log declaration, signed and submitted to THIS network's ledger. The
// SDK owns payload validation (network.EncodeAnchorTargetDeclarationPayload)
// and the walk semantics; the wire/boot projection
// (LEDGER_ANCHOR_TARGET_SCHEMA) turns admitted declarations into the
// resolver's FederationGraph and the publisher's derived parent endpoints —
// retiring the env canary.
//
// The entry's SchemaRef MUST point at the network's anchor-target schema
// position (the same "did:seq" the ledger's LEDGER_ANCHOR_TARGET_SCHEMA
// names) — that is how the walker finds declarations.
//
// Usage:
//
//	declare-anchor-target \
//	  -url https://ledger.example -log-did did:baseproof:network:self \
//	  -schema "did:baseproof:network:self:7" \
//	  -target-network-id <64-hex parent NetworkID> \
//	  -target-log-did did:baseproof:network:parent \
//	  -admission-url https://parent.example/v1/entries \
//	  -read-url https://parent.example \
//	  [-token tok] [-key signer.hex]
//
// A re-declaration with new endpoints SUPERSEDES the previous one at its
// log position (the SDK walker's rule); endpoint churn is a witnessed,
// sequenced event — an Info-grade fact, never an identity change.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/ecdsa"

	"github.com/baseproof/baseproof/core/envelope"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/baseproof/tooling/services/ledger/internal/retryhttp"
)

func main() {
	var (
		ledgerURL    = flag.String("url", "", "this network's ledger base URL (REQUIRED)")
		logDID       = flag.String("log-did", "", "this network's log DID — the entry Destination (REQUIRED)")
		schema       = flag.String("schema", "", `anchor-target schema position "did:seq" — must equal the ledger's LEDGER_ANCHOR_TARGET_SCHEMA (REQUIRED)`)
		targetID     = flag.String("target-network-id", "", "the constitutional target's 64-hex NetworkID (REQUIRED)")
		targetLogDID = flag.String("target-log-did", "", "the target parent's current log DID (REQUIRED)")
		admissionURL = flag.String("admission-url", "", "the parent's https /v1/entries admission URL (REQUIRED)")
		readURL      = flag.String("read-url", "", "the parent's https read base URL (REQUIRED)")
		retiredAt    = flag.Uint64("retired-at", 0, "optional sequence at/after which this WHERE no longer applies (>0)")
		token        = flag.String("token", "", "admission bearer token (gated networks)")
		keyFile      = flag.String("key", "", "signer secp256k1 key file (raw 32-byte hex scalar); empty = fresh did:key per run")
	)
	flag.Parse()
	for name, v := range map[string]string{
		"-url": *ledgerURL, "-log-did": *logDID, "-schema": *schema,
		"-target-network-id": *targetID, "-target-log-did": *targetLogDID,
		"-admission-url": *admissionURL, "-read-url": *readURL,
	} {
		if v == "" {
			log.Fatalf("declare-anchor-target: %s is required", name)
		}
	}

	// The declaration, validated by the SDK codec (64-lower-hex id, https
	// endpoints, retirement shape) — this tool restates none of those rules.
	rawID, err := hex.DecodeString(*targetID)
	if err != nil || len(rawID) != 32 {
		log.Fatalf("declare-anchor-target: -target-network-id must be 64 hex chars (32 bytes): %v", err)
	}
	var tid [32]byte
	copy(tid[:], rawID)
	decl := network.AnchorTargetDeclaration{
		TargetNetworkID: tid,
		LogDID:          *targetLogDID,
		Endpoints: map[string]string{
			network.AnchorTargetAdmissionService: *admissionURL,
			network.AnchorTargetReadService:      *readURL,
		},
	}
	if *retiredAt > 0 {
		decl.RetiredAt = retiredAt
	}
	payload, err := network.EncodeAnchorTargetDeclarationPayload(decl)
	if err != nil {
		log.Fatalf("declare-anchor-target: SDK refused the declaration: %v", err)
	}

	schemaPos, err := parseSchemaPos(*schema)
	if err != nil {
		log.Fatalf("declare-anchor-target: -schema: %v", err)
	}

	// Signing identity: a pinned operator key, or a fresh did:key per run
	// (open/dev networks).
	priv, signerDID, err := loadOrMintSigner(*keyFile)
	if err != nil {
		log.Fatalf("declare-anchor-target: signer: %v", err)
	}
	header := envelope.ControlHeader{
		SignerDID:   signerDID,
		Destination: *logDID,
		SchemaRef:   &schemaPos,
		EventTime:   time.Now().UTC().UnixMicro(),
	}
	entry, err := envelope.NewUnsignedEntry(header, payload)
	if err != nil {
		log.Fatalf("declare-anchor-target: build entry: %v", err)
	}
	signingHash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := sdksigs.SignEntry(signingHash, priv)
	if err != nil {
		log.Fatalf("declare-anchor-target: sign: %v", err)
	}
	entry.Signatures = []envelope.Signature{{SignerDID: signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	wire, err := envelope.Serialize(entry)
	if err != nil {
		log.Fatalf("declare-anchor-target: serialize: %v", err)
	}

	hc := retryhttp.Client(30*time.Second, nil)
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(*ledgerURL, "/")+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		log.Fatalf("declare-anchor-target: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatalf("declare-anchor-target: POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusAccepted {
		log.Fatalf("declare-anchor-target: ledger returned %d: %s", resp.StatusCode, body)
	}
	fmt.Printf("declare-anchor-target: ACCEPTED\n  target    = %s\n  parent    = %s\n  admission = %s\n  read      = %s\n  signer    = %s\n",
		*targetID, *targetLogDID, *admissionURL, *readURL, signerDID)
	fmt.Println("  NEXT: the ledger's walker projects this at boot (LEDGER_ANCHOR_TARGET_SCHEMA); the env parent canary can then be retired.")
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

// loadOrMintSigner loads a raw-hex secp256k1 scalar (the
// LEDGER_SIGNER_KEY_FILE dialect — same on-disk form genesis-ceremony
// writes) or mints a fresh did:key per run (open/dev networks).
func loadOrMintSigner(path string) (*ecdsa.PrivateKey, string, error) {
	if path == "" {
		kp, err := sdkdid.GenerateDIDKeySecp256k1()
		if err != nil {
			return nil, "", err
		}
		return kp.PrivateKey, kp.DID, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		return nil, "", fmt.Errorf("%q: not a 32-byte hex scalar", path)
	}
	priv := secp.PrivKeyFromBytes(raw)
	didKey := sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, priv.PubKey().SerializeCompressed())
	return priv.ToECDSA(), didKey, nil
}
