/*
FILE PATH: cmd/admission-authority/main.go

admission-authority — the G-authorized publisher for the on-log admission keyset
(the GATING root of trust). Run by the holder of a CURRENT admission authority
(genesis G at bootstrap), it composes the unbuilt-until-now issuance path:

	schema:    builder.BuildSchemaEntry              (a real admission_authority schema)
	snapshot:  builder.BuildAdmissionAuthoritySnapshot (Commentary + SchemaRef + the FULL set)
	payment:   Mode A (-token) or Mode B PoW          (the "can you pay?" axis)
	gating:    authz.SignWriteAuthorization(G, …)     (the "is this approved?" axis)

DECLARATIVE SET. -authorities is the FULL desired admission set, so enroll {J},
rotate {G,J}, and revoke {} are one command — the ledger resolves the LATEST
snapshot.

ZERO-TRUST ANCHOR. G signs each authorization over a WITNESS-COSIGNED, verified
horizon (sdklog.FetchVerifiedHorizon over the bootstrap's genesis_witness_set,
K-of-N) — never the ledger's unverified /v1/tree/head word. Fail-closed: an
unverifiable horizon aborts the publish.

USAGE

	admission-authority -url http://ledger:8080 \
	    -bootstrap /run/clarity/network-bootstrap.json -quorum 2 \
	    -g-key /run/clarity/admission-authority.key \
	    -authorities 0x<J-address>            # enroll J

After it prints the schema position, set it on the ledger so the keyset resolves
on-log: LEDGER_ADMISSION_AUTHORITY_SCHEMA=<log-did>@<seq>.
*/
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/baseproof/authz"
	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	sdkadmission "github.com/baseproof/baseproof/crypto/admission"
	"github.com/baseproof/baseproof/crypto/cosign"
	sdksigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	sdklog "github.com/baseproof/baseproof/log"
	sdknetwork "github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"
	"github.com/baseproof/baseproof/witness"

	"github.com/baseproof/tooling/services/ledger/internal/clienttls"
	"github.com/baseproof/tooling/services/ledger/internal/retryhttp"
)

// hc is the outbound HTTP client used for every call to the ledger.
// Initialized in main() after flag.Parse — ALWAYS retryhttp-backed for
// startup-race resilience, with TLS material composed in when the mTLS
// flags are set. There is no "retry OR mTLS" split: one single client,
// one retry posture, regardless of TLS configuration.
var hc *http.Client

// mtlsFlags exposes -client-cert / -client-key / -ca-cert.
var mtlsFlags clienttls.Flags

func init() { mtlsFlags.Bind(flag.CommandLine) }

func main() {
	var (
		ledgerURL  = flag.String("url", "http://localhost:8080", "ledger base URL")
		bootstrap  = flag.String("bootstrap", "", "path to network-bootstrap.json (trust root + log DID) — REQUIRED")
		quorum     = flag.Int("quorum", 1, "witness quorum K for the verified-anchor cosignature check")
		gKeyFile   = flag.String("g-key", "", "authorizing admission-authority key (raw 32-byte hex scalar); MUST be a CURRENT authority — REQUIRED")
		authsCSV   = flag.String("authorities", "", "comma-separated 0x EOA addresses — the FULL desired admission set (declarative). Empty = freeze {}")
		schemaArg  = flag.String("schema-pos", "", "existing admission_authority schema as <log-did>@<seq>; empty → publish a fresh schema entry first")
		token      = flag.String("token", "", "Mode A payment Bearer token; empty → Mode B PoW")
		difficulty = flag.Int("difficulty", 0, "Mode B difficulty; 0 → query /v1/admission/difficulty")
		epochSec   = flag.Int("epoch-window", 3600, "Mode B epoch window seconds")
		seqTimeout = flag.Duration("seq-timeout", 120*time.Second, "how long to wait for an entry to sequence")
	)
	flag.Parse()
	tlsCfg, err := mtlsFlags.TLSConfig()
	if err != nil {
		log.Fatalf("admission-authority: mTLS config: %v", err)
	}
	hc = retryhttp.Client(30*time.Second, tlsCfg)
	if *bootstrap == "" {
		log.Fatal("admission-authority: -bootstrap required")
	}
	if *gKeyFile == "" {
		log.Fatal("admission-authority: -g-key required (the authorizing authority)")
	}

	doc := mustBootstrap(*bootstrap)
	logDID := doc.ExchangeDID
	set := mustWitnessKeySet(doc, *quorum)

	g := mustLoadKey(*gKeyFile)
	gAddr, err := sdksigs.AddressFromPubkey(sdksigs.PubKeyBytes(&g.PublicKey))
	if err != nil {
		log.Fatalf("admission-authority: derive G address: %v", err)
	}

	kp, err := sdkdid.GenerateDIDKeySecp256k1()
	if err != nil {
		log.Fatalf("admission-authority: generate entry signer: %v", err)
	}

	authorities := mustAddresses(*authsCSV)

	genesisRoot, gerr := decodeRoot(doc.GenesisTreeHead.RootHash)
	if gerr != nil {
		log.Fatalf("admission-authority: bootstrap genesis_tree_head.root_hash: %v", gerr)
	}
	cp, cperr := sdklog.NewHTTPCheckpointClient(sdklog.HTTPCheckpointClientConfig{BaseURL: *ledgerURL, Client: hc})
	if cperr != nil {
		log.Fatalf("admission-authority: checkpoint client: %v", cperr)
	}
	anchor := func() [32]byte {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		head, herr := cp.FetchVerifiedHorizon(ctx, set)
		if herr == nil {
			return head.RootHash
		}
		// Bootstrap exception: a fresh gating=require log has no genesis seed, so
		// no cosigned head exists yet — but the FIRST governance write still needs
		// an anchor. Anchor it to the GENESIS tree head from the bootstrap doc:
		// the agreed trust root (signed at network genesis), NOT a ledger-reported
		// head — so zero-trust is preserved (we never trust the ledger's word).
		// Once this snapshot is sequenced + cosigned, later runs get a real
		// verified horizon.
		if errors.Is(herr, sdklog.ErrHorizonNotPublished) {
			fmt.Printf("admission-authority: no cosigned head yet — anchoring the bootstrap write to the genesis tree head (size=%d)\n",
				doc.GenesisTreeHead.TreeSize)
			return genesisRoot
		}
		log.Fatalf("admission-authority: anchor NOT TRUSTED — %v (refusing to authorize over an unverified head)", herr)
		return [32]byte{}
	}

	diff := uint32(*difficulty)
	if *token == "" && diff == 0 {
		diff = mustDifficulty(*ledgerURL)
	}

	p := &publisher{
		url: *ledgerURL, logDID: logDID, token: *token,
		signerDID: kp.DID, signerPriv: kp.PrivateKey,
		g: g, anchor: anchor, diff: diff, epochSec: uint64(*epochSec), seqTimeout: *seqTimeout,
	}

	fmt.Printf("admission-authority: log=%s authorizer(G)=0x%s signer=%s payment=%s\n",
		logDID, hex.EncodeToString(gAddr[:4]), kp.DID, modeLabel(*token))

	var schemaPos types.LogPosition
	if *schemaArg == "" {
		schemaPos = p.publishSchema()
		fmt.Printf("admission-authority: schema entry published at %s@%d\n", logDID, schemaPos.Sequence)
	} else {
		schemaPos = mustSchemaPos(*schemaArg, logDID)
		fmt.Printf("admission-authority: using existing schema %s@%d\n", schemaPos.LogDID, schemaPos.Sequence)
	}

	snapSeq := p.publishSnapshot(authorities, schemaPos)

	fmt.Printf("\nadmission-authority: DONE\n")
	fmt.Printf("  registered set (becomes Current()): %s\n", addrsLabel(authorities))
	fmt.Printf("  snapshot entry: %s@%d\n", logDID, snapSeq)
	fmt.Printf("\nSet on the ledger so the keyset resolves on-log:\n  LEDGER_ADMISSION_AUTHORITY_SCHEMA=%s@%d\n", schemaPos.LogDID, schemaPos.Sequence)
}

// publisher carries the wiring for sign → pay → G-authorize → submit.
type publisher struct {
	url, logDID, token string
	signerDID          string
	signerPriv         *ecdsa.PrivateKey
	g                  *ecdsa.PrivateKey
	anchor             func() [32]byte
	diff               uint32
	epochSec           uint64
	seqTimeout         time.Duration
}

func (p *publisher) publishSchema() types.LogPosition {
	entry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
		Destination: p.logDID,
		SignerDID:   p.signerDID,
		Parameters:  types.SchemaParameters{},
		EventTime:   time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		log.Fatalf("admission-authority: build schema entry: %v", err)
	}
	return types.LogPosition{LogDID: p.logDID, Sequence: p.signAuthorizeSubmit(entry)}
}

func (p *publisher) publishSnapshot(authorities [][20]byte, schemaPos types.LogPosition) uint64 {
	entry, err := builder.BuildAdmissionAuthoritySnapshot(builder.AdmissionAuthoritySnapshotParams{
		Destination: p.logDID,
		SignerDID:   p.signerDID,
		Authorities: authorities,
		SchemaRef:   &schemaPos,
		EventTime:   time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		log.Fatalf("admission-authority: build snapshot: %v", err)
	}
	return p.signAuthorizeSubmit(entry)
}

// signAuthorizeSubmit pays admission (Mode A/B), mints G's gate-5 authorization
// over a VERIFIED anchor, POSTs with both, and returns the assigned sequence.
func (p *publisher) signAuthorizeSubmit(entry *envelope.Entry) uint64 {
	canonical := p.signWithPayment(entry)
	entryIdentity := sha256.Sum256(canonical) // == envelope.EntryIdentity(signed) == ledger canonicalHash
	wa, err := authz.SignWriteAuthorization(p.g, p.logDID, entryIdentity, p.anchor())
	if err != nil {
		log.Fatalf("admission-authority: sign write authorization: %v", err)
	}
	enc, err := wa.Encode()
	if err != nil {
		log.Fatalf("admission-authority: encode write authorization: %v", err)
	}
	hash := p.post(canonical, base64.StdEncoding.EncodeToString(enc))
	seq, err := waitForSequence(p.url, hash, p.seqTimeout)
	if err != nil {
		log.Fatalf("admission-authority: sequence discovery: %v", err)
	}
	return seq
}

// signWithPayment returns the canonical signed bytes after attaching the payment
// proof: Mode A (nil proof, sign once) or Mode B (PoW grind). Mirrors backfill.
func (p *publisher) signWithPayment(entry *envelope.Entry) []byte {
	if p.token != "" {
		entry.Header.AdmissionProof = nil
		return p.signSerialize(entry)
	}
	const maxIter uint64 = 1 << 30
	for nonce := uint64(0); nonce < maxIter; nonce++ {
		entry.Header.AdmissionProof = &envelope.AdmissionProofBody{
			Mode:       types.WireByteModeB,
			Difficulty: uint8(p.diff),
			HashFunc:   sdkadmission.WireByteHashSHA256,
			Epoch:      sdkadmission.CurrentEpoch(p.epochSec),
			Nonce:      nonce,
		}
		canonical := p.signSerialize(entry)
		entryHash := sha256.Sum256(canonical)
		apiProof := sdkadmission.ProofFromWire(entry.Header.AdmissionProof, p.logDID)
		if err := sdkadmission.VerifyStamp(apiProof, entryHash, p.logDID, p.diff,
			sdkadmission.HashSHA256, nil, sdkadmission.CurrentEpoch(p.epochSec), 1); err == nil {
			return canonical
		}
	}
	log.Fatalf("admission-authority: PoW nonce exhausted (difficulty=%d too high?)", p.diff)
	return nil
}

func (p *publisher) signSerialize(entry *envelope.Entry) []byte {
	u, err := envelope.NewUnsignedEntry(entry.Header, entry.DomainPayload)
	if err != nil {
		log.Fatalf("admission-authority: new unsigned entry: %v", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(u))
	sig, err := sdksigs.SignEntry(digest, p.signerPriv)
	if err != nil {
		log.Fatalf("admission-authority: sign entry: %v", err)
	}
	u.Signatures = []envelope.Signature{{SignerDID: p.signerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: sig}}
	canonical, err := envelope.Serialize(u)
	if err != nil {
		log.Fatalf("admission-authority: serialize: %v", err)
	}
	return canonical
}

func (p *publisher) post(wire []byte, authHdr string) string {
	req, err := http.NewRequest(http.MethodPost, p.url+"/v1/entries", bytes.NewReader(wire))
	if err != nil {
		log.Fatalf("admission-authority: new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	req.Header.Set("X-Baseproof-Write-Authorization", authHdr)
	resp, err := hc.Do(req)
	if err != nil {
		log.Fatalf("admission-authority: POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusAccepted {
		log.Fatalf("admission-authority: submit HTTP %d: %s", resp.StatusCode, body)
	}
	var sct struct {
		CanonicalHash string `json:"canonical_hash"`
	}
	if err := json.Unmarshal(body, &sct); err != nil || sct.CanonicalHash == "" {
		log.Fatalf("admission-authority: parse SCT canonical_hash: %v (body=%s)", err, body)
	}
	return sct.CanonicalHash
}

// ── bootstrap / key / parsing helpers ───────────────────────────────────────

func mustBootstrap(path string) sdknetwork.BootstrapDocument {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("admission-authority: read bootstrap %q: %v", path, err)
	}
	var doc sdknetwork.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		log.Fatalf("admission-authority: parse bootstrap: %v", err)
	}
	if doc.ExchangeDID == "" {
		log.Fatal("admission-authority: bootstrap missing exchange_did")
	}
	return doc
}

// mustWitnessKeySet builds the K-of-N trust root from the bootstrap, exactly as
// the auditor does (genesis_witness_set DIDs → ECDSA keys → WitnessKeySet).
func mustWitnessKeySet(doc sdknetwork.BootstrapDocument, quorum int) *cosign.WitnessKeySet {
	if len(doc.GenesisWitnessSet) == 0 {
		log.Fatal("admission-authority: bootstrap missing genesis_witness_set")
	}
	if quorum < 1 || quorum > len(doc.GenesisWitnessSet) {
		log.Fatalf("admission-authority: -quorum %d invalid for N=%d witnesses", quorum, len(doc.GenesisWitnessSet))
	}
	ids, err := doc.IDs()
	if err != nil {
		log.Fatalf("admission-authority: derive network identity: %v", err)
	}
	keys, err := witness.KeysFromDIDs(doc.GenesisWitnessSet)
	if err != nil {
		log.Fatalf("admission-authority: resolve witness keys: %v", err)
	}
	set, err := cosign.NewECDSAWitnessKeySet(keys, ids.NetworkID, quorum)
	if err != nil {
		log.Fatalf("admission-authority: build witness key set: %v", err)
	}
	return set
}

func mustLoadKey(path string) *ecdsa.PrivateKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("admission-authority: read key %q: %v", path, err)
	}
	scalar, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(scalar) != 32 {
		log.Fatalf("admission-authority: key %q: want a 32-byte hex scalar", path)
	}
	priv, err := sdksigs.PrivKeyFromBytes(scalar)
	if err != nil {
		log.Fatalf("admission-authority: key %q: %v", path, err)
	}
	return priv
}

func mustAddresses(csv string) [][20]byte {
	out := make([][20]byte, 0)
	for _, s := range strings.Split(csv, ",") {
		s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
		if s == "" {
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 20 {
			log.Fatalf("admission-authority: bad authority address %q (want 20-byte hex)", s)
		}
		var a [20]byte
		copy(a[:], b)
		out = append(out, a)
	}
	return out
}

func mustSchemaPos(arg, defaultLogDID string) types.LogPosition {
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		log.Fatalf("admission-authority: -schema-pos %q must be <log-did>@<seq>", arg)
	}
	logDID, seqStr := arg[:at], arg[at+1:]
	if logDID == "" {
		logDID = defaultLogDID
	}
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		log.Fatalf("admission-authority: -schema-pos sequence: %v", err)
	}
	return types.LogPosition{LogDID: logDID, Sequence: seq}
}

// decodeRoot parses a 32-byte hex tree-head root (e.g. the bootstrap's
// genesis_tree_head.root_hash — 64 hex zeros for a fresh log).
func decodeRoot(h string) ([32]byte, error) {
	var r [32]byte
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != 32 {
		return r, fmt.Errorf("want 32-byte hex, got %q", h)
	}
	copy(r[:], b)
	return r, nil
}

func mustDifficulty(ledgerURL string) uint32 {
	resp, err := hc.Get(ledgerURL + "/v1/admission/difficulty")
	if err != nil {
		log.Fatalf("admission-authority: query difficulty: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Fatalf("admission-authority: difficulty HTTP %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Difficulty uint32 `json:"difficulty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Fatalf("admission-authority: decode difficulty: %v", err)
	}
	return body.Difficulty
}

func waitForSequence(ledgerURL, canonicalHash string, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	url := ledgerURL + "/v1/entries-hash/" + canonicalHash
	for time.Now().Before(deadline) {
		resp, err := hc.Get(url)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var er struct {
					SequenceNumber uint64 `json:"sequence_number"`
				}
				// 200 means the entry is sequenced (the endpoint 404s until then),
				// so sequence 0 is valid — the FIRST entry on a fresh gating=require
				// log (no genesis seed) takes seq 0.
				if jErr := json.Unmarshal(body, &er); jErr == nil {
					return er.SequenceNumber, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, fmt.Errorf("not sequenced within %s", timeout)
}

func modeLabel(token string) string {
	if token != "" {
		return "Mode A (credit)"
	}
	return "Mode B (PoW)"
}

func addrsLabel(addrs [][20]byte) string {
	if len(addrs) == 0 {
		return "{} (freeze — no authorities)"
	}
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = "0x" + hex.EncodeToString(a[:])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
