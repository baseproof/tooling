/*
FILE PATH: libs/cli/cosign.go

DESCRIPTION:

	`baseproof cosign <draft|show|sign|submit>` — the file-based cosign-request
	relay (PRE-5). Offline assembly of the in-band multi-sig model the write
	gate already verifies: every party signs the SAME SigningPayload digest,
	and the assembled entry is byte-identical to what a single-host
	--cosigner-keys submit produces. The relay is CONVENIENCE, NEVER
	AUTHORITY — the gate re-verifies the mix, the roles, and every signature
	regardless of anything checked here.

	ARTIFACT (baseproof.cosign-request/v1): explicit draft fields + payload
	(the SDK refuses to serialize unsigned entries — correctly — so the wire
	form is reconstructed at every hop via NewUnsignedEntry), a pinned
	draft_digest (sha256 of the SDK SigningPayload — reconstruction drift or
	tampering is FATAL at render, before any signing), the manifest
	operation's Signing rule embedded VERBATIM (copied from the door-verified
	manifest at draft time — describe and validate share one source), and the
	collected signatures with their claimed roles.

	RENDER-BEFORE-SIGN: `show`/`sign` reconstruct the draft, fatal-check the
	digest, display the payload, and CRYPTOGRAPHICALLY verify every already-
	collected signature against the digest — no blind countersigning.

	COMPLETENESS (client-side, signer axis): collected roles are checked
	against the embedded rule's RequiredSignerRoles/EffectiveMinCosigners
	via the SAME libs/policy helpers the gate's policy table uses. The filer
	axis (filed_by_capacity inside the payload) is the gate's domain bind —
	the relay passes the payload through opaquely.

	v1 scope: same-signer authority drafts (AuthoritySameSigner); delegated
	authority paths ride a later dial. Expiry: the draft's EventTime is
	signed by every party; the gate's existing event-time windows apply —
	the relay adds no second clock.
*/
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	sdkenv "github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/baseproof/tooling/libs/loadgen"
	"github.com/baseproof/tooling/libs/networkbundle"
	"github.com/baseproof/tooling/libs/policy"
)

// CosignRequestFormat tags the relay artifact.
const CosignRequestFormat = "baseproof.cosign-request/v1"

// CosignDraft is the reconstructible unsigned entry: every hop rebuilds the
// SDK entry from these fields and must land on the pinned digest.
type CosignDraft struct {
	SignerDID   string `json:"signer_did"`
	Destination string `json:"destination"`
	EventTime   int64  `json:"event_time"` // unix micro; signed by every party
	PayloadB64  string `json:"payload_b64"`
}

// CollectedSignature is one party's signature over the draft digest.
type CollectedSignature struct {
	SignerDID    string `json:"signer_did"`
	Role         string `json:"role,omitempty"` // claimed signer role (gate re-verifies the bind)
	AlgoID       uint16 `json:"algo_id"`
	SignatureB64 string `json:"signature_b64"`
}

// CosignRequest is the relay artifact.
type CosignRequest struct {
	SchemaVersion string      `json:"schema_version"`
	Operation     string      `json:"operation"` // the manifest event_type this satisfies
	Draft         CosignDraft `json:"draft"`

	// DraftDigest pins sha256(SigningPayload(reconstructed entry)) — the
	// exact digest every signature covers. Reconstruction mismatch = FATAL.
	DraftDigest string `json:"draft_digest"`

	// Signing is the manifest operation's enforced rule, embedded verbatim
	// at draft time from a door-verified manifest.
	Signing *policy.CosignatureRule `json:"signing"`

	Collected []CollectedSignature `json:"collected"`
}

// RunCosign dispatches `baseproof cosign <draft|show|sign|submit>`.
func RunCosign(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: baseproof cosign <draft|show|sign|submit> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "draft":
		return cosignDraft(ctx, rest)
	case "show":
		return cosignShow(ctx, rest)
	case "sign":
		return cosignSign(ctx, rest)
	case "submit":
		return cosignSubmit(ctx, rest)
	default:
		return fmt.Errorf("cosign: unknown subcommand %q (draft|show|sign|submit)", sub)
	}
}

// ─── draft ───────────────────────────────────────────────────────────

func cosignDraft(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("cosign draft", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		operation  = fs.String("operation", "", "manifest event_type this entry performs — REQUIRED")
		payload    = fs.String("payload", "", "entry payload (UTF-8; or --payload-file)")
		payloadF   = fs.String("payload-file", "", "entry payload file")
		keyFile    = fs.String("signer-key", "", "32-byte hex secp256k1 PRIMARY signer key — REQUIRED")
		role       = fs.String("role", "", "the primary's role label (default: the operation's primary_role)")
		out        = fs.String("out", "", "write the cosign-request here — REQUIRED")
		output     = fs.String("output", "table", "output format: table|json")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *operation == "" || *keyFile == "" || *out == "" {
		return fmt.Errorf("cosign draft: --operation, --signer-key and --out are required")
	}
	body, err := payloadBytes(*payload, *payloadF)
	if err != nil {
		return err
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	// The rule comes from the DOOR-VERIFIED manifest — never asserted.
	m, err := fetchVerifiedManifest(ctx, hc, b)
	if err != nil {
		return err
	}
	op := operationByType(m, *operation)
	if op == nil {
		return fmt.Errorf("cosign draft: operation %q is not in the network's manifest", *operation)
	}
	if op.Signing == nil {
		return fmt.Errorf("cosign draft: operation %q requires no cosignature mix — use `baseproof submit` directly", *operation)
	}

	rawKey, err := readHexKey(*keyFile)
	if err != nil {
		return err
	}
	id, err := loadgen.IdentityFromScalar(rawKey)
	if err != nil {
		return err
	}

	req := &CosignRequest{
		SchemaVersion: CosignRequestFormat,
		Operation:     *operation,
		Draft: CosignDraft{
			SignerDID:   id.DID,
			Destination: m.Exchange,
			EventTime:   time.Now().UTC().UnixMicro(),
			PayloadB64:  base64.StdEncoding.EncodeToString(body),
		},
		Signing: op.Signing,
	}
	digest, _, err := reconstructDigest(req)
	if err != nil {
		return err
	}
	req.DraftDigest = hex.EncodeToString(digest[:])

	primaryRole := *role
	if primaryRole == "" {
		primaryRole = op.PrimaryRole
	}
	if err := appendSignature(req, id, primaryRole, digest); err != nil {
		return err
	}
	if err := writeCosignRequest(*out, req); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "cosign: drafted %s (digest %s) — relay the file to the countersigners\n", *out, short(req.DraftDigest))
	return emitOutput(*output, "cosign-draft", cosignStatus(req), func() error {
		renderCosignRequest(req)
		return nil
	})
}

// ─── show / sign ─────────────────────────────────────────────────────

func cosignShow(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("cosign show", flag.ContinueOnError)
	output := fs.String("output", "table", "output format: table|json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: baseproof cosign show <request-file>")
	}
	req, _, err := loadAndRender(fs.Arg(0))
	if err != nil {
		return err
	}
	return emitOutput(*output, "cosign-show", cosignStatus(req), func() error {
		renderCosignRequest(req)
		return nil
	})
}

func cosignSign(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("cosign sign", flag.ContinueOnError)
	var (
		keyFile = fs.String("signer-key", "", "32-byte hex secp256k1 countersigner key — REQUIRED")
		role    = fs.String("role", "", "the role this countersignature satisfies — REQUIRED")
		output  = fs.String("output", "table", "output format: table|json")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *keyFile == "" || *role == "" {
		return fmt.Errorf("usage: baseproof cosign sign <request-file> --signer-key k.hex --role <role>")
	}
	path := fs.Arg(0)

	// RENDER-BEFORE-SIGN: reconstruct, fatal-check the digest, verify every
	// collected signature — only then countersign.
	req, digest, err := loadAndRender(path)
	if err != nil {
		return err
	}
	if !req.Signing.PermitsSignerRole(*role) {
		return fmt.Errorf("cosign sign: role %q is not in the operation's required_signer_roles %v",
			*role, req.Signing.RequiredSignerRoles)
	}
	rawKey, err := readHexKey(*keyFile)
	if err != nil {
		return err
	}
	id, err := loadgen.IdentityFromScalar(rawKey)
	if err != nil {
		return err
	}
	if err := appendSignature(req, id, *role, digest); err != nil {
		return err
	}
	if err := writeCosignRequest(path, req); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "cosign: countersigned as %s (%s) — %s\n", id.DID, *role, completenessLine(req))
	return emitOutput(*output, "cosign-sign", cosignStatus(req), func() error {
		renderCosignRequest(req)
		return nil
	})
}

// ─── submit ──────────────────────────────────────────────────────────

func cosignSubmit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("cosign submit", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		output     = fs.String("output", "table", "output format: table|json")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: baseproof cosign submit <request-file>")
	}
	req, digest, err := loadAndRender(fs.Arg(0))
	if err != nil {
		return err
	}
	// Client-side completeness on the signer axis — the gate re-verifies
	// everything (including the filer bind inside the payload) regardless.
	if missing := missingSignerCount(req); missing > 0 {
		return fmt.Errorf("cosign submit: incomplete mix — %s (the gate would refuse; collect %d more)",
			completenessLine(req), missing)
	}

	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	if b.WriteEndpoint == "" {
		return fmt.Errorf("cosign submit: the network is not gated (no write_endpoint) — a cosignature mix is validated by the write gate")
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	u, err := reconstructEntry(req)
	if err != nil {
		return err
	}
	for _, c := range req.Collected {
		sig, dErr := base64.StdEncoding.DecodeString(c.SignatureB64)
		if dErr != nil {
			return fmt.Errorf("cosign submit: signature of %s: %v", c.SignerDID, dErr)
		}
		u.Signatures = append(u.Signatures, sdkenv.Signature{
			SignerDID: c.SignerDID, AlgoID: c.AlgoID, Bytes: sig,
		})
	}
	if vErr := u.Validate(); vErr != nil {
		return fmt.Errorf("cosign submit: assembled entry invalid: %w", vErr)
	}
	wire, err := sdkenv.Serialize(u)
	if err != nil {
		return fmt.Errorf("cosign submit: serialize: %w", err)
	}
	hash, err := postThroughGate(ctx, hc, strings.TrimRight(b.WriteEndpoint, "/")+"/v1/entries/submit", wire)
	if err != nil {
		return err
	}
	seq, err := pollSequence(ctx, hc, strings.TrimRight(b.Endpoint, "/")+"/v1/entries-hash/"+hash, *timeout)
	if err != nil {
		return fmt.Errorf("the write gate accepted the relay submission (canonical_hash=%s) but the ledger did not sequence it: %w", hash, err)
	}
	data := struct {
		Sequence      uint64 `json:"sequence"`
		CanonicalHash string `json:"canonical_hash"`
		Operation     string `json:"operation"`
		Signatures    int    `json:"signatures"`
		DraftDigest   string `json:"draft_digest"`
	}{seq, hash, req.Operation, len(req.Collected), hex.EncodeToString(digest[:])}
	return emitOutput(*output, "cosign-submit", data, func() error {
		fmt.Printf("cosign: ✔ sequenced at %d (canonical_hash=%s, %d signatures over digest %s)\n",
			seq, short(hash), data.Signatures, short(data.DraftDigest))
		return nil
	})
}

// ─── mechanics ───────────────────────────────────────────────────────

// reconstructEntry rebuilds the SDK unsigned entry from the draft fields.
func reconstructEntry(req *CosignRequest) (*sdkenv.Entry, error) {
	payload, err := base64.StdEncoding.DecodeString(req.Draft.PayloadB64)
	if err != nil {
		return nil, fmt.Errorf("cosign: draft payload: %w", err)
	}
	auth := sdkenv.AuthoritySameSigner
	return sdkenv.NewUnsignedEntry(sdkenv.ControlHeader{
		SignerDID:     req.Draft.SignerDID,
		Destination:   req.Draft.Destination,
		AuthorityPath: &auth,
		EventTime:     req.Draft.EventTime,
	}, payload)
}

// reconstructDigest rebuilds the entry and returns the signing digest. When
// the artifact carries a pinned DraftDigest, a mismatch is FATAL — the file
// was tampered with or the hosts disagree on the wire contract.
func reconstructDigest(req *CosignRequest) ([32]byte, *sdkenv.Entry, error) {
	u, err := reconstructEntry(req)
	if err != nil {
		return [32]byte{}, nil, err
	}
	digest := sha256.Sum256(sdkenv.SigningPayload(u))
	if req.DraftDigest != "" && req.DraftDigest != hex.EncodeToString(digest[:]) {
		return [32]byte{}, nil, fmt.Errorf("cosign: TAMPERED draft — reconstructed digest %s does not match the pinned %s (refusing before any signature)",
			short(hex.EncodeToString(digest[:])), short(req.DraftDigest))
	}
	return digest, u, nil
}

// loadAndRender loads + strict-decodes the artifact, fatal-checks the digest,
// and cryptographically verifies every collected signature — render before
// sign, no blind countersigning.
func loadAndRender(path string) (*CosignRequest, [32]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("cosign: read %q: %w", path, err)
	}
	var req CosignRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, [32]byte{}, fmt.Errorf("cosign: decode %q: %w", path, err)
	}
	if req.SchemaVersion != CosignRequestFormat {
		return nil, [32]byte{}, fmt.Errorf("cosign: %q schema_version %q, want %q", path, req.SchemaVersion, CosignRequestFormat)
	}
	if req.Signing == nil {
		return nil, [32]byte{}, fmt.Errorf("cosign: %q carries no signing rule — not a relayable request", path)
	}
	digest, _, err := reconstructDigest(&req)
	if err != nil {
		return nil, [32]byte{}, err
	}
	for i := range req.Collected {
		if err := verifyCollected(&req.Collected[i], digest); err != nil {
			return nil, [32]byte{}, fmt.Errorf("cosign: collected[%d] (%s): %w — refusing the artifact", i, req.Collected[i].SignerDID, err)
		}
	}
	return &req, digest, nil
}

// verifyCollected cryptographically checks one collected signature against
// the digest (did:key secp256k1 / ECDSA — the relay's v1 scheme).
func verifyCollected(c *CollectedSignature, digest [32]byte) error {
	if c.AlgoID != sdkenv.SigAlgoECDSA {
		return fmt.Errorf("unsupported algo_id %d (relay v1 verifies ECDSA did:key)", c.AlgoID)
	}
	pubBytes, _, err := sdkdid.ParseDIDKey(c.SignerDID)
	if err != nil {
		return fmt.Errorf("signer DID: %v", err)
	}
	pub, err := secp.ParsePubKey(pubBytes)
	if err != nil {
		return fmt.Errorf("signer public key: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(c.SignatureB64)
	if err != nil {
		return fmt.Errorf("signature encoding: %v", err)
	}
	if err := signatures.VerifyEntry(digest, sig, pub.ToECDSA()); err != nil {
		return fmt.Errorf("signature does not verify against the draft digest: %v", err)
	}
	return nil
}

// appendSignature signs the digest and appends, refusing duplicates.
func appendSignature(req *CosignRequest, id loadgen.Identity, role string, digest [32]byte) error {
	for _, c := range req.Collected {
		if c.SignerDID == id.DID {
			return fmt.Errorf("cosign: %s has already signed this request", id.DID)
		}
	}
	sig, err := signatures.SignEntry(digest, id.Priv)
	if err != nil {
		return fmt.Errorf("cosign: sign: %w", err)
	}
	req.Collected = append(req.Collected, CollectedSignature{
		SignerDID: id.DID, Role: role,
		AlgoID: sdkenv.SigAlgoECDSA, SignatureB64: base64.StdEncoding.EncodeToString(sig),
	})
	return nil
}

// missingSignerCount is the client-side signer-axis completeness check,
// derived from the embedded rule via the SAME libs/policy helpers the gate's
// table exposes: cosigners (beyond the primary) holding a required role,
// counted against EffectiveMinCosigners.
func missingSignerCount(req *CosignRequest) int {
	need := req.Signing.EffectiveMinCosigners()
	have := 0
	for i, c := range req.Collected {
		if i == 0 {
			continue // the primary is not a cosigner
		}
		if req.Signing.PermitsSignerRole(c.Role) {
			have++
		}
	}
	if have >= need {
		return 0
	}
	return need - have
}

func completenessLine(req *CosignRequest) string {
	need := req.Signing.EffectiveMinCosigners()
	missing := missingSignerCount(req)
	return fmt.Sprintf("%d/%d required cosigners collected (roles %v)", need-missing, need, req.Signing.RequiredSignerRoles)
}

// CosignStatusData is the --output json data shape for draft/show/sign.
type CosignStatusData struct {
	Operation   string               `json:"operation"`
	Destination string               `json:"destination"`
	SignerDID   string               `json:"signer_did"`
	EventTime   int64                `json:"event_time"`
	DraftDigest string               `json:"draft_digest"`
	Required    []string             `json:"required_signer_roles"`
	MinCosign   int                  `json:"min_cosigners"`
	Collected   []CollectedSignature `json:"collected"`
	Complete    bool                 `json:"complete"`
}

func cosignStatus(req *CosignRequest) CosignStatusData {
	return CosignStatusData{
		Operation:   req.Operation,
		Destination: req.Draft.Destination,
		SignerDID:   req.Draft.SignerDID,
		EventTime:   req.Draft.EventTime,
		DraftDigest: req.DraftDigest,
		Required:    append([]string(nil), req.Signing.RequiredSignerRoles...),
		MinCosign:   req.Signing.EffectiveMinCosigners(),
		Collected:   append([]CollectedSignature(nil), req.Collected...),
		Complete:    missingSignerCount(req) == 0,
	}
}

func renderCosignRequest(req *CosignRequest) {
	fmt.Printf("cosign request: operation=%s destination=%s\n", req.Operation, req.Draft.Destination)
	fmt.Printf("  primary=%s event_time=%d digest=%s\n", req.Draft.SignerDID, req.Draft.EventTime, short(req.DraftDigest))
	fmt.Printf("  rule: required_signer_roles=%v min_cosigners=%d intra_exchange_only=%v\n",
		req.Signing.RequiredSignerRoles, req.Signing.EffectiveMinCosigners(), req.Signing.IntraExchangeOnly)
	payload, err := base64.StdEncoding.DecodeString(req.Draft.PayloadB64)
	if err == nil {
		pretty := payload
		var any json.RawMessage
		if json.Unmarshal(payload, &any) == nil {
			if p, e := json.MarshalIndent(any, "  ", "  "); e == nil {
				pretty = p
			}
		}
		fmt.Printf("  payload (%d bytes):\n  %s\n", len(payload), pretty)
	}
	for i, c := range req.Collected {
		who := "cosigner"
		if i == 0 {
			who = "primary"
		}
		fmt.Printf("  [%d] %s %s role=%q ✔ verified\n", i, who, c.SignerDID, c.Role)
	}
	fmt.Printf("  status: %s\n", completenessLine(req))
}

// fetchVerifiedManifest pulls the network's bundle for its sole served
// destination and runs it through the door — the rule a draft embeds is
// always derived from a verified document, never asserted.
func fetchVerifiedManifest(ctx context.Context, hc *http.Client, b *ClientBundle) (*networkbundle.Manifest, error) {
	dest, err := soleServedDestination(ctx, hc, b.Endpoint)
	if err != nil {
		return nil, err
	}
	raw, _, err := fetchManifestBytes(ctx, hc, b.Endpoint, dest)
	if err != nil {
		return nil, err
	}
	return verifyAgainstNetwork(ctx, hc, b, raw)
}

func operationByType(m *networkbundle.Manifest, evt string) *networkbundle.Operation {
	for i := range m.Operations {
		if m.Operations[i].EventType == evt {
			return &m.Operations[i]
		}
	}
	return nil
}

func payloadBytes(literal, file string) ([]byte, error) {
	switch {
	case literal != "" && file != "":
		return nil, fmt.Errorf("cosign: pass --payload or --payload-file, not both")
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("cosign: read payload %q: %w", file, err)
		}
		return b, nil
	case literal != "":
		return []byte(literal), nil
	default:
		return nil, fmt.Errorf("cosign: --payload or --payload-file is required")
	}
}

// writeCosignRequest writes atomically (temp + rename) so a relay file is
// never observed half-written.
func writeCosignRequest(path string, req *CosignRequest) error {
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
