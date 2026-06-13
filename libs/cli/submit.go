package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/loadgen"
)

// RunSubmit submits ONE entry to the bundle's network — the canonical end-user
// action. A new entity mints (or loads) a signer identity; an amendment (--amend
// <seq>) updates an existing entity, signed by its key (--key-file). It prints
// the assigned sequence + the entry's SMT key.
func RunSubmit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	var (
		bundlePath   = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network      = fs.String("network", "", "stored network name (else the active network)")
		payload      = fs.String("payload", "", "entry payload (UTF-8) — REQUIRED")
		dryRun       = fs.Bool("dry-run", false, "build, sign, validate and serialize the entry, then stop BEFORE the POST")
		amend        = fs.Int64("amend", -1, "amend the entity at this sequence (signed by its key); omit to create a new entity")
		delegateTo   = fs.String("delegate-to", "", "mint a delegation: the entity (--key-file) grants authority to this delegate DID")
		delegation   = fs.Int64("delegation", -1, "with --amend: a DELEGATED amendment citing the delegation at this sequence (--key-file is the delegate)")
		keyFile      = fs.String("key-file", "", "32-byte hex secp256k1 signer key; REQUIRED for --amend/--delegate-to/delegated, optional for a new entity")
		outKey       = fs.String("out-key", "", "write the generated signer key (hex) here (new root only)")
		token        = fs.String("token", "", "Mode A credit token; empty ⇒ Mode B PoW")
		difficulty   = fs.Int("difficulty", 0, "Mode B PoW difficulty (0 ⇒ query the ledger)")
		cosignerKeys = fs.String("cosigner-keys", "", "comma-separated key files (hex) added as INLINE cosignatures on ONE entry (in-band multi-sig, model #1; requires a gated network's write_endpoint — the write gate's cosignature policy decides)")
		cosign       = fs.String("cosign", "", "TWO-PART attestation (model #2): submit a separate entry that cosigns the prior primary at <log-did>@<seq> (sets Header.CosignatureOf; @<seq> alone ⇒ this network's log)")
		timeout      = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *payload == "" {
		return fmt.Errorf("--payload is required")
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	logDID, err := b.RequireLogDID()
	if err != nil {
		return err
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	// Resolve the signer identity.
	var id loadgen.Identity
	switch {
	case *keyFile != "":
		raw, kerr := readHexKey(*keyFile)
		if kerr != nil {
			return kerr
		}
		if id, err = loadgen.IdentityFromScalar(raw); err != nil {
			return err
		}
	case *amend >= 0 || *delegation >= 0 || *delegateTo != "":
		return fmt.Errorf("this operation requires --key-file (the signer: the entity for --amend/--delegate-to, the delegate for a delegated amendment)")
	default:
		kp, gerr := sdkdid.GenerateDIDKeySecp256k1()
		if gerr != nil {
			return fmt.Errorf("generate signer key: %w", gerr)
		}
		id = loadgen.Identity{DID: kp.DID, Priv: kp.PrivateKey}
		if *outKey != "" {
			if werr := writeHexKey(*outKey, scalarBytes(kp.PrivateKey)); werr != nil {
				return werr
			}
			tablef("submit: wrote signer key → %s (keep it to amend this root later)\n", *outKey)
		}
	}

	// Resolve any INLINE cosigners (model #1, in-band multi-sig): each signs the
	// SAME signing payload and rides on ONE entry. The write gate's cosignature
	// policy decides, so they require a gated write_endpoint (enforced at submit
	// below).
	cosigners, ccErr := resolveCosigners(*cosignerKeys)
	if ccErr != nil {
		return ccErr
	}
	if *cosign != "" && (*amend >= 0 || *delegation >= 0 || *delegateTo != "") {
		return fmt.Errorf("--cosign is standalone (an attestation entry): combine it with --payload only, not --amend/--delegate-to/--delegation")
	}

	// Build the entry.
	var entry *envelope.Entry
	kind := "entity"
	switch {
	case *cosign != "":
		// Model #2 (two-part attestation): a commentary entry that cosigns the prior
		// primary via Header.CosignatureOf. The ledger's gate-2 requires that target
		// to ALREADY be sequenced (part 1); this submit is part 2.
		pos, perr := parseLogPos(*cosign, logDID)
		if perr != nil {
			return perr
		}
		kind = "attestation→" + pos.String()
		entry, err = builder.BuildCommentary(builder.CommentaryParams{
			Destination: logDID, SignerDID: id.DID,
			Payload: []byte(*payload), EventTime: time.Now().UTC().UnixMicro(),
		})
		if err == nil {
			entry.Header.CosignatureOf = &pos
		}
	case *delegateTo != "":
		kind = "delegation→" + short(*delegateTo)
		entry, err = builder.BuildDelegation(builder.DelegationParams{
			Destination: logDID, SignerDID: id.DID, DelegateDID: *delegateTo,
			Payload: []byte(*payload), EventTime: time.Now().UTC().UnixMicro(),
		})
	case *amend >= 0 && *delegation >= 0:
		kind = fmt.Sprintf("delegated-amendment-of-%d-via-%d", *amend, *delegation)
		entry, err = builder.BuildPathBEntry(builder.PathBParams{
			Destination: logDID, SignerDID: id.DID,
			TargetRoot:         types.LogPosition{LogDID: logDID, Sequence: uint64(*amend)},
			DelegationPointers: []types.LogPosition{{LogDID: logDID, Sequence: uint64(*delegation)}},
			Payload:            []byte(*payload), EventTime: time.Now().UTC().UnixMicro(),
		})
	case *amend >= 0:
		kind = fmt.Sprintf("amendment-of-%d", *amend)
		entry, err = builder.BuildAmendment(builder.AmendmentParams{
			Destination: logDID, SignerDID: id.DID,
			TargetRoot: types.LogPosition{LogDID: logDID, Sequence: uint64(*amend)},
			Payload:    []byte(*payload), EventTime: time.Now().UTC().UnixMicro(),
		})
	default:
		entry, err = builder.BuildRootEntity(builder.RootEntityParams{
			Destination: logDID, SignerDID: id.DID,
			Payload: []byte(*payload), EventTime: time.Now().UTC().UnixMicro(),
		})
	}
	if err != nil {
		return fmt.Errorf("build entry: %w", err)
	}

	var seq uint64
	if b.WriteEndpoint != "" {
		// GATED network: write THROUGH the network's write gate — it runs its
		// admission policy (cosignature + prerequisite) and mints the gate-5
		// WriteAuthorization the ledger requires. Multi-sign (primary + inline
		// cosigners); the gate's forward satisfies the payment axis, so no
		// PoW/token is attached here.
		seq, err = submitViaGate(ctx, hc, b, entry, id, cosigners, *timeout, *dryRun)
	} else {
		if len(cosigners) > 0 {
			return fmt.Errorf("--cosigner-keys (in-band multi-sig) needs a gated network (a write_endpoint / write gate): inline cosignatures are validated by the gate's cosignature policy, not on a direct-to-ledger write")
		}
		seq, err = loadgen.SubmitOne(ctx, loadgen.SubmitParams{
			LedgerURL:      b.Endpoint,
			LogDID:         logDID,
			Token:          *token,
			Difficulty:     uint32(*difficulty),
			EpochWindowSec: b.Admission.EpochWindowSec,
			HTTPClient:     hc,
		}, entry, id.Priv, id.DID)
	}
	if err != nil {
		return err
	}

	key := smt.DeriveKey(types.LogPosition{LogDID: logDID, Sequence: seq})
	tablef("submit: %s sequenced — seq=%d signer=%s smt_key=%s\n", kind, seq, id.DID, hex.EncodeToString(key[:]))
	return nil
}

// scalarBytes renders a private key's secret scalar as 32 big-endian bytes.
func scalarBytes(priv *ecdsa.PrivateKey) []byte {
	b := make([]byte, 32)
	priv.D.FillBytes(b)
	return b
}

// readHexKey reads a 32-byte hex secp256k1 scalar from a file (whitespace trimmed).
func readHexKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", path, err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("parse key %q: not hex: %w", path, err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("key %q: want 32 bytes (64 hex), got %d", path, len(raw))
	}
	return raw, nil
}

// writeHexKey writes a scalar as hex to a 0600 file.
func writeHexKey(path string, raw []byte) error {
	if err := os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		return fmt.Errorf("write key %q: %w", path, err)
	}
	return nil
}

// resolveCosigners loads each comma-separated hex key file into a loadgen.Identity
// — the INLINE cosigners for model #1 (in-band multi-sig). Empty ⇒ none.
func resolveCosigners(csv string) ([]loadgen.Identity, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var out []loadgen.Identity
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		raw, rErr := readHexKey(p)
		if rErr != nil {
			return nil, fmt.Errorf("cosigner key: %w", rErr)
		}
		id, iErr := loadgen.IdentityFromScalar(raw)
		if iErr != nil {
			return nil, fmt.Errorf("cosigner key %q: %w", p, iErr)
		}
		out = append(out, id)
	}
	return out, nil
}

// parseLogPos parses a <log-did>@<seq> position (model #2's --cosign target). A
// bare @<seq> defaults the log to this network's own log.
func parseLogPos(arg, defaultLogDID string) (types.LogPosition, error) {
	at := strings.LastIndex(arg, "@")
	if at < 0 {
		return types.LogPosition{}, fmt.Errorf("--cosign %q must be <log-did>@<seq> (or @<seq> for this network's log)", arg)
	}
	ld, seqStr := arg[:at], arg[at+1:]
	if ld == "" {
		ld = defaultLogDID
	}
	seq, err := strconv.ParseUint(strings.TrimSpace(seqStr), 10, 64)
	if err != nil {
		return types.LogPosition{}, fmt.Errorf("--cosign sequence %q: not a uint64", seqStr)
	}
	return types.LogPosition{LogDID: ld, Sequence: seq}, nil
}

// submitViaGate signs entry with the primary + inline cosigners (over the SAME
// signing payload), POSTs it THROUGH the network's write gate (which runs its
// admission policy + mints the gate-5 WriteAuthorization), then waits for the
// LEDGER to sequence it.
// Reads stay on the ledger; the bundle's mTLS transport serves both hops (one
// network CA verifies both server certs).
func submitViaGate(ctx context.Context, hc *http.Client, b *ClientBundle, entry *envelope.Entry, primary loadgen.Identity, cosigners []loadgen.Identity, timeout time.Duration, dryRun bool) (uint64, error) {
	u, err := envelope.NewUnsignedEntry(entry.Header, entry.DomainPayload)
	if err != nil {
		return 0, fmt.Errorf("new unsigned entry: %w", err)
	}
	digest := sha256.Sum256(envelope.SigningPayload(u))
	sigs := make([]envelope.Signature, 0, 1+len(cosigners))
	psig, err := signatures.SignEntry(digest, primary.Priv)
	if err != nil {
		return 0, fmt.Errorf("primary sign: %w", err)
	}
	sigs = append(sigs, envelope.Signature{SignerDID: primary.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: psig})
	for _, c := range cosigners {
		csig, serr := signatures.SignEntry(digest, c.Priv)
		if serr != nil {
			return 0, fmt.Errorf("cosigner %s sign: %w", c.DID, serr)
		}
		sigs = append(sigs, envelope.Signature{SignerDID: c.DID, AlgoID: envelope.SigAlgoECDSA, Bytes: csig})
	}
	u.Signatures = sigs
	if vErr := u.Validate(); vErr != nil {
		return 0, fmt.Errorf("validate signed entry: %w", vErr)
	}
	wire, err := envelope.Serialize(u)
	if err != nil {
		return 0, fmt.Errorf("serialize: %w", err)
	}
	if dryRun {
		// PRE-1 two-phase contract: the entry built, signed, validated and
		// serialized through the production pipeline; the write does not
		// happen. The canonical bytes ARE what a real run would post.
		tableln("dry-run: entry validated and serialized; stopping before POST")
		tablef("dry-run: canonical bytes: %d\n", len(wire))
		return 0, nil
	}
	hash, err := postThroughGate(ctx, hc, strings.TrimRight(b.WriteEndpoint, "/")+"/v1/entries/submit", wire)
	if err != nil {
		return 0, err
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return pollSequence(ctx, hc, strings.TrimRight(b.Endpoint, "/")+"/v1/entries-hash/"+hash, timeout)
}

// postThroughGate POSTs wire bytes to the gate's /v1/entries/submit (mTLS) and
// returns the canonical_hash from the forwarded ledger SCT. A non-202 surfaces the
// gate's own rejection — its submit-gate verdict (cosignature/prerequisite) or the
// ledger's gate-5 refusal — verbatim, so the operator sees exactly which gate said no.
func postThroughGate(ctx context.Context, hc *http.Client, url string, wire []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("write gate submit HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var sct struct {
		CanonicalHash string `json:"canonical_hash"`
	}
	if jErr := json.Unmarshal(body, &sct); jErr != nil || sct.CanonicalHash == "" {
		return "", fmt.Errorf("parse forwarded SCT canonical_hash: %v (body=%s)", jErr, body)
	}
	return sct.CanonicalHash, nil
}

// pollSequence polls the ledger's GET /v1/entries-hash/{hash} until the entry is
// sequenced, returning its assigned sequence. sequence_number is decoded as a
// POINTER so a still-pending {"state":...} keeps polling (never collapses to 0).
func pollSequence(ctx context.Context, hc *http.Client, url string, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		req, rErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if rErr != nil {
			return 0, rErr
		}
		resp, dErr := hc.Do(req)
		if dErr == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var er struct {
					SequenceNumber *uint64 `json:"sequence_number"`
				}
				if json.Unmarshal(body, &er) == nil && er.SequenceNumber != nil {
					return *er.SequenceNumber, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, fmt.Errorf("the write gate accepted the write, but the ledger did not sequence it within %s", timeout)
}

// ─────────────────────────────────────────────────────────────────────────────
// The agnostic dumb-write transport (J7). The protocol "POST already-signed
// canonical bytes → poll /v1/entries-hash until sequenced" was reimplemented in
// every direct-to-ledger tool (judicial-cli submit/wait, the ledger's
// submit-stamp, declare-anchor-target). It lives here ONCE: the POST half
// (SubmitWire → canonical_hash, or PostEntry → the raw SCT body for callers that
// verify it), the poll half (WaitForSequence), and the one-shot
// (SubmitWireAndWait) — all operating only on (http client, ledger URL, bytes,
// token): NO bundle, no network identity, no domain type, so it sits BENEATH the
// network bundle (a bundle-driven caller resolves URL+client from
// b.Endpoint/b.HTTPClient; a bundle-free tool passes a raw URL).
// ─────────────────────────────────────────────────────────────────────────────

// SubmitWire POSTs already-signed canonical entry bytes to a ledger's
// POST /v1/entries and returns the canonical_hash from the 202 SCT (no poll) —
// the POST half. token, when non-empty, is a Bearer credential (gated/Mode-A);
// a non-202 surfaces the ledger's admission verdict verbatim.
func SubmitWire(ctx context.Context, hc *http.Client, ledgerBaseURL, token string, wire []byte) (string, error) {
	return postDirect(ctx, hc, strings.TrimRight(ledgerBaseURL, "/")+"/v1/entries", token, wire)
}

// WaitForSequence polls a ledger's GET /v1/entries-hash/{hash} until the entry
// is sequenced, returning its assigned sequence — the poll half. The terminal
// response is the entry record carrying sequence_number (pollSequence); the
// pending/manual interim {"state":…} keeps polling. timeout (<=0 ⇒ 120s) bounds it.
func WaitForSequence(ctx context.Context, hc *http.Client, ledgerBaseURL, hash string, timeout time.Duration) (uint64, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return pollSequence(ctx, hc, strings.TrimRight(ledgerBaseURL, "/")+"/v1/entries-hash/"+hash, timeout)
}

// SubmitWireAndWait is SubmitWire then WaitForSequence — the one-shot
// submit-and-confirm a tool uses when it wants the sequence in one call.
func SubmitWireAndWait(ctx context.Context, hc *http.Client, ledgerBaseURL, token string, wire []byte, timeout time.Duration) (uint64, error) {
	hash, err := SubmitWire(ctx, hc, ledgerBaseURL, token, wire)
	if err != nil {
		return 0, err
	}
	return WaitForSequence(ctx, hc, ledgerBaseURL, hash, timeout)
}

// PostEntry POSTs already-signed canonical entry bytes to a ledger's
// POST /v1/entries and returns the RAW 202 SCT response body — the transport
// every direct-to-ledger writer shares. SubmitWire is the convenience that
// extracts canonical_hash from this body; a tool that needs the whole SCT reads
// the body itself (submit-stamp verifies the SCT's own signature against the
// ledger's did:key; declare-anchor-target just needs the 202). token, when
// non-empty, is a Bearer credential; a non-202 surfaces the ledger's verdict.
func PostEntry(ctx context.Context, hc *http.Client, ledgerBaseURL, token string, wire []byte) ([]byte, error) {
	return postRaw(ctx, hc, strings.TrimRight(ledgerBaseURL, "/")+"/v1/entries", token, wire)
}

// postDirect POSTs wire bytes to a ledger's /v1/entries (the dumb-write surface,
// no submit gate) and returns the canonical_hash from the 202 SCT — the direct
// sibling of postThroughGate.
func postDirect(ctx context.Context, hc *http.Client, url, token string, wire []byte) (string, error) {
	body, err := postRaw(ctx, hc, url, token, wire)
	if err != nil {
		return "", err
	}
	var sct struct {
		CanonicalHash string `json:"canonical_hash"`
	}
	if jErr := json.Unmarshal(body, &sct); jErr != nil || sct.CanonicalHash == "" {
		return "", fmt.Errorf("parse SCT canonical_hash: %v (body=%s)", jErr, body)
	}
	return sct.CanonicalHash, nil
}

// postRaw POSTs octet-stream wire bytes (Bearer token when set) to url and
// returns the 202 body; a non-202 surfaces the ledger's verdict verbatim. The
// single POST implementation behind SubmitWire and PostEntry.
func postRaw(ctx context.Context, hc *http.Client, url, token string, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("ledger /v1/entries HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
