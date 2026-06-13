/*
FILE PATH: libs/cli/burn_cmd.go

`baseproof network burn <draft|consent|finalize|submit>` — the operator's
driver for the NETWORK-BURN ceremony (tooling#110). A burn is rotation-class:
K-of-N cosignatures of the CURRENT witness set over the burn content digest
under cosign.PurposeBurn (the W1 authority model). The assembly + verification
live in the SDK behind libs/burnceremony (the relay seam); these verbs are the
operator's file choreography around it, mirroring `network rotation`:

	draft     build the proposed burn (reason class, evidence refs, the
	          optional FINAL-ANCHOR position the network sealed into its
	          parent BEFORE burning) and write a burn-draft to relay to each
	          witness host. Prints the content digest the witnesses sign.
	consent   ONE witness host signs the draft's content digest with its key
	          (cosign.PurposeBurn) and writes a burn-consent file. Identity
	          (pub_key_id) is DERIVED from the key, never asserted.
	finalize  merge a draft + its collected consent files (ONE list) into the
	          on-log EntryNetworkBurnV1 payload; burnceremony.Finalize
	          SELF-VERIFIES through network.VerifyBurn against the live set
	          before anything is written — an under-quorum / rogue / tampered
	          burn is UNCONSTRUCTIBLE here (assembly shares the verifier).
	submit    re-validate fail-closed (structural decode + LOCAL VerifyBurn
	          against the live set), then POST to POST /v1/network/burn — the
	          ceremony's door, which feeds the single BurnProcessor chokepoint
	          (the authority). A burn this driver cannot verify locally is
	          never posted.

The driver mints no trust: the cosignatures ARE the authority, BurnProcessor
is the verifier. Local checks refuse by NAME before a wasted relay or POST —
convenience, never authority.
*/
package cli

import (
	"bytes"
	"context"
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

	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/crypto/signatures"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/libs/burnceremony"
)

// burnStrings is a repeatable string flag (--evidence, --consent).
type burnStrings []string

func (s *burnStrings) String() string     { return strings.Join(*s, ",") }
func (s *burnStrings) Set(v string) error { *s = append(*s, v); return nil }

// runNetworkBurn dispatches `baseproof network burn <sub>`.
func runNetworkBurn(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: baseproof network burn <draft|consent|finalize|submit>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "draft":
		return burnDraftCmd(ctx, rest)
	case "consent":
		return burnConsentCmd(ctx, rest)
	case "finalize":
		return burnFinalizeCmd(ctx, rest)
	case "submit":
		return burnSubmitCmd(ctx, rest)
	default:
		return fmt.Errorf("network burn: unknown subcommand %q (draft|consent|finalize|submit)", sub)
	}
}

// ─── draft ───────────────────────────────────────────────────────────

func burnDraftCmd(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("network burn draft", flag.ContinueOnError)
	var (
		bundlePath  = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network_    = fs.String("network", "", "stored network name (else the active network)")
		reasonClass = fs.String("reason-class", "", "the freeze-taxonomy token (e.g. witness_quorum_compromise) — REQUIRED")
		finalAnchor = fs.String("final-anchor", "", "the parent position sealed BEFORE burning: <log-did>@<seq> (optional; root networks omit)")
		out         = fs.String("out", "", "write the burn-draft here — REQUIRED")
		output      = fs.String("output", "table", "output format: table|json")
	)
	var evidence burnStrings
	fs.Var(&evidence, "evidence", "an evidence reference (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *reasonClass == "" || *out == "" {
		return fmt.Errorf("network burn draft: --reason-class and --out are required")
	}
	b, err := resolveBundle(*bundlePath, *network_)
	if err != nil {
		return err
	}
	if b.NetworkID == "" {
		return fmt.Errorf("network burn draft: the bundle carries no network id")
	}

	d := burnceremony.Draft{
		SchemaVersion: burnceremony.DraftSchemaV1,
		NetworkIDHex:  b.NetworkID,
		ReasonClass:   *reasonClass,
		EvidenceRefs:  evidence,
	}
	if *finalAnchor != "" {
		logDID, seq, perr := parseAnchorAt(*finalAnchor)
		if perr != nil {
			return fmt.Errorf("network burn draft: --final-anchor: %w", perr)
		}
		d.FinalAnchor = &burnceremony.FinalAnchor{LogDID: logDID, Sequence: seq}
	}

	// The content digest is derivable from the draft — print it so the
	// operator can distribute the EXACT bytes each witness signs.
	digest, err := burnceremony.ContentDigest(d)
	if err != nil {
		return fmt.Errorf("network burn draft: content digest: %w", err)
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		return fmt.Errorf("write draft %q: %w", *out, err)
	}
	return emitOutput(*output, "network-burn-draft", map[string]any{
		"out":            *out,
		"network_id":     d.NetworkIDHex,
		"reason_class":   d.ReasonClass,
		"content_digest": hex.EncodeToString(digest[:]),
		"final_anchor":   *finalAnchor,
	}, func() error {
		tablef("burn-draft written: %s\n", *out)
		tablef("content digest (each witness signs THIS): %s\n", hex.EncodeToString(digest[:]))
		tableln("next: distribute the draft; each witness runs `network burn consent`")
		return nil
	})
}

// ─── consent ─────────────────────────────────────────────────────────

func burnConsentCmd(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("network burn consent", flag.ContinueOnError)
	var (
		draftPath = fs.String("draft", "", "the burn-draft to consent to — REQUIRED")
		keyFile   = fs.String("key-file", "", "this witness's 32-byte hex secp256k1 key — REQUIRED")
		out       = fs.String("out", "", "write the burn-consent here — REQUIRED")
		output    = fs.String("output", "table", "output format: table|json")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *draftPath == "" || *keyFile == "" || *out == "" {
		return fmt.Errorf("network burn consent: --draft, --key-file and --out are required")
	}
	d, err := readBurnDraft(*draftPath)
	if err != nil {
		return err
	}
	scalar, err := readHexKey(*keyFile)
	if err != nil {
		return err
	}
	priv, err := signatures.PrivKeyFromBytes(scalar)
	if err != nil {
		return fmt.Errorf("network burn consent: key: %w", err)
	}
	// pub_key_id is DERIVED from the key (sha256 of the secp256k1 pubkey
	// bytes — the witness-set key-id convention), never asserted by a flag.
	pub := signatures.PubKeyBytes(&priv.PublicKey)
	pubKeyID := sha256.Sum256(pub)

	consent, err := burnceremony.Sign(d, priv, pubKeyID, signatures.SchemeECDSA)
	if err != nil {
		return fmt.Errorf("network burn consent: sign: %w", err)
	}
	raw, err := json.MarshalIndent(consent, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		return fmt.Errorf("write consent %q: %w", *out, err)
	}
	return emitOutput(*output, "network-burn-consent", map[string]any{
		"out":            *out,
		"pub_key_id":     consent.PubKeyIDHex,
		"content_digest": consent.ContentDigestHex,
	}, func() error {
		tablef("burn-consent written: %s (pub_key_id %s)\n", *out, short(consent.PubKeyIDHex))
		return nil
	})
}

// ─── finalize ────────────────────────────────────────────────────────

func burnFinalizeCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network burn finalize", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network_   = fs.String("network", "", "stored network name (else the active network)")
		draftPath  = fs.String("draft", "", "the burn-draft — REQUIRED")
		out        = fs.String("out", "", "write the finalized on-log burn payload here — REQUIRED")
		output     = fs.String("output", "table", "output format: table|json")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	var consentPaths burnStrings
	fs.Var(&consentPaths, "consent", "a collected burn-consent file (repeatable) — REQUIRED")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *draftPath == "" || *out == "" || len(consentPaths) == 0 {
		return fmt.Errorf("network burn finalize: --draft, --consent (>=1) and --out are required")
	}
	d, err := readBurnDraft(*draftPath)
	if err != nil {
		return err
	}
	consents := make([]burnceremony.Consent, 0, len(consentPaths))
	for _, p := range consentPaths {
		c, cerr := readBurnConsent(p)
		if cerr != nil {
			return cerr
		}
		consents = append(consents, c)
	}
	b, err := resolveBundle(*bundlePath, *network_)
	if err != nil {
		return err
	}
	if b.QuorumK <= 0 {
		return fmt.Errorf("network burn finalize: the bundle carries no witness quorum (quorum_k) — re-add the network to refresh it from the verified constitution")
	}
	set, err := liveWitnessKeySet(ctx, b, *timeout)
	if err != nil {
		return err
	}
	// Finalize SELF-VERIFIES through network.VerifyBurn — an under-quorum,
	// rogue-signed, cross-proposal, or tampered burn is unconstructible here.
	payload, err := burnceremony.Finalize(d, consents, set)
	if err != nil {
		return fmt.Errorf("network burn finalize: refused to assemble: %w", err)
	}
	if err := os.WriteFile(*out, payload, 0o600); err != nil {
		return fmt.Errorf("write finalized burn %q: %w", *out, err)
	}
	return emitOutput(*output, "network-burn-finalize", map[string]any{
		"out":           *out,
		"payload_bytes": len(payload),
		"consents":      len(consents),
	}, func() error {
		tablef("finalized burn written: %s (%d bytes, %d consents, self-verified)\n", *out, len(payload), len(consents))
		tableln("next: `network burn submit` to the ceremony door")
		return nil
	})
}

// ─── submit ──────────────────────────────────────────────────────────

func burnSubmitCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network burn submit", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network_   = fs.String("network", "", "stored network name (else the active network)")
		in         = fs.String("in", "", "the finalized burn payload (from `finalize`) — REQUIRED")
		output     = fs.String("output", "table", "output format: table|json")
		dryRun     = fs.Bool("dry-run", false, "decode + LOCAL VerifyBurn against the live set, then stop BEFORE the POST")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("network burn submit: --in (the finalized payload) is required")
	}
	payload, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read finalized burn %q: %w", *in, err)
	}
	// Structural decode FIRST — a malformed/unsigned payload is refused here,
	// never posted (the SDK decoder runs Validate: no signatures ⇒ refusal).
	burn, err := network.DecodeNetworkBurnPayload(payload)
	if err != nil {
		return fmt.Errorf("network burn submit: refused locally — payload does not decode: %w", err)
	}
	b, err := resolveBundle(*bundlePath, *network_)
	if err != nil {
		return err
	}
	set, err := liveWitnessKeySet(ctx, b, *timeout)
	if err != nil {
		return err
	}
	// Local full re-verify against the LIVE set: a burn this driver cannot
	// verify is refused by NAME, never posted (the door would reject it).
	if verr := network.VerifyBurn(burn, set); verr != nil {
		return fmt.Errorf("network burn submit: refused locally — does not verify against the live witness set (the door would reject it): %w", verr)
	}
	if *dryRun {
		return emitOutput(*output, "network-burn-submit", map[string]any{
			"dry_run": true, "verified": true,
			"endpoint": b.Endpoint + "/v1/network/burn", "payload_bytes": len(payload),
		}, func() error {
			tableln("dry-run: burn verified locally against the live set; stopping before POST")
			return nil
		})
	}

	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.Endpoint+"/v1/network/burn", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("post burn: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("network burn submit: door refused (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return emitOutput(*output, "network-burn-submit", map[string]any{
		"endpoint": b.Endpoint + "/v1/network/burn", "status": "burned", "response": json.RawMessage(respBody),
	}, func() error {
		tablef("burn submitted: the network is burned (%s)\n", strings.TrimSpace(string(respBody)))
		return nil
	})
}

// ─── helpers ─────────────────────────────────────────────────────────

func readBurnDraft(path string) (burnceremony.Draft, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return burnceremony.Draft{}, fmt.Errorf("read draft %q: %w", path, err)
	}
	var d burnceremony.Draft
	if err := json.Unmarshal(raw, &d); err != nil {
		return burnceremony.Draft{}, fmt.Errorf("parse draft %q: %w", path, err)
	}
	return d, nil
}

func readBurnConsent(path string) (burnceremony.Consent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return burnceremony.Consent{}, fmt.Errorf("read consent %q: %w", path, err)
	}
	var c burnceremony.Consent
	if err := json.Unmarshal(raw, &c); err != nil {
		return burnceremony.Consent{}, fmt.Errorf("parse consent %q: %w", path, err)
	}
	return c, nil
}

// liveWitnessKeySet fetches the network's CURRENT witness set from the LIVE
// history (keys, never asserted) and builds the ECDSA WitnessKeySet the burn
// verifier needs. The v1 relay transport is ECDSA-only, matching the rotation
// driver's bound.
func liveWitnessKeySet(ctx context.Context, b *ClientBundle, timeout time.Duration) (*cosign.WitnessKeySet, error) {
	if b.NetworkID == "" {
		return nil, fmt.Errorf("the bundle carries no network id")
	}
	nid, err := hex.DecodeString(b.NetworkID)
	if err != nil || len(nid) != 32 {
		return nil, fmt.Errorf("bundle network id is not 64 hex chars")
	}
	hc, err := b.HTTPClient(timeout)
	if err != nil {
		return nil, err
	}
	var cur wireWitnessSetFull
	if err := getJSON(ctx, hc, b.Endpoint+"/v1/network/witnesses/current", &cur); err != nil {
		return nil, fmt.Errorf("fetch current witness set: %w", err)
	}
	keys, err := wireWitnessKeys(cur.Keys)
	if err != nil {
		return nil, fmt.Errorf("current witness set: %w", err)
	}
	var netID cosign.NetworkID
	copy(netID[:], nid)
	set, err := cosign.NewECDSAWitnessKeySet(keys, netID, b.QuorumK)
	if err != nil {
		return nil, fmt.Errorf("build witness key set (the v1 driver is ECDSA-only): %w", err)
	}
	return set, nil
}

// parseAnchorAt parses "<log-did>@<seq>" into its parts.
func parseAnchorAt(s string) (string, uint64, error) {
	logDID, seqStr, ok := strings.Cut(s, "@")
	if !ok || logDID == "" {
		return "", 0, fmt.Errorf("want <log-did>@<seq>, got %q", s)
	}
	seq, err := strconv.ParseUint(seqStr, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("sequence: %w", err)
	}
	return logDID, seq, nil
}
