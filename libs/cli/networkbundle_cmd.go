/*
FILE PATH: libs/cli/networkbundle_cmd.go

DESCRIPTION:

	`baseproof network bundle <get|verify|publish>` — the platform verbs over
	the network bundle (the baseproof-network-manifest/v1 discovery document).

	get      fetches GET /v1/network/bundle?destination=… from the resolved
	         network and runs it through the VERIFY DOOR before showing
	         anything: the bytes must be canonical, name the network the
	         bundle store pins, and anchor every driveable operation. The
	         serve headers (published / position / enforced-match) ride along.
	         Discovery is never authority — an unverifiable document is
	         refused, not displayed.

	verify   runs the same door over a local manifest FILE against the
	         resolved network's hash-verified constitution.

	publish  the on-log publication producer (PRE-2's producer line),
	         generalized VERBATIM from the judicial network's proven
	         two-step — composition stays with each network's composer; this
	         verb signs and sequences what a composer emitted:

	           1. --publish-anchor              → the anchor schema entry;
	              waits for its sequence and prints the exact --anchor value.
	           2. --manifest m.json --anchor L@S → verify the file through
	              the door, then publish it as an entry whose SchemaRef cites
	              the anchor. The LATEST citing entry is the current manifest
	              (GET /v1/query/schema_ref/{pos}).

	         Publication is fail-closed: a manifest that does not pass the
	         door against the target network's constitution is never signed.
*/
package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/baseproof/baseproof/builder"
	sdkenv "github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/crypto/signatures"
	sdktypes "github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/loadgen"
	"github.com/baseproof/tooling/libs/networkbundle"
)

// runNetworkBundle dispatches `baseproof network bundle <get|verify|publish>`.
func runNetworkBundle(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: baseproof network bundle <get|verify|publish> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "get":
		return networkBundleGet(ctx, rest)
	case "verify":
		return networkBundleVerify(ctx, rest)
	case "publish":
		return networkBundlePublish(ctx, rest)
	default:
		return fmt.Errorf("network bundle: unknown subcommand %q (get|verify|publish)", sub)
	}
}

// NetworkBundleGetData is the --output json data shape (kind "network-bundle").
type NetworkBundleGetData struct {
	Verified      bool                    `json:"verified"`
	Destination   string                  `json:"destination"`
	ContentHash   string                  `json:"content_hash"`
	Published     string                  `json:"published,omitempty"`      // X-Manifest-Published
	Position      string                  `json:"position,omitempty"`       // X-Manifest-Position
	EnforcedMatch string                  `json:"enforced_match,omitempty"` // X-Manifest-Enforced-Match
	Manifest      *networkbundle.Manifest `json:"manifest"`
}

func networkBundleGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network bundle get", flag.ContinueOnError)
	var (
		bundlePath  = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network     = fs.String("network", "", "stored network name (else the active network)")
		destination = fs.String("destination", "", "exchange/destination DID (default: the single destination the endpoint serves)")
		out         = fs.String("out", "", "also write the verified canonical bytes to this file")
		output      = fs.String("output", "table", "output format: table|json")
		timeout     = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
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

	dest := *destination
	if dest == "" {
		if dest, err = soleServedDestination(ctx, hc, b.Endpoint); err != nil {
			return err
		}
	}

	raw, hdr, err := fetchManifestBytes(ctx, hc, b.Endpoint, dest)
	if err != nil {
		return err
	}
	m, err := verifyAgainstNetwork(ctx, hc, b, raw)
	if err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	if *out != "" {
		if werr := os.WriteFile(*out, raw, 0o600); werr != nil {
			return fmt.Errorf("write %s: %w", *out, werr)
		}
		fmt.Fprintf(os.Stderr, "network bundle: wrote verified canonical bytes → %s\n", *out)
	}
	data := NetworkBundleGetData{
		Verified:      true,
		Destination:   dest,
		ContentHash:   hex.EncodeToString(h[:]),
		Published:     hdr.Get("X-Manifest-Published"),
		Position:      hdr.Get("X-Manifest-Position"),
		EnforcedMatch: hdr.Get("X-Manifest-Enforced-Match"),
		Manifest:      m,
	}
	return emitOutput(*output, "network-bundle", data, func() error {
		renderBundleSummary(data)
		return nil
	})
}

// NetworkBundleVerifyData is the --output json data shape
// (kind "network-bundle-verify").
type NetworkBundleVerifyData struct {
	Verified    bool   `json:"verified"`
	File        string `json:"file"`
	NetworkID   string `json:"network_id"`
	Exchange    string `json:"exchange"`
	ContentHash string `json:"content_hash"`
	Operations  int    `json:"operations"`
}

func networkBundleVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network bundle verify", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		output     = fs.String("output", "table", "output format: table|json")
		timeout    = fs.Duration("timeout", 15*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: baseproof network bundle verify <manifest.json> [--network <name>]")
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", fs.Arg(0), err)
	}
	m, err := verifyAgainstNetwork(ctx, hc, b, raw)
	if err != nil {
		return err
	}
	h := sha256.Sum256(raw)
	data := NetworkBundleVerifyData{
		Verified: true, File: fs.Arg(0),
		NetworkID: m.Network.NetworkID, Exchange: m.Exchange,
		ContentHash: hex.EncodeToString(h[:]), Operations: len(m.Operations),
	}
	return emitOutput(*output, "network-bundle-verify", data, func() error {
		fmt.Printf("network bundle: ✔ VERIFIED %s\n", fs.Arg(0))
		fmt.Printf("  network=%s exchange=%s operations=%d content_hash=%s\n",
			short(data.NetworkID), data.Exchange, data.Operations, short(data.ContentHash))
		return nil
	})
}

// NetworkBundlePublishData is the --output json data shape
// (kind "network-bundle-publish").
type NetworkBundlePublishData struct {
	Step          string `json:"step"` // "anchor" | "manifest"
	CanonicalHash string `json:"canonical_hash"`
	Sequence      uint64 `json:"sequence"`
	Anchor        string `json:"anchor,omitempty"`       // step 1: the value to pass as --anchor
	ContentHash   string `json:"content_hash,omitempty"` // step 2: the published manifest's hash
	Exchange      string `json:"exchange,omitempty"`
}

func networkBundlePublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("network bundle publish", flag.ContinueOnError)
	var (
		bundlePath    = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network       = fs.String("network", "", "stored network name (else the active network)")
		manifestPath  = fs.String("manifest", "", "composed manifest JSON to publish (step 2; from your network's composer)")
		anchor        = fs.String("anchor", "", "manifest anchor position <log-did>@<seq> (step 2; from step 1's output)")
		publishAnchor = fs.Bool("publish-anchor", false, "publish the manifest ANCHOR schema entry (step 1 of 2) and wait for its sequence")
		destination   = fs.String("destination", "", "destination DID for the anchor entry (step 1; default: the bundle's log DID)")
		keyFile       = fs.String("signer-key", "", "32-byte hex secp256k1 signer key (REQUIRED; the publication signer)")
		token         = fs.String("token", "", "Mode A credit token; empty ⇒ Mode B/unauthenticated per the network's posture")
		output        = fs.String("output", "table", "output format: table|json")
		timeout       = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return fmt.Errorf("network bundle publish: --signer-key is required")
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}
	rawKey, err := readHexKey(*keyFile)
	if err != nil {
		return err
	}
	id, err := loadgen.IdentityFromScalar(rawKey)
	if err != nil {
		return err
	}

	// ── Step 1: the anchor schema entry (the position every manifest cites). ──
	if *publishAnchor {
		dest := *destination
		if dest == "" {
			dest = b.LogDID
		}
		if dest == "" {
			return fmt.Errorf("network bundle publish: --destination required (the bundle carries no log DID)")
		}
		entry, bErr := builder.BuildSchemaEntry(builder.SchemaEntryParams{
			Destination: dest,
			SignerDID:   id.DID,
			Parameters:  sdktypes.SchemaParameters{},
			EventTime:   time.Now().UTC().UnixMicro(),
		})
		if bErr != nil {
			return fmt.Errorf("build anchor schema entry: %w", bErr)
		}
		hash, seq, sErr := signSubmitWait(ctx, hc, b.Endpoint, *token, entry.Header, entry.DomainPayload, id, *timeout)
		if sErr != nil {
			return sErr
		}
		data := NetworkBundlePublishData{
			Step: "anchor", CanonicalHash: hash, Sequence: seq,
			Anchor: fmt.Sprintf("%s@%d", dest, seq),
		}
		return emitOutput(*output, "network-bundle-publish", data, func() error {
			fmt.Printf("anchor published: %s  (canonical_hash=%s)\n", data.Anchor, short(hash))
			fmt.Printf("next: baseproof network bundle publish --manifest <m.json> --anchor %s --signer-key %s\n", data.Anchor, *keyFile)
			return nil
		})
	}

	// ── Step 2: verify the composed manifest through the door, then publish. ──
	if *manifestPath == "" || *anchor == "" {
		return fmt.Errorf("network bundle publish: --manifest and --anchor are required (or --publish-anchor for step 1)")
	}
	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", *manifestPath, err)
	}
	m, err := verifyAgainstNetwork(ctx, hc, b, raw)
	if err != nil {
		return fmt.Errorf("refusing to publish: %w", err)
	}
	anchorPos, err := parseLogPos(*anchor, m.Exchange)
	if err != nil {
		return err
	}

	auth := sdkenv.AuthoritySameSigner
	header := sdkenv.ControlHeader{
		SignerDID:     id.DID,
		Destination:   m.Exchange,
		AuthorityPath: &auth,
		EventTime:     time.Now().UTC().UnixMicro(),
		SchemaRef:     &anchorPos,
	}
	hash, seq, err := signSubmitWait(ctx, hc, b.Endpoint, *token, header, raw, id, *timeout)
	if err != nil {
		return err
	}
	ch := sha256.Sum256(raw)
	data := NetworkBundlePublishData{
		Step: "manifest", CanonicalHash: hash, Sequence: seq,
		ContentHash: hex.EncodeToString(ch[:]), Exchange: m.Exchange,
	}
	return emitOutput(*output, "network-bundle-publish", data, func() error {
		fmt.Printf("manifest published: exchange=%s operations=%d content_hash=%s\n",
			m.Exchange, len(m.Operations), short(data.ContentHash))
		fmt.Printf("  sequenced at %d (canonical_hash=%s, anchor %s@%d)\n", seq, short(hash), anchorPos.LogDID, anchorPos.Sequence)
		fmt.Printf("  resolve: GET %s/v1/query/schema_ref/%s@%d — the LATEST citing entry is current\n",
			b.Endpoint, anchorPos.LogDID, anchorPos.Sequence)
		return nil
	})
}

// ── shared mechanics ─────────────────────────────────────────────────

// verifyAgainstNetwork runs the networkbundle verify door against the resolved
// network's hash-verified constitution: discovery is never authority.
func verifyAgainstNetwork(ctx context.Context, hc *http.Client, b *ClientBundle, raw []byte) (*networkbundle.Manifest, error) {
	doc, err := fetchBootstrap(ctx, hc, b.Endpoint, b.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("fetch the constitution to verify against: %w", err)
	}
	return networkbundle.VerifyManifest(raw, doc)
}

// soleServedDestination resolves the endpoint's single served destination from
// the discovery envelope; ambiguity requires an explicit --destination.
func soleServedDestination(ctx context.Context, hc *http.Client, endpoint string) (string, error) {
	var env struct {
		Exchanges []string `json:"exchanges"`
	}
	if err := getJSON(ctx, hc, endpoint+"/v1/network/bundle", &env); err != nil {
		return "", fmt.Errorf("fetch bundle envelope: %w", err)
	}
	if len(env.Exchanges) != 1 {
		return "", fmt.Errorf("endpoint serves %d destinations %v — pass --destination", len(env.Exchanges), env.Exchanges)
	}
	return env.Exchanges[0], nil
}

// fetchManifestBytes GETs the manifest for one destination, returning the raw
// body (the bytes the door verifies) and the serve headers.
func fetchManifestBytes(ctx context.Context, hc *http.Client, endpoint, dest string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/network/bundle?destination="+dest, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200] + "…"
		}
		return nil, nil, fmt.Errorf("fetch bundle: HTTP %d: %s", resp.StatusCode, msg)
	}
	return body, resp.Header, nil
}

// signSubmitWait signs header+payload with the identity, validates, submits
// through the shared transport (J7), and waits for the LEDGER to sequence it.
func signSubmitWait(ctx context.Context, hc *http.Client, endpoint, token string, header sdkenv.ControlHeader, payload []byte, id loadgen.Identity, timeout time.Duration) (string, uint64, error) {
	u, err := sdkenv.NewUnsignedEntry(header, payload)
	if err != nil {
		return "", 0, fmt.Errorf("new unsigned entry: %w", err)
	}
	digest := sha256.Sum256(sdkenv.SigningPayload(u))
	sig, err := signatures.SignEntry(digest, id.Priv)
	if err != nil {
		return "", 0, fmt.Errorf("sign: %w", err)
	}
	u.Signatures = []sdkenv.Signature{{SignerDID: id.DID, AlgoID: sdkenv.SigAlgoECDSA, Bytes: sig}}
	if vErr := u.Validate(); vErr != nil {
		return "", 0, fmt.Errorf("entry.Validate: %w", vErr)
	}
	wire, err := sdkenv.Serialize(u)
	if err != nil {
		return "", 0, fmt.Errorf("serialize: %w", err)
	}
	hash, err := SubmitWire(ctx, hc, endpoint, token, wire)
	if err != nil {
		return "", 0, err
	}
	seq, err := WaitForSequence(ctx, hc, endpoint, hash, timeout)
	if err != nil {
		return "", 0, fmt.Errorf("submitted (canonical_hash=%s) but not sequenced: %w", hash, err)
	}
	return hash, seq, nil
}

func renderBundleSummary(d NetworkBundleGetData) {
	fmt.Printf("network bundle: ✔ VERIFIED destination=%s\n", d.Destination)
	fmt.Printf("  content_hash=%s published=%s", short(d.ContentHash), orDash(d.Published))
	if d.Position != "" {
		fmt.Printf(" position=%s", d.Position)
	}
	if d.EnforcedMatch != "" {
		fmt.Printf(" enforced_match=%s", d.EnforcedMatch)
	}
	fmt.Println()
	m := d.Manifest
	fmt.Printf("  network=%s name=%q quorum_k=%d log=%s\n",
		short(m.Network.NetworkID), m.Network.Name, m.Network.QuorumK, m.Network.LogDID)
	fmt.Printf("  endpoints=%d operations=%d roles=%d datatypes=%d federation=%d\n",
		len(m.Endpoints), len(m.Operations), len(m.Roles), len(m.Datatypes), len(m.Federation))
	if m.Submit.Path != "" {
		fmt.Printf("  submit: %s %s  admission: gating=%s payment=%v\n",
			orDash(m.Submit.Endpoint), m.Submit.Path, orDash(m.Admission.Gating), m.Admission.Payment)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
