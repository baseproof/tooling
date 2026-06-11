package cli

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	sdklog "github.com/baseproof/baseproof/log"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/types"

	libsbundle "github.com/baseproof/tooling/libs/bundle"
	"github.com/baseproof/tooling/libs/clitools"
	"github.com/baseproof/tooling/libs/networkbundle"
)

// RunProof generates a v2 self-anchored proof of an entry over the live ledger,
// SELF-VERIFIES it offline before doing anything with it (a proof we cannot
// verify is never emitted — fail-closed), and either writes it to --out (a
// portable file anyone can `baseproof verify`) or renders the verdict.
func RunProof(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON (else --network or the active network)")
		network    = fs.String("network", "", "stored network name (else the active network)")
		seq        = fs.Uint64("seq", 0, "entry sequence to prove — REQUIRED")
		smtKeyHex  = fs.String("smt-key", "", "64-hex SMT key (default: derived from log DID + seq)")
		out        = fs.String("out", "", "write the portable v2 proof to this file (else verify + render)")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	b, err := resolveBundle(*bundlePath, *network)
	if err != nil {
		return err
	}
	logDID, err := b.RequireLogDID()
	if err != nil {
		return err
	}

	// SMT key: explicit --smt-key, else derived from (log DID, seq).
	var smtKey [32]byte
	if *smtKeyHex != "" {
		raw, derr := hex.DecodeString(*smtKeyHex)
		if derr != nil || len(raw) != 32 {
			return fmt.Errorf("--smt-key must be 64 hex chars (32 bytes)")
		}
		copy(smtKey[:], raw)
	} else {
		smtKey = smt.DeriveKey(types.LogPosition{LogDID: logDID, Sequence: *seq})
	}

	httpClient, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}
	ledger, err := ledgerReaderFor(b, logDID)
	if err != nil {
		return err
	}
	doc, err := fetchBootstrap(ctx, httpClient, b.Endpoint, b.BootstrapHash)
	if err != nil {
		return err
	}
	nb, err := networkbundle.Build(doc, b.Endpoint, networkbundle.Vocabulary{
		GovernanceSchemas: governanceSchemas(b, logDID),
		CitedMemberKey:    smtKey,
	})
	if err != nil {
		return err
	}
	gather, err := libsbundle.NewBundleGather(ctx, nb, ledger, httpClient, *seq, smtKey)
	if err != nil {
		return fmt.Errorf("build gather: %w", err)
	}

	proof, err := generateProof(ctx, gather, *seq)
	if err != nil {
		return err
	}

	// SELF-VERIFY offline before emitting — never hand out an unverifiable proof.
	trustRoots, err := trustRootFromProof(proof)
	if err != nil {
		return err
	}
	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil || res == nil || !res.Valid {
		return fmt.Errorf("generated proof did not self-verify (fail-closed): %w", err)
	}

	renderProof(os.Stdout, proof, res, *seq)
	if *out != "" {
		if err := writeProofFile(proof, *out); err != nil {
			return err
		}
		fmt.Printf("\nproof: wrote %s (portable — verify it anywhere with `baseproof verify %s`)\n", *out, *out)
	}
	return nil
}

// renderProof writes a full, structured view of a generated v2 proof + its
// offline self-verification result: the trust facts (network/seq/tree size/quorum)
// and EVERY proof section with its verdict — ✔ verified, or ∅ not-asserted (a
// section this network legitimately does not carry). The fuller counterpart to the
// one-line summary, so an operator sees exactly what the portable artifact proves.
func renderProof(w io.Writer, proof *sdkbundle.StandaloneProof, res *sdkbundle.StandaloneResult, seq uint64) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	nid := proof.NetworkID
	fmt.Fprintf(tw, "proof\t%s standalone — verifiable offline (no ledger needed)\n", proof.Format)
	fmt.Fprintf(tw, "network\t%s\n", hex.EncodeToString(nid[:]))
	fmt.Fprintf(tw, "sequence\t%d\n", seq)
	fmt.Fprintf(tw, "tree_size\t%d\n", res.TreeSize)
	fmt.Fprintf(tw, "quorum\t%d-of-%d witnesses\n", res.WitnessQuorum.Have, res.WitnessQuorum.Need)
	_ = tw.Flush()
	fmt.Fprintln(w, "sections:")
	for _, s := range res.Coverage.Verified {
		fmt.Fprintf(w, "  ✔ %s\n", s)
	}
	for _, s := range res.Coverage.NotAsserted {
		fmt.Fprintf(w, "  ∅ %s (not asserted by this network)\n", s)
	}
}

// generateProof builds a v2 standalone proof from a gather. Pure orchestration —
// the testable core (a fake gather drives it without a live ledger).
func generateProof(ctx context.Context, gather sdkbundle.StandaloneGather, seq uint64) (*sdkbundle.StandaloneProof, error) {
	proof, err := sdkbundle.BuildStandalone(ctx, gather, seq)
	if err != nil {
		return nil, fmt.Errorf("build standalone proof (seq=%d): %w", seq, err)
	}
	return proof, nil
}

// writeProofFile encodes a proof as JCS-canonical bytes and writes it to a file.
func writeProofFile(proof *sdkbundle.StandaloneProof, path string) error {
	raw, err := sdkbundle.EncodeStandalone(proof)
	if err != nil {
		return fmt.Errorf("encode proof: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write proof %q: %w", path, err)
	}
	return nil
}

// ledgerReaderFor builds the LedgerReader the gather drives, from the bundle's
// transport posture: a client cert+key ⇒ mTLS; else a pinned CA ⇒ open-HTTPS
// server-verify; else plaintext.
func ledgerReaderFor(b *ClientBundle, logDID string) (*clitools.LedgerClient, error) {
	t := b.Transport
	var dids []string
	if logDID != "" {
		dids = []string{logDID}
	}
	switch {
	case t.ClientCertFile != "" && t.ClientKeyFile != "":
		tlsCfg := sdklog.ClientTLSConfig{
			ClientCertFile: t.ClientCertFile, ClientKeyFile: t.ClientKeyFile,
			RootCAFile: t.CAFile, ServerName: hostOf(b.Endpoint),
		}
		return clitools.NewMTLSLedgerClient(b.Endpoint, tlsCfg, dids...)
	case t.CAFile != "":
		return clitools.NewServerVerifyLedgerClient(b.Endpoint, t.CAFile, hostOf(b.Endpoint), dids...)
	default:
		return clitools.NewLedgerClient(b.Endpoint, dids...)
	}
}

// hostOf returns an endpoint URL's host (for the TLS ServerName / SNI).
func hostOf(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		return u.Hostname()
	}
	return ""
}

// governanceSchemas projects the bundle's per-network schema positions (sequence
// on the network's own log) into the SDK's vocabulary shape.
func governanceSchemas(b *ClientBundle, logDID string) map[string]types.LogPosition {
	if len(b.Schemas) == 0 {
		return nil
	}
	out := make(map[string]types.LogPosition, len(b.Schemas))
	for name, seq := range b.Schemas {
		out[name] = types.LogPosition{LogDID: logDID, Sequence: seq}
	}
	return out
}

// fetchBootstrap GETs the network's genesis bootstrap and admits it through the
// SDK's ONE first-contact door, network.LoadVerifiedBootstrap: strict decode,
// NetworkID recomputed over the CANONICAL SUBSET (so the served form may be the
// endorsed one — endorsements live outside the canonical bytes), pin equality,
// and the genesis ceremony verified whenever the constitution's policy requires
// it. A require-network constitution stripped of its endorsements is refused
// HERE, at the client, regardless of what the server chose to serve.
//
// The pin is REQUIRED. The pre-#75 behaviour skipped verification when the
// bundle carried no bootstrap pin — a lenient first contact that trusted
// whatever the endpoint served. A pinless bundle now refuses first contact
// (fail closed; re-author it with `baseproof network add`, which always pins).
func fetchBootstrap(ctx context.Context, httpClient *http.Client, endpoint, expectHashHex string) (*network.BootstrapDocument, error) {
	if expectHashHex == "" {
		return nil, fmt.Errorf("bundle carries no bootstrap pin — refusing unverified first contact with %s (re-author the bundle: `baseproof network add` always pins)", endpoint)
	}
	pinBytes, err := hex.DecodeString(strings.ToLower(expectHashHex))
	if err != nil || len(pinBytes) != 32 {
		return nil, fmt.Errorf("bundle bootstrap pin %q is not a 32-byte hex digest", expectHashHex)
	}
	var pin [32]byte
	copy(pin[:], pinBytes)

	u := strings.TrimRight(endpoint, "/") + "/v1/network/bootstrap"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bootstrap HTTP %d from %s", resp.StatusCode, u)
	}
	doc, err := network.LoadVerifiedBootstrap(raw, pin)
	if err != nil {
		return nil, fmt.Errorf("bootstrap from %s failed first-contact verification: %w", endpoint, err)
	}
	return doc, nil
}
