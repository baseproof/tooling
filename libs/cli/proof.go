package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	nb, err := networkbundle.Build(doc, b.Endpoint, b.QuorumK, networkbundle.Vocabulary{
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

	nid := proof.NetworkID
	fmt.Printf("proof: v2  network=%s  seq=%d  tree_size=%d  quorum=%d-of-%d  (verified offline)\n",
		hex.EncodeToString(nid[:]), *seq, res.TreeSize, res.WitnessQuorum.Have, res.WitnessQuorum.Need)
	fmt.Printf("proof: verified: %v\n", res.Coverage.Verified)
	if len(res.Coverage.NotAsserted) > 0 {
		fmt.Printf("proof: not asserted (absent sections): %v\n", res.Coverage.NotAsserted)
	}
	if *out != "" {
		if err := writeProofFile(proof, *out); err != nil {
			return err
		}
		fmt.Printf("proof: wrote %s (portable — verify it anywhere with `baseproof verify %s`)\n", *out, *out)
	}
	return nil
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

// fetchBootstrap GETs the network's genesis bootstrap (JCS-canonical bytes) and,
// when expectHashHex is set, fails closed unless SHA-256(bytes) matches it — the
// Zero-Trust confirmation that the endpoint serves the network the bundle pins.
func fetchBootstrap(ctx context.Context, httpClient *http.Client, endpoint, expectHashHex string) (*network.BootstrapDocument, error) {
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
	if expectHashHex != "" {
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != strings.ToLower(expectHashHex) {
			return nil, fmt.Errorf("bootstrap hash mismatch: endpoint %s serves a different network than the bundle pins (fail-closed)", endpoint)
		}
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode bootstrap: %w", err)
	}
	return &doc, nil
}
