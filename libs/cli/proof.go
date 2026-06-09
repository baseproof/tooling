package cli

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"github.com/baseproof/baseproof/core/smt"
	"github.com/baseproof/baseproof/crypto/cosign"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/bundle"
)

// RunProof fetches the entry's proof bundle from the network, verifies it
// (witness quorum + RFC-6962 inclusion + SMT membership, all via the SDK
// verifier), renders it, and reports the verdict. The SMT key defaults to the one
// derived from (log DID, seq), so the usual case is just `--seq N`.
func RunProof(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON — REQUIRED")
		seq        = fs.Uint64("seq", 0, "entry sequence to prove — REQUIRED")
		smtKeyHex  = fs.String("smt-key", "", "64-hex SMT key (default: derived from log DID + seq)")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return fmt.Errorf("--bundle is required")
	}
	b, err := LoadClientBundle(*bundlePath)
	if err != nil {
		return err
	}
	networkID, err := b.NetworkID32()
	if err != nil {
		return err
	}
	if b.QuorumK <= 0 {
		return fmt.Errorf("client bundle quorum_k must be > 0 to verify a proof")
	}

	// Resolve the SMT key: explicit --smt-key, else derive from (log DID, seq).
	var smtKey [32]byte
	if *smtKeyHex != "" {
		raw, derr := hex.DecodeString(*smtKeyHex)
		if derr != nil || len(raw) != 32 {
			return fmt.Errorf("--smt-key must be 64 hex chars (32 bytes)")
		}
		copy(smtKey[:], raw)
	} else {
		if b.LogDID == "" {
			return fmt.Errorf("client bundle has no log_did; pass --smt-key explicitly")
		}
		smtKey = smt.DeriveKey(types.LogPosition{LogDID: b.LogDID, Sequence: *seq})
	}

	hc, err := b.HTTPClient(*timeout)
	if err != nil {
		return err
	}

	bundleObj, err := bundle.FetchBundle(ctx, hc, b.Endpoint, *seq, smtKey)
	if err != nil {
		return fmt.Errorf("fetch bundle (seq=%d): %w", *seq, err)
	}
	resolver, err := bundle.NewHTTPWitnessSetResolver(b.Endpoint, hc, cosign.NetworkID(networkID), b.QuorumK)
	if err != nil {
		return fmt.Errorf("witness-set resolver: %w", err)
	}

	verdict := bundle.VerifyBundleWithResolver(ctx, bundleObj, resolver, networkID)
	fmt.Print(bundle.Render(bundleObj))
	fmt.Printf("proof: verdict=%s\n", verdict.Outcome)
	if verdict.Err != nil {
		fmt.Printf("proof: detail=%v\n", verdict.Err)
	}
	if verdict.Outcome != bundle.OutcomeVerified {
		return fmt.Errorf("bundle did not verify (verdict=%s)", verdict.Outcome)
	}
	return nil
}
