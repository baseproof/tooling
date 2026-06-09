package cli

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/baseproof/baseproof/builder"
	"github.com/baseproof/baseproof/core/envelope"
	"github.com/baseproof/baseproof/core/smt"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/types"

	"github.com/baseproof/tooling/libs/loadgen"
)

// RunSubmit submits ONE entry to the bundle's network — the canonical end-user
// action. A new root mints (or loads) a signer identity; an amendment (--amend
// <seq>) is a Path-A change signed by the original root's key (--key-file). It
// prints the assigned sequence + the entry's SMT key.
func RunSubmit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	var (
		bundlePath = fs.String("bundle", "", "client bundle JSON — REQUIRED")
		payload    = fs.String("payload", "", "entry payload (UTF-8) — REQUIRED")
		amend      = fs.Int64("amend", -1, "amend the root at this sequence (Path A); omit to create a new root")
		keyFile    = fs.String("key-file", "", "32-byte hex secp256k1 signer key; REQUIRED for --amend, optional for a new root")
		outKey     = fs.String("out-key", "", "write the generated signer key (hex) here (new root only)")
		token      = fs.String("token", "", "Mode A credit token; empty ⇒ Mode B PoW")
		difficulty = fs.Int("difficulty", 0, "Mode B PoW difficulty (0 ⇒ query the ledger)")
		timeout    = fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || *payload == "" {
		return fmt.Errorf("--bundle and --payload are required")
	}
	b, err := LoadClientBundle(*bundlePath)
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
	case *amend >= 0:
		return fmt.Errorf("--amend requires --key-file (an amendment must be signed by the root's original key)")
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
			fmt.Printf("submit: wrote signer key → %s (keep it to amend this root later)\n", *outKey)
		}
	}

	// Build the entry.
	var entry *envelope.Entry
	if *amend >= 0 {
		entry, err = builder.BuildAmendment(builder.AmendmentParams{
			Destination: logDID,
			SignerDID:   id.DID,
			TargetRoot:  types.LogPosition{LogDID: logDID, Sequence: uint64(*amend)},
			Payload:     []byte(*payload),
			EventTime:   time.Now().UTC().UnixMicro(),
		})
	} else {
		entry, err = builder.BuildRootEntity(builder.RootEntityParams{
			Destination: logDID,
			SignerDID:   id.DID,
			Payload:     []byte(*payload),
			EventTime:   time.Now().UTC().UnixMicro(),
		})
	}
	if err != nil {
		return fmt.Errorf("build entry: %w", err)
	}

	seq, err := loadgen.SubmitOne(ctx, loadgen.SubmitParams{
		LedgerURL:      b.Endpoint,
		LogDID:         logDID,
		Token:          *token,
		Difficulty:     uint32(*difficulty),
		EpochWindowSec: b.Admission.EpochWindowSec,
		HTTPClient:     hc,
	}, entry, id.Priv, id.DID)
	if err != nil {
		return err
	}

	kind := "root"
	if *amend >= 0 {
		kind = fmt.Sprintf("amendment-of-%d", *amend)
	}
	key := smt.DeriveKey(types.LogPosition{LogDID: logDID, Sequence: seq})
	fmt.Printf("submit: %s sequenced — seq=%d signer=%s smt_key=%s\n", kind, seq, id.DID, hex.EncodeToString(key[:]))
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
