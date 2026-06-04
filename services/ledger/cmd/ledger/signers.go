// Signer-key loading + DID derivation helpers.
//
// FILE PATH:
//
//	cmd/ledger/signers.go
//
// DESCRIPTION:
//
//	Three loaders, one DID-derivation helper. Each loader follows the
//	same shape: keyFile non-empty → load from disk; keyFile empty →
//	generate ephemeral + warn. Production deployments MUST use the
//	on-disk path so cryptographic identity is stable across restarts.
//
// CONTENTS:
//
//	loadOrGenerateTesseraSigner — checkpoint signer (Ed25519 via note.Signer).
//	loadOrGenerateLedgerSigner   — entry signer (secp256k1 ECDSA + did:key).
//	loadOrGenerateWitnessSigner  — witness cosign-server signer (ECDSA).
//	didKeyFromSecp256k1Priv      — composes did:key:z... from a private key.
//
// Extracted verbatim from cmd/ledger/main.go as part of the
// lifecycle-phase decomposition (P3). No behavioural change.
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/note"

	sdkcryptosigs "github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"

	"github.com/baseproof/tooling/services/ledger/tessera"
)

// loadOrGenerateTesseraSigner resolves the checkpoint signer.
//
// CRYPTO BOUNDARY — this signer is Ed25519 BY REQUIREMENT, and that is
// correct. It signs the Merkle TreeHead checkpoint in the C2SP /
// golang.org/x/mod/sumdb/note format, which admits exactly one key
// type: Ed25519 (algorithm id 1; see note.go "There is only one key
// type"). This is the Layer-4 INFRASTRUCTURE plane — the log vouching
// for its own tree head so witnesses will cosign it — and it is
// DISTINCT from the Layer-2 domain plane, where envelope.Entry
// identities are secp256k1-only (see admission/multisig_verifier.go).
// The checkpoint note is NOT in JN's trust chain: JN trusts the
// secp256k1 witness COSIGNATURES carried in the anchor, never this
// note, so its Ed25519 key does not weaken the secp256k1 identity
// guarantee. Do NOT "purge Ed25519" here — dropping this signer breaks
// standard transparency-log checkpoint emission and stalls the witness
// cosign handshake. secp256k1 notes are non-standard everywhere (the
// SDK ships none; transparency-dev tops out at P-256), so a swap would
// be a custom cross-impl format, not a cleanup.
//
// Priority:
//   - keyFile non-empty: load note.Signer from disk; fail if
//     unreadable. Production deployments MUST use this.
//   - keyFile empty: generate an ephemeral Ed25519 signer with a
//     loud warning log. Local-dev only — the verifier key is
//     printed once and lost on next restart.
//
// origin / logDID are used to derive the signer name when
// generating ephemerally (Tessera's signer name appears in every
// checkpoint and identifies the log).
func loadOrGenerateTesseraSigner(keyFile, origin, logDID string, logger *slog.Logger) (note.Signer, string, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read tessera signer key %q: %w", keyFile, err)
		}
		signer, err := note.NewSigner(string(data))
		if err != nil {
			return nil, "", fmt.Errorf("parse tessera signer key %q: %w", keyFile, err)
		}
		logger.Info("tessera signer loaded from file", "key_file", keyFile, "name", signer.Name())
		return signer, "", nil
	}
	// Ephemeral fallback for local dev.
	name := origin
	if name == "" {
		name = logDID
	}
	signer, vkey, err := tessera.GenerateEphemeralSigner(name)
	if err != nil {
		return nil, "", err
	}
	logger.Warn("tessera signer is ephemeral — NOT for production",
		"name", signer.Name(),
		"verifier_key", vkey,
	)
	return signer, vkey, nil
}

// loadOrGenerateLedgerSigner resolves the ledger's entry signing key.
// The ledger signs its own entries (anchor commentary, commitment
// commentary) before submitting them to admission, which then
// verifies the signature via did.NewECDSAKeyResolver (SDK). Returns
// the private key plus the computed did:key:z... identifier — that
// string becomes cfg.LedgerDID at the composition root.
//
// KEY FORMAT — raw secp256k1 scalar, hex-encoded. The ledger signs with
// secp256k1 (SDK-native) and derives a did:key:zQ3s… on the secp256k1
// curve. secp256k1 is NOT a stdlib x509 curve, so an x509/PEM
// "EC PRIVATE KEY" cannot represent it (x509.ParseECPrivateKey rejects the
// secp256k1 OID); worse, a P-256 PEM WOULD parse but then
// didKeyFromSecp256k1Priv derives a DID off the secp256k1 curve, fails
// closed at boot, and never produces a usable identity. So the on-disk
// form is a 32-byte big-endian scalar as hex — the same dialect
// cmd/init-network uses for the admission-authority secp256k1 key (and
// what `init-network -out-ledger-key` writes). A PEM file is rejected with
// an explicit message rather than mis-parsed.
//
// Priority:
//   - keyFile non-empty: hex-decode a 32-byte secp256k1 scalar via
//     signatures.PrivKeyFromBytes. Production deployments MUST use this so
//     the ledger's did:key is stable across restarts.
//   - keyFile empty: generate an ephemeral secp256k1 key and log a
//     warning. Local-dev only — entry consumers that pin the
//     ledger's DID will see a different DID on every restart.
func loadOrGenerateLedgerSigner(keyFile string, logger *slog.Logger) (*ecdsa.PrivateKey, string, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, "", fmt.Errorf("read ledger signer key %q: %w", keyFile, err)
		}
		s := strings.TrimSpace(string(data))
		if strings.Contains(s, "-----BEGIN") {
			return nil, "", fmt.Errorf("ledger signer key %q is PEM-encoded; this build expects a raw 32-byte secp256k1 scalar as hex (x509/PEM cannot represent secp256k1, and a P-256 PEM would derive a DID off the secp256k1 curve)", keyFile)
		}
		raw, err := hex.DecodeString(s)
		if err != nil {
			return nil, "", fmt.Errorf("ledger signer key %q: not valid hex: %w", keyFile, err)
		}
		priv, err := sdkcryptosigs.PrivKeyFromBytes(raw)
		if err != nil {
			return nil, "", fmt.Errorf("ledger signer key %q: %w", keyFile, err)
		}
		didKey, err := didKeyFromSecp256k1Priv(priv)
		if err != nil {
			return nil, "", fmt.Errorf("encode did:key from %q: %w", keyFile, err)
		}
		logger.Info("ledger signer loaded from file", "key_file", keyFile, "did", didKey)
		return priv, didKey, nil
	}
	// Ephemeral fallback for local dev.
	priv, err := sdkcryptosigs.GenerateKey()
	if err != nil {
		return nil, "", fmt.Errorf("generate ledger signer: %w", err)
	}
	didKey, err := didKeyFromSecp256k1Priv(priv)
	if err != nil {
		return nil, "", fmt.Errorf("encode did:key for ephemeral signer: %w", err)
	}
	logger.Warn("ledger signer is ephemeral — NOT for production",
		"did", didKey,
	)
	return priv, didKey, nil
}

// didKeyFromSecp256k1Priv composes a did:key:z... identifier from a
// secp256k1 private key. Same multibase + multicodec encoding the
// SDK's did.GenerateDIDKeySecp256k1 produces internally; this helper
// exists because the ledger threads in keys loaded from disk rather
// than generating them via the SDK constructor.
func didKeyFromSecp256k1Priv(priv *ecdsa.PrivateKey) (string, error) {
	uncompressed := sdkcryptosigs.PubKeyBytes(&priv.PublicKey)
	compressed, err := sdkcryptosigs.CompressSecp256k1Pubkey(uncompressed)
	if err != nil {
		return "", err
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}
