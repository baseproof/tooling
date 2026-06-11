/*
FILE PATH: cmd/genesis-ceremony/main.go

The network constitution producer — SUPERSEDES cmd/init-network.

A network is born by a ceremony, and the ceremony's trust shape depends on who
holds the keys. This tool has three modes, one per custody model:

	genesis-ceremony build     — production phase 1 (assemble, don't mint):
	                             the coordinator holds NO witness keys. Witness
	                             (and optional genesis-auditor) identities come
	                             in as flags; out comes the UNENDORSED
	                             constitution + the derived NetworkID.
	genesis-ceremony assemble  — production phase 3: collect each witness's
	                             independently-produced endorsement (the
	                             services/witness/cmd/genesis-endorse output),
	                             attach, emit the SERVED form, and round-trip it
	                             through the SAME first-contact gate every
	                             consumer runs. A partial ceremony cannot emit.
	genesis-ceremony dev       — DEV-ONLY single-host fixture mode (the old
	                             init-network behavior, flag-compatible): mints
	                             every key it names and self-endorses N-of-N.
	                             One process holding a network's entire witness
	                             set is a fixture, never a production network.

Phase 2 — each witness endorsing on its own host with its own key — is
genesis-endorse (services/witness/cmd/genesis-endorse); endorsements travel as
files, so the coordinator and the witnesses share no transport and no trust.

The single-host ceremony is deliberately NOT reachable from build/assemble:
production paths cannot drift into key custody by flag accident — the modes are
different code, not different switches.
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "build":
		runBuild(os.Args[2:])
	case "assemble":
		runAssemble(os.Args[2:])
	case "dev":
		runDev(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "genesis-ceremony: unknown mode %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `genesis-ceremony — the network constitution producer (supersedes init-network)

Modes (one per key-custody model):

  build      Assemble the UNENDORSED constitution from externally-held witness
             DIDs (+ optional genesis auditors). The coordinator mints no keys.
  assemble   Attach the witnesses' independently-produced endorsements
             (genesis-endorse output) and emit the verified SERVED constitution.
  dev        DEV-ONLY: single-host fixture mode — mints every key and
             self-endorses (the old init-network behavior).

Production ceremony:
  1. genesis-ceremony build -network-name N -witness-dids did:key:a,did:key:b,… \
       -admission-authority 0x… -out unendorsed.json
  2. on each witness host:
       genesis-endorse -bootstrap unendorsed.json -key witness.pem -out endorsement-<i>.json
  3. genesis-ceremony assemble -unendorsed unendorsed.json \
       -endorsements endorsement-1.json,endorsement-2.json,… -out bootstrap.json

Run "genesis-ceremony <mode> -h" for per-mode flags.
`)
}

// ─────────────────────────────────────────────────────────────────────────────
// Constitution construction (shared by all three modes)
// ─────────────────────────────────────────────────────────────────────────────

// buildBootstrapDoc assembles the genesis BootstrapDocument from the resolved
// inputs. auditors + auditorPolicy are the genesis-auditor declaration (nil/""
// ⇒ no genesis auditors, the pre-existing shape): the founding auditor set is
// canonical-bytes material exactly like the witness set, and
// auditorPolicy="require" demands a valid endorsement from EVERY genesis
// auditor at first contact (network.VerifyGenesisAuditorEndorsements).
func buildBootstrapDoc(logDID, networkName, gating, endorsementPolicy string, genesisDIDs []string, quorumK int, genesisAuthorityAddr string, minSignatures uint8, auditors []network.GenesisAuditor, auditorPolicy string) network.BootstrapDocument {
	// GenesisEndorsementPolicy is canonical-bytes material: "require" is hashed
	// into the NetworkID, so it cannot be stripped post-mint without minting a
	// DIFFERENT network — the fail-closed half of issue #77. "off" emits no
	// policy key (the legacy/pre-ceremony doc shape). The endorsements
	// themselves are attached AFTER ID derivation: they sign the identity, so
	// they live outside the canonical bytes by definition.
	genesisEndorsementPolicy := ""
	if endorsementPolicy != "off" {
		genesisEndorsementPolicy = network.GenesisEndorsementRequire
	}
	genesisAuditorPolicy := ""
	if auditorPolicy != "" && auditorPolicy != "off" {
		genesisAuditorPolicy = network.GenesisEndorsementRequire
	}
	return network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       logDID,
		NetworkName:       networkName,
		GenesisWitnessSet: genesisDIDs,
		// GenesisQuorumK is REQUIRED since baseproof SDK rc4 and is hashed into
		// the NetworkID: the constitution is the single source of truth for the
		// K-of-N quorum, so every consumer (ledger, auditor, CLI) derives K from
		// the verified doc rather than from an off-log config knob. validate()
		// enforces 1<=K<=N and the quorum-intersection invariant 2K>N.
		GenesisQuorumK: quorumK,
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: "0000000000000000000000000000000000000000000000000000000000000000",
			TreeSize: 0,
		},
		// v1.20.0: genesis admission. The genesis admission-authority secp256k1
		// EOA (the write-path root of trust) is bound into the doc and the
		// gating policy set. gating=require (default) is production
		// default-require; gating=off opens writes for dev/test load harnesses.
		GenesisAdmissionAuthorities: []string{genesisAuthorityAddr},
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: gating != "off",
			CostMode:       "uncharged",
		},
		// GenesisSignaturePolicy is REQUIRED since baseproof SDK v1.31 (it is
		// hashed into the NetworkID, and validate() rejects the empty zero value
		// as an "admit-nothing" policy that would brick writes). Emit the
		// zero-trust default — secp256k1-ECDSA entry signatures, ECDSA
		// cosignatures — matching gen-fixtures so a network bootstrapped by
		// either tool admits the same set. MinSignaturesPerEntry is the
		// operator-set floor (-min-signatures, default 1); the SDK's
		// validateGenesisSignaturePolicy re-asserts the [1, 64] range inside
		// doc.IDs(), so a 0 floor can never be locked into the NetworkID.
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001}, // SigAlgoECDSA (secp256k1)
			AllowedCosignSchemeTags: []uint8{0x01},    // SchemeECDSA
			MinSignaturesPerEntry:   minSignatures,
		},
		GenesisEndorsementPolicy: genesisEndorsementPolicy,
		// Genesis auditors: the declared founding auditor set + its endorsement
		// policy. Both are canonical-bytes material; a "require" with no
		// genesis_auditors is rejected by the SDK as unsatisfiable.
		GenesisAuditors:                 auditors,
		GenesisAuditorEndorsementPolicy: genesisAuditorPolicy,
	}
}

// resolveGenesisQuorumK turns the -quorum flag into the constitutional
// GenesisQuorumK, fail-closed at mint: 0 ⇒ auto majority (N/2+1, the smallest K
// satisfying 2K>N); an explicit K must satisfy 1<=K<=N AND 2K>N, the
// quorum-intersection invariant (two disjoint K-quorums would make a fork
// unprovable as equivocation), which the SDK's validate() re-asserts.
func resolveGenesisQuorumK(flagK, witnessCount int) (int, error) {
	if flagK == 0 {
		return witnessCount/2 + 1, nil
	}
	if flagK < 1 || flagK > witnessCount {
		return 0, fmt.Errorf("-quorum %d out of range [1, %d]", flagK, witnessCount)
	}
	if 2*flagK <= witnessCount {
		return 0, fmt.Errorf("-quorum %d dilutes the quorum-intersection invariant (need 2K>N, N=%d): "+
			"two disjoint K-quorums could finalise conflicting heads without provable equivocation", flagK, witnessCount)
	}
	return flagK, nil
}

// emitVerified finalizes a constitution for serving, fail-closed: the SERVED
// form (network.EndorsedBootstrapBytes — endorsements INSIDE the JSON, OUTSIDE
// the canonical bytes), re-indented for human audit, then round-tripped through
// network.LoadVerifiedBootstrap pinned to the NetworkID the doc STRUCT derives.
// That pin is a real cross-representation check (struct → emitted bytes), so a
// mint that cannot pass first contact never leaves the tool.
func emitVerified(doc network.BootstrapDocument) ([]byte, error) {
	ids, err := doc.IDs()
	if err != nil {
		return nil, fmt.Errorf("validate doc: %w", err)
	}
	served, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		return nil, fmt.Errorf("serving-form emit: %w", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, served, "", "  "); err != nil {
		return nil, fmt.Errorf("indent serving form: %w", err)
	}
	pretty.WriteByte('\n')
	body := pretty.Bytes()
	if _, err := network.LoadVerifiedBootstrap(body, [32]byte(ids.NetworkID)); err != nil {
		return nil, fmt.Errorf("first-contact round-trip (refusing to write a mint that fails it): %w", err)
	}
	return body, nil
}

// mintServedBootstrap is the DEV-mode sealer: it runs the N-of-N
// self-endorsement ceremony with the keys this process minted, then emits via
// emitVerified. Production assembly never calls this — it has no keys.
//
//  1. doc.IDs() — the SDK's validate() + NetworkID derivation. The endorsement
//     policy is already in the doc (canonical-bytes material), so the derived
//     NetworkID is bound to it.
//  2. When the policy requires endorsement, EVERY witness key self-endorses
//     via network.EndorseGenesis (the SDK ceremony primitive — cosign over
//     the NetworkID under PurposeGenesisEndorsement). Genesis is N-of-N: the
//     verifier demands an endorsement from every DID in GenesisWitnessSet,
//     and dev mode holds every key it names, so a partial ceremony is a bug,
//     not an option. No auditor endorsements: dev mode mints no auditor
//     identities, so GenesisAuditorEndorsementPolicy stays unset there.
//  3. emitVerified — the serving form + the first-contact round-trip.
//
// Returns the bytes to write and the doc with endorsements attached (for the
// caller's summary). doc is taken by value; the input is never mutated.
func mintServedBootstrap(doc network.BootstrapDocument, witnessPrivs []*ecdsa.PrivateKey) ([]byte, network.BootstrapDocument, error) {
	if _, err := doc.IDs(); err != nil {
		return nil, doc, fmt.Errorf("validate doc: %w", err)
	}
	if doc.RequiresEndorsement() {
		ends := make([]network.GenesisEndorsement, 0, len(witnessPrivs))
		for i, priv := range witnessPrivs {
			e, eErr := network.EndorseGenesis(doc, priv)
			if eErr != nil {
				return nil, doc, fmt.Errorf("witness #%d endorse: %w", i+1, eErr)
			}
			ends = append(ends, e)
		}
		doc.GenesisEndorsements = ends
	}
	body, err := emitVerified(doc)
	if err != nil {
		return nil, doc, err
	}
	return body, doc, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Key material (DEV MODE ONLY — build/assemble never touch keys)
// ─────────────────────────────────────────────────────────────────────────────

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// ifGenerated returns "generated" or "loaded" — used in human
// log lines to make first-vs-subsequent runs distinguishable.
func ifGenerated(generated bool) string {
	if generated {
		return "generated"
	}
	return "loaded"
}

// loadOrGenerateAdmissionAuthority loads (hex-encoded 32-byte scalar) or
// generates a secp256k1 EOA — the genesis admission authority — and returns its
// "0x"-prefixed Ethereum address. Idempotent: a re-run preserves the key file
// and derives the same address. secp256k1 is stored as raw hex (x509 EC PEM
// does not support the curve), 0600.
func loadOrGenerateAdmissionAuthority(path string) (addrHex string, generated bool, err error) {
	var priv *secp.PrivateKey
	if data, rerr := os.ReadFile(path); rerr == nil {
		raw, derr := hex.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil || len(raw) != 32 {
			return "", false, fmt.Errorf("parse admission key %q: not 32-byte hex", path)
		}
		priv = secp.PrivKeyFromBytes(raw)
	} else if errors.Is(rerr, os.ErrNotExist) {
		p, gerr := secp.GeneratePrivateKey()
		if gerr != nil {
			return "", false, fmt.Errorf("generate admission key: %w", gerr)
		}
		priv = p
		generated = true
		if merr := os.MkdirAll(dirOf(path), 0o755); merr != nil {
			return "", false, fmt.Errorf("mkdir %q: %w", dirOf(path), merr)
		}
		if werr := os.WriteFile(path, []byte(hex.EncodeToString(priv.Serialize())), 0o600); werr != nil {
			return "", false, fmt.Errorf("write %q: %w", path, werr)
		}
	} else {
		return "", false, fmt.Errorf("read %q: %w", path, rerr)
	}
	addr, aerr := signatures.AddressFromPubkey(priv.PubKey().SerializeUncompressed())
	if aerr != nil {
		return "", false, fmt.Errorf("derive admission address: %w", aerr)
	}
	return "0x" + hex.EncodeToString(addr[:]), generated, nil
}

// loadOrGenerateLedgerSignerKey loads (hex-encoded 32-byte scalar) or generates
// a secp256k1 private key — the ledger's OPERATIONAL signer — and returns its
// did:key:zQ3s… (Multicodec secp256k1). Idempotent: a re-run preserves the key
// file and re-derives the same DID. The on-disk form (raw hex) and the DID
// derivation here match exactly what cmd/ledger's loadOrGenerateLedgerSigner
// reads + computes, so the printed DID is the one the ledger will report.
// secp256k1 is stored as raw hex (x509 EC PEM does not support the curve), 0600.
func loadOrGenerateLedgerSignerKey(path string) (didKey string, generated bool, err error) {
	var priv *secp.PrivateKey
	if data, rerr := os.ReadFile(path); rerr == nil {
		raw, derr := hex.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil || len(raw) != 32 {
			return "", false, fmt.Errorf("parse ledger signer key %q: not 32-byte hex", path)
		}
		priv = secp.PrivKeyFromBytes(raw)
	} else if errors.Is(rerr, os.ErrNotExist) {
		p, gerr := secp.GeneratePrivateKey()
		if gerr != nil {
			return "", false, fmt.Errorf("generate ledger signer key: %w", gerr)
		}
		priv = p
		generated = true
		if merr := os.MkdirAll(dirOf(path), 0o755); merr != nil {
			return "", false, fmt.Errorf("mkdir %q: %w", dirOf(path), merr)
		}
		if werr := os.WriteFile(path, []byte(hex.EncodeToString(priv.Serialize())), 0o600); werr != nil {
			return "", false, fmt.Errorf("write %q: %w", path, werr)
		}
	} else {
		return "", false, fmt.Errorf("read %q: %w", path, rerr)
	}
	// Compressed secp256k1 pubkey → Multicodec secp256k1 did:key. Identical to
	// cmd/ledger didKeyFromSecp256k1Priv (PubKeyBytes→Compress→EncodeDIDKey).
	compressed := priv.PubKey().SerializeCompressed()
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), generated, nil
}

// witnessPEMType is the PEM block type for a witness secp256k1 private key.
// It MUST stay byte-identical to tooling' witkey.PEMType — that is the
// cross-repo contract: dev mode writes the witness PEM here, the
// tooling witness daemon loads it via witkey.LoadPEM. The block carries
// the raw 32-byte big-endian scalar (secp256k1 is not a stdlib x509 curve, so
// SEC1/"EC PRIVATE KEY" cannot represent it).
const witnessPEMType = "BASEPROOF SECP256K1 PRIVATE KEY"

// secp256k1DIDKey derives the did:key:zQ3s… (Multicodec secp256k1) for a
// secp256k1 private key — identical to cmd/ledger didKeyFromSecp256k1Priv and
// to tooling witkey.DID, so the bootstrap DID matches what every consumer
// (the ledger's quorum.LoadWitnessKeys and the witness daemon) derives.
func secp256k1DIDKey(priv *ecdsa.PrivateKey) (string, error) {
	compressed, err := signatures.CompressSecp256k1Pubkey(signatures.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		return "", err
	}
	return sdkdid.EncodeDIDKey(sdkdid.MulticodecSecp256k1, compressed), nil
}

// loadOrGenerateWitnessKey loads a secp256k1 witness key (raw 32-byte scalar in
// a witnessPEMType PEM block) from path, OR generates a fresh one and writes it.
// Returns the key + a flag indicating whether it was newly generated. A legacy
// P-256 "EC PRIVATE KEY" file fails the type check loudly — wipe to regenerate
// as secp256k1.
func loadOrGenerateWitnessKey(path string) (*ecdsa.PrivateKey, bool, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != witnessPEMType {
			return nil, false, fmt.Errorf("witness key %q: expected PEM block %q (secp256k1); a legacy/other key was found — wipe to regenerate", path, witnessPEMType)
		}
		priv, pErr := signatures.PrivKeyFromBytes(block.Bytes)
		if pErr != nil {
			return nil, false, fmt.Errorf("parse witness key %q: %w", path, pErr)
		}
		return priv, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read %q: %w", path, err)
	}

	priv, err := signatures.GenerateKey()
	if err != nil {
		return nil, false, fmt.Errorf("generate secp256k1 witness key: %w", err)
	}
	var scalar [32]byte
	priv.D.FillBytes(scalar[:])
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: witnessPEMType, Bytes: scalar[:]})
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, false, fmt.Errorf("mkdir %q: %w", dirOf(path), err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, false, fmt.Errorf("write %q: %w", path, err)
	}
	return priv, true, nil
}
