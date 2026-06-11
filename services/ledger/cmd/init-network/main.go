/*
FILE PATH:

	cmd/init-network/main.go

DESCRIPTION:

	One-shot bootstrap-doc + witness-key generator for local
	dev. Produces a self-witness K=1 topology that
	scripts/run-local.sh consumes:

	    ./bin/init-network \
	        -out-witness-key=.run/witness.pem \
	        -out-bootstrap=.run/network-bootstrap.json \
	        -log-did=did:baseproof:ledger:local

	Idempotent on the witness key: re-runs preserve the
	existing key file, derive the SAME did:key from it, and
	rewrite the bootstrap doc (which depends on the DID).

KEY ARCHITECTURAL DECISIONS:
  - Mirrors loadOrGenerateWitnessSigner in cmd/ledger/main.go:
    same secp256k1 key shape (PEM-encoded EC private key) so
    the ledger consumes whatever this tool produces without
    a translation layer.
  - DID derivation reuses didKeyFromSecp256k1Priv-equivalent
    logic via the SDK's did.EncodeDIDKey + multicodec.
  - Bootstrap doc is the minimum-viable shape: protocol_version
  - exchange_did + network_name + genesis_witness_set
    (single-element) + zero-tree-head. Sufficient for
    single-node K=1 dev; production deployments use a real
    Exchange-issued bootstrap.
  - Fail-closed minting (#77): the tool holds every witness key it
    names, so by default it runs the full N-of-N genesis ceremony
    itself — GenesisEndorsementPolicy=require is bound into the
    NetworkID, every key endorses via network.EndorseGenesis, and
    the output must pass network.LoadVerifiedBootstrap (the
    consumer's first-contact gate) BEFORE it is written. A mint
    that cannot pass first contact never leaves the tool.

OVERVIEW:

	Output:
	  .run/witness.pem            — secp256k1 EC private key (PEM)
	  .run/network-bootstrap.json — BootstrapDocument with the
	                                derived did:key in genesis_witness_set,
	                                self-endorsed by every witness key
	                                (unless -endorsement-policy=off)
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/baseproof/baseproof/crypto/signatures"
	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func main() {
	outDir := flag.String("out-dir", ".run",
		"directory to write witness keys + bootstrap doc into")
	outBootstrap := flag.String("out-bootstrap", "",
		"path to write the network BootstrapDocument JSON "+
			"(default: <out-dir>/network-bootstrap.json)")
	logDID := flag.String("log-did", "did:baseproof:ledger:local",
		"LogDID — used as exchange_did stand-in for local dev")
	networkName := flag.String("network-name", "local-dev",
		"network_name field of the BootstrapDocument")
	gating := flag.String("gating", "require",
		`genesis admission gating: "require" (default-require a WriteAuthorization, production) `+
			`or "off" (open writes — dev/test load harnesses only)`)
	witnessCount := flag.Int("witnesses", 1,
		"number of witness keys to generate. Each key is written to "+
			"<out-dir>/witnesses/witness-<i>.pem and its DID is added "+
			"to GenesisWitnessSet. The Ledger writer is NEVER in the "+
			"witness set — that's a network role, not a Ledger role.")
	quorum := flag.Int("quorum", 0,
		"genesis witness quorum K-of-N — the GenesisQuorumK bound into the "+
			"NetworkID (REQUIRED since baseproof SDK rc4: the constitution is the "+
			"single source of truth for K, so the ledger no longer takes it from "+
			"the LEDGER_WITNESS_QUORUM_K env). 0 = auto majority (N/2+1). MUST "+
			"satisfy 1<=K<=N AND 2K>N — the quorum-intersection invariant: with "+
			"two disjoint K-quorums a fork stops being provable equivocation, so "+
			"the SDK's validate() rejects 2K<=N before the doc can be minted.")
	outLedgerKey := flag.String("out-ledger-key", "",
		"path to write the ledger's OPERATIONAL secp256k1 signer key as a "+
			"raw 32-byte hex scalar (the format LEDGER_SIGNER_KEY_FILE reads). "+
			"Empty → not written; the ledger mints an ephemeral key at boot. "+
			"Idempotent: a re-run preserves an existing key and re-derives the "+
			"same did:key. This is the ledger's gossip-originator + entry-author "+
			"identity — distinct from the witness set and the admission authority.")
	minSignatures := flag.Int("min-signatures", 1,
		"genesis GenesisSignaturePolicy.MinSignaturesPerEntry — the minimum count "+
			"of cryptographically-valid signatures every admitted entry must carry. "+
			"MUST be in [1, 64]: a 0 floor would admit unsigned entries and is "+
			"rejected by the SDK at NetworkID derivation; 64 is the envelope wire "+
			"cap. Post-genesis this floor is amendable on-log via an "+
			"BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1 entry (see cmd/ledger "+
			"LEDGER_SIGNATURE_POLICY_SCHEMA); the amendment is itself a logged, "+
			"witness-cosigned governance act, never an off-log override.")
	endorsementPolicy := flag.String("endorsement-policy", "require",
		`genesis endorsement policy: "require" (default) sets GenesisEndorsementPolicy=require — `+
			"INSIDE the canonical bytes, so the requirement is NetworkID-bound and cannot be "+
			"stripped post-mint — and has every generated witness key self-endorse the "+
			"constitution (N-of-N genesis ceremony; this tool HOLDS all the keys it names, so "+
			`it can run the full ceremony at mint). "off" emits no policy and no endorsements `+
			"(legacy/dev escape hatch). Either way the output must pass "+
			"network.LoadVerifiedBootstrap before it is written.")
	flag.Parse()

	if *witnessCount < 1 {
		log.Fatalf("init-network: -witnesses must be >= 1 (a network without witnesses cannot finalise heads)")
	}
	if *minSignatures < 1 || *minSignatures > 64 {
		log.Fatalf("init-network: -min-signatures must be in [1, 64] (got %d); a 0 floor would admit unsigned entries", *minSignatures)
	}
	// The endorsement policy is canonical-bytes material (NetworkID-bound), so a
	// typo must not silently mint a constitution the operator did not intend.
	if *endorsementPolicy != "require" && *endorsementPolicy != "off" {
		log.Fatalf(`init-network: -endorsement-policy must be "require" or "off" (got %q)`, *endorsementPolicy)
	}
	// Resolve the genesis quorum K (see resolveGenesisQuorumK): 0 ⇒ auto
	// majority. An out-of-range or diluting K fails here at mint, not at the
	// network's first boot.
	quorumK, qErr := resolveGenesisQuorumK(*quorum, *witnessCount)
	if qErr != nil {
		log.Fatalf("init-network: %v", qErr)
	}

	bootstrapPath := *outBootstrap
	if bootstrapPath == "" {
		bootstrapPath = *outDir + "/network-bootstrap.json"
	}

	// Generate N witness keys and collect their DIDs. Every key is
	// genuinely network witness material: a witness daemon
	// will load the PEM file and serve /v1/cosign for the
	// corresponding DID. The Ledger writer holds NONE of these keys.
	//
	// secp256k1 BY REQUIREMENT — the witness/cosign layer is secp256k1
	// end-to-end: the ledger resolves these DIDs via quorum.LoadWitnessKeys →
	// witness.KeysFromDIDs (secp256k1-only) at boot, and the witness daemon
	// loads the PEM via tooling' witkey (also secp256k1). A P-256
	// witness DID is rejected on both sides.
	genesisDIDs := make([]string, 0, *witnessCount)
	witnessPrivs := make([]*ecdsa.PrivateKey, 0, *witnessCount)
	keyPaths := make([]string, 0, *witnessCount)
	for i := 1; i <= *witnessCount; i++ {
		path := fmt.Sprintf("%s/witnesses/witness-%d.pem", *outDir, i)
		priv, generated, kerr := loadOrGenerateWitnessKey(path)
		if kerr != nil {
			log.Fatalf("init-network: witness #%d (%s): %v", i, path, kerr)
		}
		did, derr := secp256k1DIDKey(priv)
		if derr != nil {
			log.Fatalf("init-network: witness #%d (%s): derive DID: %v", i, path, derr)
		}
		genesisDIDs = append(genesisDIDs, did)
		witnessPrivs = append(witnessPrivs, priv)
		keyPaths = append(keyPaths, path)
		fmt.Printf("init-network: witness #%d %s = %s -> %s\n",
			i, ifGenerated(generated), path, did)
	}

	// Genesis admission authority: generate-or-load the secp256k1 EOA that may
	// authorize writes from genesis (the write-path root of trust).
	authKeyPath := fmt.Sprintf("%s/admission-authority.key", *outDir)
	genesisAuthorityAddr, authGen, authErr := loadOrGenerateAdmissionAuthority(authKeyPath)
	if authErr != nil {
		log.Fatalf("init-network: admission authority key (%s): %v", authKeyPath, authErr)
	}
	fmt.Printf("init-network: admission authority %s = %s -> %s\n",
		ifGenerated(authGen), authKeyPath, genesisAuthorityAddr)

	// Optional: the ledger's OPERATIONAL signer key — its gossip-originator +
	// entry-author secp256k1 did:key. Written as a raw hex scalar (the dialect
	// LEDGER_SIGNER_KEY_FILE reads). NOT added to the witness set or admission
	// authorities — it is a distinct role. Pinning it makes the ledger's did:key
	// stable across restarts (production); leaving it unset lets the ledger mint
	// an ephemeral key (dev), which peers/auditors discover via /v1/log-info.
	if *outLedgerKey != "" {
		ledgerDID, ledgerGen, lkErr := loadOrGenerateLedgerSignerKey(*outLedgerKey)
		if lkErr != nil {
			log.Fatalf("init-network: ledger signer key (%s): %v", *outLedgerKey, lkErr)
		}
		fmt.Printf("init-network: ledger signer %s = %s -> %s\n",
			ifGenerated(ledgerGen), *outLedgerKey, ledgerDID)
	}

	doc := buildBootstrapDoc(*logDID, *networkName, *gating, *endorsementPolicy, genesisDIDs, quorumK, genesisAuthorityAddr, uint8(*minSignatures))
	// mintServedBootstrap runs the SDK validation (doc.IDs()), the genesis
	// self-endorsement ceremony when the policy requires it, and the
	// first-contact round-trip (network.LoadVerifiedBootstrap) over the EXACT
	// bytes to be written. Any failure exits non-zero here, BEFORE the file
	// exists — a mint that cannot pass first contact never leaves the tool.
	body, doc, mErr := mintServedBootstrap(doc, witnessPrivs)
	if mErr != nil {
		log.Fatalf("init-network: %v", mErr)
	}
	if err := os.MkdirAll(dirOf(bootstrapPath), 0o755); err != nil {
		log.Fatalf("init-network: mkdir bootstrap dir: %v", err)
	}
	if err := os.WriteFile(bootstrapPath, body, 0o644); err != nil {
		log.Fatalf("init-network: write bootstrap: %v", err)
	}

	fmt.Printf("init-network: witnesses     = %d (key paths: %v)\n",
		*witnessCount, keyPaths)
	fmt.Printf("init-network: endorsements  = %d (policy=%s)\n",
		len(doc.GenesisEndorsements), *endorsementPolicy)
	fmt.Printf("init-network: bootstrap     = %s\n", bootstrapPath)
}

// mintServedBootstrap finalizes the constitution for serving, fail-closed:
//
//  1. doc.IDs() — the SDK's validate() + NetworkID derivation. The endorsement
//     policy is already in the doc (canonical-bytes material), so the derived
//     NetworkID is bound to it.
//  2. When the policy requires endorsement, EVERY witness key self-endorses
//     via network.EndorseGenesis (the SDK ceremony primitive — cosign over
//     the NetworkID under PurposeGenesisEndorsement). Genesis is N-of-N: the
//     verifier demands an endorsement from every DID in GenesisWitnessSet,
//     and this tool holds every key it names, so a partial ceremony is a bug,
//     not an option. No auditor endorsements: GenesisAuditorEndorsementPolicy
//     is unset, so the SDK requires none.
//  3. network.EndorsedBootstrapBytes — the SDK's SERVING form (endorsements
//     INSIDE the JSON, OUTSIDE the canonical bytes), verified before emit.
//     Re-indented only for human audit; whitespace is not canonical material.
//  4. network.LoadVerifiedBootstrap(body, NetworkID) over the exact bytes the
//     caller will write — the same single first-contact gate every consumer
//     runs. If first contact would fail, the mint must not exist.
//
// Returns the bytes to write and the doc with endorsements attached (for the
// caller's summary). doc is taken by value; the input is never mutated.
func mintServedBootstrap(doc network.BootstrapDocument, witnessPrivs []*ecdsa.PrivateKey) ([]byte, network.BootstrapDocument, error) {
	ids, err := doc.IDs()
	if err != nil {
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
	served, err := network.EndorsedBootstrapBytes(doc)
	if err != nil {
		return nil, doc, fmt.Errorf("serving-form emit: %w", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, served, "", "  "); err != nil {
		return nil, doc, fmt.Errorf("indent serving form: %w", err)
	}
	pretty.WriteByte('\n')
	body := pretty.Bytes()
	if _, err := network.LoadVerifiedBootstrap(body, [32]byte(ids.NetworkID)); err != nil {
		return nil, doc, fmt.Errorf("first-contact round-trip (refusing to write a mint that fails it): %w", err)
	}
	return body, doc, nil
}

// resolveGenesisQuorumK turns the -quorum flag into the constitutional
// GenesisQuorumK bound into the NetworkID. flagK==0 means "auto": a simple
// majority (N/2+1), which satisfies the quorum-intersection invariant 2K>N for
// every N≥1. An explicit flagK is validated against the same two gates the
// SDK's validate() applies inside doc.IDs() — 1<=K<=N and 2K>N — so a network
// that could fork undetectably (two disjoint K-quorums when 2K<=N) can never be
// minted by this tool, and the operator sees a precise message here rather than
// a generic NetworkID-derivation failure later.
func resolveGenesisQuorumK(flagK, witnessCount int) (int, error) {
	k := flagK
	if k == 0 {
		k = witnessCount/2 + 1 // simple majority — 2K>N holds for all N≥1
	}
	if k < 1 || k > witnessCount {
		return 0, fmt.Errorf("-quorum K=%d out of range 1..%d (N witnesses)", k, witnessCount)
	}
	if 2*k <= witnessCount {
		return 0, fmt.Errorf("-quorum K=%d violates the quorum-intersection invariant 2K>N for N=%d: "+
			"two disjoint K-quorums could each finalise a different head, making a fork unprovable equivocation", k, witnessCount)
	}
	return k, nil
}

// buildBootstrapDoc assembles the genesis BootstrapDocument from the resolved
// inputs. Extracted from main so the document's validity is unit-testable (see
// main_test.go) — the SDK's validate() runs inside doc.IDs(), and a missing
// genesis_signature_policy (required since SDK v1.31) is rejected as an
// "admit-nothing" policy, which is exactly the regression this guards.
func buildBootstrapDoc(logDID, networkName, gating, endorsementPolicy string, genesisDIDs []string, quorumK int, genesisAuthorityAddr string, minSignatures uint8) network.BootstrapDocument {
	// GenesisEndorsementPolicy is canonical-bytes material: "require" is hashed
	// into the NetworkID, so it cannot be stripped post-mint without minting a
	// DIFFERENT network — the fail-closed half of issue #77. "off" emits no
	// policy key (the legacy/pre-ceremony doc shape). The endorsements
	// themselves are attached AFTER ID derivation (mintServedBootstrap): they
	// sign the identity, so they live outside the canonical bytes by definition.
	genesisEndorsementPolicy := ""
	if endorsementPolicy != "off" {
		genesisEndorsementPolicy = network.GenesisEndorsementRequire
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
		// doc.IDs() below, so a 0 floor can never be locked into the NetworkID.
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001}, // SigAlgoECDSA (secp256k1)
			AllowedCosignSchemeTags: []uint8{0x01},    // SchemeECDSA
			MinSignaturesPerEntry:   minSignatures,
		},
		GenesisEndorsementPolicy: genesisEndorsementPolicy,
		// GenesisAuditorEndorsementPolicy stays unset: this tool mints no
		// auditor identities, and a "require" with no genesis_auditors is
		// rejected by the SDK as unsatisfiable. LoadVerifiedBootstrap therefore
		// demands witness endorsements only.
	}
}

// dirOf returns the directory portion of path. For
// ".run/witness.pem" it returns ".run".
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
// cross-repo contract: init-network writes the witness PEM here, the
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
