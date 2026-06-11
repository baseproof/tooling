/*
FILE PATH: cmd/gen-fixtures/main.go

DESCRIPTION:

	One-shot fixture generator for running the standalone-witness
	daemon locally without a ledger checkout. Produces:

	    <out-dir>/witnesses/witness-<i>.pem    — secp256k1 private key (PEM)
	    <out-dir>/network-bootstrap.json       — BootstrapDocument

	Keys are secp256k1 (internal/witkey) — the Baseproof witness/cosign
	curve. The daemon (main.go) loads the same witkey PEM, and each
	witness's secp256k1 did:key:zQ3s… is listed in genesis_witness_set
	so the ledger's witness.KeysFromDIDs resolver accepts it and the
	network identity derivation (BootstrapDocument.IDs()) succeeds.

USAGE:

	go run ./cmd/gen-fixtures                       # 1 witness, .run/
	go run ./cmd/gen-fixtures -witnesses=3          # K=3 fleet
	go run ./cmd/gen-fixtures -out-dir=/tmp/fixt    # custom dir

IDEMPOTENCY:

	Re-runs preserve any existing .pem files (load + reuse) and
	rewrite the bootstrap doc to match. Wipe with `rm -rf .run`
	if you want a fresh keyset.

MODULE BOUNDARY:

	Imports only github.com/baseproof/baseproof — never the
	ledger. Mirrors the boundary documented in
	internal/serve/serve.go.
*/
package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	sdkdid "github.com/baseproof/baseproof/did"
	"github.com/baseproof/baseproof/network"

	"github.com/baseproof/tooling/services/witness/internal/blskey"
	"github.com/baseproof/tooling/services/witness/internal/witkey"
)

const (
	defaultOutDir      = ".run"
	defaultLogDID      = "did:baseproof:standalone-witness:local"
	defaultNetworkName = "local-dev"
	zeroRootHash       = "0000000000000000000000000000000000000000000000000000000000000000"
)

func main() {
	outDir := flag.String("out-dir", defaultOutDir,
		"directory to write witness keys + bootstrap doc into")
	outBootstrap := flag.String("out-bootstrap", "",
		"path to write the BootstrapDocument JSON "+
			"(default: <out-dir>/network-bootstrap.json)")
	logDID := flag.String("log-did", defaultLogDID,
		"ExchangeDID field of the BootstrapDocument")
	networkName := flag.String("network-name", defaultNetworkName,
		"network_name field of the BootstrapDocument")
	witnessCount := flag.Int("witnesses", 1,
		"number of witness keys to generate")
	scheme := flag.String("scheme", "ecdsa",
		"witness cosignature scheme: ecdsa (secp256k1 did:key genesis witnesses, "+
			"the default) or bls (BLS12-381 witnesses + one ECDSA genesis anchor — "+
			"a BLS key cannot be a genesis did:key, so the bootstrap admits cosign "+
			"scheme 0x02 and the BLS witnesses join the verifying set on-log via "+
			"the WitnessEndpointDeclaration each daemon emits at boot).")
	genesisAuditorDIDs := flag.String("genesis-auditor-did", "",
		"comma-separated secp256k1 did:key(s) to declare as genesis auditors in the "+
			"bootstrap (bound into the NetworkID). Each is recognized by the always-on "+
			"auditor-scope gate, so its claim-class findings (equivocation, etc.) are "+
			"admitted. Typically the ledger's gossip-originator did:key.")
	genesisAuditorFindingsURL := flag.String("genesis-auditor-findings-url", "",
		"findings-publishing URL stamped on every -genesis-auditor-did entry "+
			"(required when -genesis-auditor-did is set).")
	flag.Parse()

	if err := run(*outDir, *outBootstrap, *logDID, *networkName, *witnessCount, *scheme,
		*genesisAuditorDIDs, *genesisAuditorFindingsURL, os.Stdout); err != nil {
		log.Fatalf("gen-fixtures: %v", err)
	}
}

// run is the testable body. It is exported via lowercase so
// main_test.go can drive it without exec'ing a subprocess.
func run(outDir, outBootstrap, logDID, networkName string, witnessCount int, scheme, genesisAuditorDIDs, genesisAuditorFindingsURL string, stdout *os.File) error {
	if witnessCount < 1 {
		return fmt.Errorf("-witnesses must be >= 1 (got %d): a network without witnesses cannot finalise heads", witnessCount)
	}
	if logDID == "" {
		return errors.New("-log-did must be non-empty")
	}
	if networkName == "" {
		return errors.New("-network-name must be non-empty")
	}

	bootstrapPath := outBootstrap
	if bootstrapPath == "" {
		bootstrapPath = filepath.Join(outDir, "network-bootstrap.json")
	}

	if scheme != "ecdsa" && scheme != "bls" {
		return fmt.Errorf("-scheme must be \"ecdsa\" or \"bls\" (got %q)", scheme)
	}
	genesisDIDs, keyPaths, cosignTags, err := generateWitnessKeys(outDir, scheme, witnessCount, stdout)
	if err != nil {
		return err
	}

	doc := network.BootstrapDocument{
		ProtocolVersion:   "v1",
		ExchangeDID:       logDID,
		NetworkName:       networkName,
		GenesisWitnessSet: genesisDIDs,
		// GenesisQuorumK is REQUIRED since rc4 and NetworkID-bound: the
		// constitution is the single source of truth for K. The fixture
		// generator mints a simple majority (N/2+1), which satisfies the
		// quorum-intersection invariant 2K>N for every N — matching
		// init-network's auto default so either tool mints the same shape.
		GenesisQuorumK: len(genesisDIDs)/2 + 1,
		GenesisTreeHead: network.GenesisTreeHead{
			RootHash: zeroRootHash,
			TreeSize: 0,
		},
		// v1.20.0: genesis admission. Witness fixtures are not a ledger
		// gate, so gating is off (no admission authorities required).
		GenesisAdmissionPolicy: network.GenesisAdmissionPolicy{
			GatingRequired: false,
			CostMode:       "uncharged",
		},
		// GenesisSignaturePolicy is required since SDK v1.31 (hashed
		// into NetworkID). Permissive default suitable for witness
		// fixtures (the daemon never enforces it; the ledger does).
		GenesisSignaturePolicy: network.SignaturePolicy{
			AllowedEntrySigSchemes:  []uint16{0x0001}, // SigAlgoECDSA (entry signing stays ECDSA)
			AllowedCosignSchemeTags: cosignTags,       // [ECDSA] for -scheme=ecdsa; [ECDSA, BLS] for -scheme=bls
			MinSignaturesPerEntry:   1,
		},
	}

	// Genesis auditors: secp256k1 did:key(s) the always-on auditor-scope gate
	// recognizes from sequence 0 (bound into the NetworkID via the JCS bytes).
	auditors, err := buildGenesisAuditors(genesisAuditorDIDs, genesisAuditorFindingsURL)
	if err != nil {
		return err
	}
	doc.GenesisAuditors = auditors

	if _, err := doc.IDs(); err != nil {
		return fmt.Errorf("validate bootstrap document: %w", err)
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bootstrap: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(bootstrapPath), 0o755); err != nil {
		return fmt.Errorf("mkdir bootstrap dir: %w", err)
	}
	if err := os.WriteFile(bootstrapPath, append(body, '\n'), 0o644); err != nil {
		return fmt.Errorf("write bootstrap: %w", err)
	}

	fmt.Fprintf(stdout, "gen-fixtures: witnesses = %d\n", witnessCount)
	fmt.Fprintf(stdout, "gen-fixtures: keys      = %v\n", keyPaths)
	fmt.Fprintf(stdout, "gen-fixtures: bootstrap = %s\n", bootstrapPath)
	return nil
}

// buildGenesisAuditors decodes each comma-separated secp256k1 did:key into a
// network.GenesisAuditor recognized by the always-on auditor-scope gate. The
// public key is taken from the did:key itself (self-certifying), so the
// declaration is consistent with the originator's gossip identity. Scope is the
// full set (ScopeAll) — a founding auditor is trusted for every finding kind.
// Empty input yields no genesis auditors (the bootstrap then declares none, and
// the gate has no genesis recognition anchor).
func buildGenesisAuditors(didCSV, findingsURL string) ([]network.GenesisAuditor, error) {
	didCSV = strings.TrimSpace(didCSV)
	if didCSV == "" {
		return nil, nil
	}
	if strings.TrimSpace(findingsURL) == "" {
		return nil, errors.New("-genesis-auditor-findings-url is required when -genesis-auditor-did is set")
	}
	var out []network.GenesisAuditor
	for _, raw := range strings.Split(didCSV, ",") {
		did := strings.TrimSpace(raw)
		if did == "" {
			continue
		}
		if !strings.HasPrefix(did, "did:key:zQ3s") {
			return nil, fmt.Errorf("genesis auditor %q must be a secp256k1 did:key (did:key:zQ3s…)", did)
		}
		pub, _, perr := sdkdid.ParseDIDKey(did)
		if perr != nil {
			return nil, fmt.Errorf("genesis auditor %q: %w", did, perr)
		}
		out = append(out, network.GenesisAuditor{
			AuditorDID:  did,
			PublicKey:   hex.EncodeToString(pub),
			SchemeTag:   0x01, // SchemeECDSA (secp256k1 did:key)
			FindingsURL: findingsURL,
			Scope:       uint16(network.ScopeAll),
		})
	}
	return out, nil
}

func ifGenerated(generated bool) string {
	if generated {
		return "generated"
	}
	return "loaded"
}

// generateWitnessKeys produces the genesis witness set + on-disk key files for
// the chosen cosign scheme, and returns the AllowedCosignSchemeTags the
// bootstrap must admit.
//
//   - ecdsa: witnessCount secp256k1 did:key witnesses, all listed in
//     genesis_witness_set (resolved by witness.KeysFromDIDs). cosignTags=[ECDSA].
//   - bls: witnessCount BLS12-381 witnesses written as blskey PEMs, PLUS one
//     ECDSA "genesis anchor" did:key. A BLS key cannot be a genesis did:key
//     (the did:key multicodec carries no PoP slot, and KeysFromDIDs is
//     secp256k1-only), so the anchor is the resolvable genesis witness and the
//     BLS witnesses join the verifying set on-log via the
//     WitnessEndpointDeclaration each daemon emits at boot. cosignTags=[ECDSA, BLS].
func generateWitnessKeys(outDir, scheme string, witnessCount int, stdout *os.File) (genesisDIDs, keyPaths []string, cosignTags []uint8, err error) {
	if scheme == "bls" {
		// Genesis anchor: an ECDSA did:key so genesis_witness_set is valid and
		// resolvable; the BLS witnesses below join on-log.
		anchorPath := filepath.Join(outDir, "witnesses", "genesis-anchor.pem")
		anchor, generated, aerr := loadOrGenerateWitnessKey(anchorPath)
		if aerr != nil {
			return nil, nil, nil, fmt.Errorf("genesis anchor (%s): %w", anchorPath, aerr)
		}
		anchorDID, derr := witkey.DID(anchor)
		if derr != nil {
			return nil, nil, nil, fmt.Errorf("genesis anchor (%s): derive DID: %w", anchorPath, derr)
		}
		genesisDIDs = append(genesisDIDs, anchorDID)
		keyPaths = append(keyPaths, anchorPath)
		fmt.Fprintf(stdout, "gen-fixtures: genesis anchor (ecdsa) %s %s -> %s\n",
			ifGenerated(generated), anchorPath, anchorDID)

		for i := 1; i <= witnessCount; i++ {
			path := filepath.Join(outDir, "witnesses", fmt.Sprintf("witness-%d.bls.pem", i))
			id, gen, berr := loadOrGenerateBLSKey(path)
			if berr != nil {
				return nil, nil, nil, fmt.Errorf("bls witness #%d (%s): %w", i, path, berr)
			}
			keyPaths = append(keyPaths, path)
			fmt.Fprintf(stdout, "gen-fixtures: bls witness #%d %s %s -> pub_key_id %s (joins on-log)\n",
				i, ifGenerated(gen), path, hex.EncodeToString(id[:]))
		}
		return genesisDIDs, keyPaths, []uint8{0x01, 0x02}, nil
	}

	for i := 1; i <= witnessCount; i++ {
		path := filepath.Join(outDir, "witnesses", fmt.Sprintf("witness-%d.pem", i))
		priv, generated, gerr := loadOrGenerateWitnessKey(path)
		if gerr != nil {
			return nil, nil, nil, fmt.Errorf("witness #%d (%s): %w", i, path, gerr)
		}
		did, derr := witkey.DID(priv)
		if derr != nil {
			return nil, nil, nil, fmt.Errorf("witness #%d (%s): derive DID: %w", i, path, derr)
		}
		genesisDIDs = append(genesisDIDs, did)
		keyPaths = append(keyPaths, path)
		fmt.Fprintf(stdout, "gen-fixtures: witness #%d %s %s -> %s\n",
			i, ifGenerated(generated), path, did)
	}
	return genesisDIDs, keyPaths, []uint8{0x01}, nil
}

// loadOrGenerateBLSKey reads an existing BLS witness key at path, or generates
// a fresh one and writes it. Returns the witness's PubKeyID (SHA-256 of the G2
// key) for logging + a flag indicating whether it was newly generated.
// Idempotent across runs (mirrors loadOrGenerateWitnessKey for secp256k1).
func loadOrGenerateBLSKey(path string) (id [32]byte, generated bool, err error) {
	if _, statErr := os.Stat(path); statErr == nil {
		priv, lerr := blskey.LoadPEM(path)
		if lerr != nil {
			return [32]byte{}, false, lerr
		}
		return blskey.PubKeyID(blskey.PubKey(priv)), false, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return [32]byte{}, false, fmt.Errorf("stat %q: %w", path, statErr)
	}

	priv, _, gerr := blskey.Generate()
	if gerr != nil {
		return [32]byte{}, false, fmt.Errorf("generate bls key: %w", gerr)
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		return [32]byte{}, false, fmt.Errorf("mkdir %q: %w", filepath.Dir(path), mkErr)
	}
	if wErr := os.WriteFile(path, blskey.EncodePEM(priv), 0o600); wErr != nil {
		return [32]byte{}, false, fmt.Errorf("write %q: %w", path, wErr)
	}
	return blskey.PubKeyID(blskey.PubKey(priv)), true, nil
}

// loadOrGenerateWitnessKey reads an existing secp256k1 witness key at path,
// OR generates a fresh one and writes it. Returns the key + a flag indicating
// whether it was newly generated. Idempotent across runs (a legacy P-256
// "EC PRIVATE KEY" file fails the witkey type check loudly — wipe .run to
// regenerate as secp256k1).
func loadOrGenerateWitnessKey(path string) (*ecdsa.PrivateKey, bool, error) {
	if _, err := os.Stat(path); err == nil {
		priv, lerr := witkey.LoadPEM(path)
		if lerr != nil {
			return nil, false, lerr
		}
		return priv, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("stat %q: %w", path, err)
	}

	priv, err := witkey.Generate()
	if err != nil {
		return nil, false, fmt.Errorf("generate key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, false, fmt.Errorf("mkdir %q: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, witkey.EncodePEM(priv), 0o600); err != nil {
		return nil, false, fmt.Errorf("write %q: %w", path, err)
	}
	return priv, true, nil
}
