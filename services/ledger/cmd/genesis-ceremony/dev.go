/*
FILE PATH: cmd/genesis-ceremony/dev.go

DEV-ONLY single-host fixture mode — the superseded init-network behavior,
flag-compatible so the e2e fleet and local-dev scripts move over unchanged
(plus the leading "dev" argument).

One process minting a network's ENTIRE witness set and self-endorsing N-of-N is
a fixture, never a production ceremony: whoever runs it holds every key the
constitution names. Production networks use build → genesis-endorse (per
witness, per host) → assemble, where the coordinator holds no keys at all.

Idempotent on key material: re-runs preserve existing key files, derive the
SAME DIDs from them, and rewrite the bootstrap doc (which depends on the DIDs).
*/
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"os"
)

func runDev(args []string) {
	fs := flag.NewFlagSet("genesis-ceremony dev", flag.ExitOnError)
	outDir := fs.String("out-dir", ".run",
		"directory to write witness keys + bootstrap doc into")
	outBootstrap := fs.String("out-bootstrap", "",
		"path to write the network BootstrapDocument JSON "+
			"(default: <out-dir>/network-bootstrap.json)")
	logDID := fs.String("log-did", "did:baseproof:ledger:local",
		"LogDID — used as exchange_did stand-in for local dev")
	networkName := fs.String("network-name", "local-dev",
		"network_name field of the BootstrapDocument")
	gating := fs.String("gating", "require",
		`genesis admission gating: "require" (default-require a WriteAuthorization, production) `+
			`or "off" (open writes — dev/test load harnesses only)`)
	witnessCount := fs.Int("witnesses", 1,
		"number of witness keys to generate. Each key is written to "+
			"<out-dir>/witnesses/witness-<i>.pem and its DID is added "+
			"to GenesisWitnessSet. The Ledger writer is NEVER in the "+
			"witness set — that's a network role, not a Ledger role.")
	quorum := fs.Int("quorum", 0,
		"genesis witness quorum K-of-N — the GenesisQuorumK bound into the "+
			"NetworkID (REQUIRED since baseproof SDK rc4: the constitution is the "+
			"single source of truth for K, so the ledger no longer takes it from "+
			"the LEDGER_WITNESS_QUORUM_K env). 0 = auto majority (N/2+1). MUST "+
			"satisfy 1<=K<=N AND 2K>N — the quorum-intersection invariant: with "+
			"two disjoint K-quorums a fork stops being provable equivocation, so "+
			"the SDK's validate() rejects 2K<=N before the doc can be minted.")
	outLedgerKey := fs.String("out-ledger-key", "",
		"path to write the ledger's OPERATIONAL secp256k1 signer key as a "+
			"raw 32-byte hex scalar (the format LEDGER_SIGNER_KEY_FILE reads). "+
			"Empty → not written; the ledger mints an ephemeral key at boot. "+
			"Idempotent: a re-run preserves an existing key and re-derives the "+
			"same did:key. This is the ledger's gossip-originator + entry-author "+
			"identity — distinct from the witness set and the admission authority.")
	minSignatures := fs.Int("min-signatures", 1,
		"genesis GenesisSignaturePolicy.MinSignaturesPerEntry — the minimum count "+
			"of cryptographically-valid signatures every admitted entry must carry. "+
			"MUST be in [1, 64]: a 0 floor would admit unsigned entries and is "+
			"rejected by the SDK at NetworkID derivation; 64 is the envelope wire "+
			"cap. Post-genesis this floor is amendable on-log via an "+
			"BP-ENTRY-NETWORK-SIGNATURE-POLICY-V1 entry (see cmd/ledger "+
			"LEDGER_SIGNATURE_POLICY_SCHEMA); the amendment is itself a logged, "+
			"witness-cosigned governance act, never an off-log override.")
	endorsementPolicy := fs.String("endorsement-policy", "require",
		`genesis endorsement policy: "require" (default) sets GenesisEndorsementPolicy=require — `+
			"INSIDE the canonical bytes, so the requirement is NetworkID-bound and cannot be "+
			"stripped post-mint — and has every generated witness key self-endorse the "+
			"constitution (N-of-N genesis ceremony; dev mode HOLDS all the keys it names, so "+
			`it can run the full ceremony at mint). "off" emits no policy and no endorsements `+
			"(legacy/dev escape hatch). Either way the output must pass "+
			"network.LoadVerifiedBootstrap before it is written.")
	anchoringMaxInterval := fs.Duration("anchoring-max-interval", 0,
		"constitutional ANCHORING commitment bound (see `genesis-ceremony build -h`); 0 = none")
	_ = fs.Parse(args)

	if *witnessCount < 1 {
		log.Fatalf("genesis-ceremony dev: -witnesses must be >= 1 (a network without witnesses cannot finalise heads)")
	}
	if *minSignatures < 1 || *minSignatures > 64 {
		log.Fatalf("genesis-ceremony dev: -min-signatures must be in [1, 64] (got %d); a 0 floor would admit unsigned entries", *minSignatures)
	}
	// The endorsement policy is canonical-bytes material (NetworkID-bound), so a
	// typo must not silently mint a constitution the operator did not intend.
	if *endorsementPolicy != "require" && *endorsementPolicy != "off" {
		log.Fatalf(`genesis-ceremony dev: -endorsement-policy must be "require" or "off" (got %q)`, *endorsementPolicy)
	}
	// Resolve the genesis quorum K (see resolveGenesisQuorumK): 0 ⇒ auto
	// majority. An out-of-range or diluting K fails here at mint, not at the
	// network's first boot.
	quorumK, qErr := resolveGenesisQuorumK(*quorum, *witnessCount)
	if qErr != nil {
		log.Fatalf("genesis-ceremony dev: %v", qErr)
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
			log.Fatalf("genesis-ceremony dev: witness #%d (%s): %v", i, path, kerr)
		}
		did, derr := secp256k1DIDKey(priv)
		if derr != nil {
			log.Fatalf("genesis-ceremony dev: witness #%d (%s): derive DID: %v", i, path, derr)
		}
		genesisDIDs = append(genesisDIDs, did)
		witnessPrivs = append(witnessPrivs, priv)
		keyPaths = append(keyPaths, path)
		fmt.Printf("genesis-ceremony dev: witness #%d %s = %s -> %s\n",
			i, ifGenerated(generated), path, did)
	}

	// Genesis admission authority: generate-or-load the secp256k1 EOA that may
	// authorize writes from genesis (the write-path root of trust).
	authKeyPath := fmt.Sprintf("%s/admission-authority.key", *outDir)
	genesisAuthorityAddr, authGen, authErr := loadOrGenerateAdmissionAuthority(authKeyPath)
	if authErr != nil {
		log.Fatalf("genesis-ceremony dev: admission authority key (%s): %v", authKeyPath, authErr)
	}
	fmt.Printf("genesis-ceremony dev: admission authority %s = %s -> %s\n",
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
			log.Fatalf("genesis-ceremony dev: ledger signer key (%s): %v", *outLedgerKey, lkErr)
		}
		fmt.Printf("genesis-ceremony dev: ledger signer %s = %s -> %s\n",
			ifGenerated(ledgerGen), *outLedgerKey, ledgerDID)
	}

	doc := buildBootstrapDoc(*logDID, *networkName, *gating, *endorsementPolicy, genesisDIDs, quorumK, genesisAuthorityAddr, uint8(*minSignatures), nil, "", anchoringPolicyFromFlag(*anchoringMaxInterval))
	// mintServedBootstrap runs the SDK validation (doc.IDs()), the genesis
	// self-endorsement ceremony when the policy requires it, and the
	// first-contact round-trip (network.LoadVerifiedBootstrap) over the EXACT
	// bytes to be written. Any failure exits non-zero here, BEFORE the file
	// exists — a mint that cannot pass first contact never leaves the tool.
	body, doc, mErr := mintServedBootstrap(doc, witnessPrivs)
	if mErr != nil {
		log.Fatalf("genesis-ceremony dev: %v", mErr)
	}
	if err := os.MkdirAll(dirOf(bootstrapPath), 0o755); err != nil {
		log.Fatalf("genesis-ceremony dev: mkdir bootstrap dir: %v", err)
	}
	if err := os.WriteFile(bootstrapPath, body, 0o644); err != nil {
		log.Fatalf("genesis-ceremony dev: write bootstrap: %v", err)
	}

	fmt.Printf("genesis-ceremony dev: witnesses     = %d (key paths: %v)\n",
		*witnessCount, keyPaths)
	fmt.Printf("genesis-ceremony dev: endorsements  = %d (policy=%s)\n",
		len(doc.GenesisEndorsements), *endorsementPolicy)
	fmt.Printf("genesis-ceremony dev: bootstrap     = %s\n", bootstrapPath)
}
