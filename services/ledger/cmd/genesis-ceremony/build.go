/*
FILE PATH: cmd/genesis-ceremony/build.go

Production phase 1 — assemble, don't mint.

The coordinator holds NO keys in this mode: witness identities arrive as
did:key strings (each witness generated its own key on its own host), the
admission authority arrives as an address, and genesis auditors (optional)
arrive as a JSON declaration of already-existing identities. The output is the
UNENDORSED constitution: it validates (doc.IDs() — the NetworkID is derived and
printed), but under a require policy it cannot yet pass first contact — that is
the point; the ceremony (genesis-endorse on each witness host) happens next,
and assemble seals it.

There are deliberately no key-output flags here: production paths cannot drift
into key custody by flag accident.
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/baseproof/baseproof/network"
)

func runBuild(args []string) {
	fs := flag.NewFlagSet("genesis-ceremony build", flag.ExitOnError)
	networkName := fs.String("network-name", "",
		"network_name field of the BootstrapDocument (REQUIRED)")
	logDID := fs.String("log-did", "",
		"the network's exchange/log DID (REQUIRED)")
	witnessDIDs := fs.String("witness-dids", "",
		"comma-separated genesis witness did:key list (REQUIRED). Each DID's key "+
			"is held by ITS witness on ITS host — this tool never sees a key. The "+
			"witnesses endorse the emitted unendorsed constitution independently "+
			"via genesis-endorse; assemble collects the results.")
	quorum := fs.Int("quorum", 0,
		"genesis witness quorum K-of-N bound into the NetworkID. "+
			"0 = auto majority (N/2+1). Must satisfy 1<=K<=N and 2K>N.")
	gating := fs.String("gating", "require",
		`genesis admission gating: "require" (production default) or "off"`)
	admissionAuthority := fs.String("admission-authority", "",
		"the genesis admission authority's 0x-prefixed secp256k1 EOA address "+
			"(REQUIRED — the write-path root of trust; its key stays wherever it "+
			"was generated, never here)")
	minSignatures := fs.Int("min-signatures", 1,
		"GenesisSignaturePolicy.MinSignaturesPerEntry, in [1, 64]")
	endorsementPolicy := fs.String("endorsement-policy", "require",
		`genesis endorsement policy: "require" (default; the N-of-N witness `+
			`ceremony is demanded at every first contact) or "off"`)
	auditorsFile := fs.String("genesis-auditors", "",
		"path to a JSON array of genesis auditors "+
			`([{"auditor_did","public_key","scheme_tag","findings_url","scope"},…]) `+
			"declared in the constitution. Optional; their endorsement policy is "+
			"-auditor-endorsement-policy.")
	auditorPolicy := fs.String("auditor-endorsement-policy", "",
		`genesis AUDITOR endorsement policy: "require" demands a valid endorsement `+
			`from EVERY declared genesis auditor at first contact; "off"/empty `+
			"declares the auditors without an endorsement requirement. Defaults to "+
			`"require" when -genesis-auditors is set (safety machinery defaults ON), `+
			"unset otherwise.")
	anchoringMaxInterval := fs.Duration("anchoring-max-interval", 0,
		"constitutional ANCHORING commitment: the maximum staleness of an external "+
			"anchor of this network's heads (e.g. 24h). 0 = no commitment. Bound into "+
			"the NetworkID; the ledger derives its anchor-publisher cadence from it "+
			"and auditors monitor it (network.CheckAnchoring).")
	out := fs.String("out", "unendorsed.json",
		"path to write the UNENDORSED constitution")
	_ = fs.Parse(args)

	if *networkName == "" || *logDID == "" || *witnessDIDs == "" || *admissionAuthority == "" {
		log.Fatalf("genesis-ceremony build: -network-name, -log-did, -witness-dids, and -admission-authority are required")
	}
	if *minSignatures < 1 || *minSignatures > 64 {
		log.Fatalf("genesis-ceremony build: -min-signatures must be in [1, 64] (got %d)", *minSignatures)
	}
	if *endorsementPolicy != "require" && *endorsementPolicy != "off" {
		log.Fatalf(`genesis-ceremony build: -endorsement-policy must be "require" or "off" (got %q)`, *endorsementPolicy)
	}

	dids := splitDIDs(*witnessDIDs)
	if len(dids) == 0 {
		log.Fatalf("genesis-ceremony build: -witness-dids parsed to an empty list")
	}
	quorumK, qErr := resolveGenesisQuorumK(*quorum, len(dids))
	if qErr != nil {
		log.Fatalf("genesis-ceremony build: %v", qErr)
	}

	var auditors []network.GenesisAuditor
	effectiveAuditorPolicy := *auditorPolicy
	if *auditorsFile != "" {
		raw, err := os.ReadFile(*auditorsFile)
		if err != nil {
			log.Fatalf("genesis-ceremony build: read -genesis-auditors %s: %v", *auditorsFile, err)
		}
		if err := json.Unmarshal(raw, &auditors); err != nil {
			log.Fatalf("genesis-ceremony build: parse -genesis-auditors %s: %v", *auditorsFile, err)
		}
		if len(auditors) == 0 {
			log.Fatalf("genesis-ceremony build: -genesis-auditors %s is an empty list", *auditorsFile)
		}
		// Safety machinery defaults ON: declared auditors get a require policy
		// unless the operator explicitly opted out.
		if effectiveAuditorPolicy == "" {
			effectiveAuditorPolicy = "require"
			fmt.Println("genesis-ceremony build: -auditor-endorsement-policy defaulted to \"require\" (auditors declared)")
		}
	} else if effectiveAuditorPolicy == "require" {
		log.Fatalf("genesis-ceremony build: -auditor-endorsement-policy=require with no -genesis-auditors is unsatisfiable")
	}

	doc := buildBootstrapDoc(*logDID, *networkName, *gating, *endorsementPolicy,
		dids, quorumK, *admissionAuthority, uint8(*minSignatures), auditors, effectiveAuditorPolicy,
		anchoringPolicyFromFlag(*anchoringMaxInterval))

	// Validate + derive the identity NOW: the NetworkID is fixed by these
	// canonical bytes — the ceremony signs it, so it must be final and printable
	// before any witness endorses.
	ids, err := doc.IDs()
	if err != nil {
		log.Fatalf("genesis-ceremony build: constitution does not validate: %v", err)
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatalf("genesis-ceremony build: marshal: %v", err)
	}
	body = append(body, '\n')
	if err := os.MkdirAll(dirOf(*out), 0o755); err != nil {
		log.Fatalf("genesis-ceremony build: mkdir: %v", err)
	}
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		log.Fatalf("genesis-ceremony build: write %s: %v", *out, err)
	}

	fmt.Printf("genesis-ceremony build: unendorsed constitution = %s\n", *out)
	fmt.Printf("genesis-ceremony build: network_id              = %x\n", ids.NetworkID)
	fmt.Printf("genesis-ceremony build: witnesses               = %d (quorum K=%d)\n", len(dids), quorumK)
	if len(auditors) > 0 {
		fmt.Printf("genesis-ceremony build: genesis auditors        = %d (policy=%s)\n", len(auditors), effectiveAuditorPolicy)
	}
	if *endorsementPolicy == "require" {
		fmt.Println("genesis-ceremony build: NEXT — on each witness host:")
		fmt.Printf("  genesis-endorse -bootstrap %s -key <witness.pem> -out endorsement-<witness>.json\n", *out)
		fmt.Println("then collect the endorsement files and run: genesis-ceremony assemble")
	}
}

// splitDIDs parses the comma-separated -witness-dids value, trimming
// whitespace and dropping empties.
func splitDIDs(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
