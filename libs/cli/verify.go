package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
)

// The verify exit-code contract (PRE-1; the binary maps these):
//
//	0  the proof VERIFIED
//	1  the proof FAILED verification (ErrVerificationFailed: a failed
//	   cryptographic check, a refused embedded constitution, or a pin
//	   mismatch — the proof is the problem)
//	2  verification COULD NOT RUN (ErrVerifyUsage: bad flags, unreadable
//	   file, malformed bytes, store errors — the invocation is the problem)
//
// CI consumers branch on the code; stderr carries the reason; --output json
// emits the versioned result envelope on success.
var (
	ErrVerificationFailed = errors.New("verification failed")
	ErrVerifyUsage        = errors.New("could not verify")
)

// VerifyData is the --output json data shape (kind "verify").
type VerifyData struct {
	Verified    bool     `json:"verified"`
	Format      string   `json:"format"`
	NetworkID   string   `json:"network_id"`
	TreeSize    uint64   `json:"tree_size"`
	QuorumHave  int      `json:"quorum_have"`
	QuorumNeed  int      `json:"quorum_need"`
	Pinned      bool     `json:"pinned"`
	PinnedTo    string   `json:"pinned_to,omitempty"`
	Sections    []string `json:"verified_sections,omitempty"`
	NotAsserted []string `json:"not_asserted,omitempty"`
}

// RunVerify verifies a v2 standalone proof FILE fully offline. It is
// NETWORK-AGNOSTIC by default: a v2 proof is self-contained (it embeds its
// genesis bootstrap + witness set + network id), so the trust root is derived
// from the proof itself (trust-on-first-use) and the network id is reported.
// --pin <64-hex network id> additionally binds the proof to a network id you
// already trust, failing closed on mismatch. Zero network calls.
func RunVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pin := fs.String("pin", "", "require the proof's network id to equal this 64-hex id")
	bundlePath := fs.String("bundle", "", "pin against this network bundle's id (content-addressed anchor)")
	network := fs.String("network", "", "pin against this stored/active network")
	output := fs.String("output", "table", "output format: table|json")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", ErrVerifyUsage, err)
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: usage: baseproof verify <proof-file> [--pin <64hex> | --network <name> | --bundle <file>]", ErrVerifyUsage)
	}

	// A network bundle is the cleaner ZT anchor than a raw --pin: its network id is
	// content-addressed to its bootstrap, so pinning the proof to it binds "this is
	// the network I trust". --pin (raw id) still works; neither ⇒ self-anchored TOFU.
	effectivePin := *pin
	if *bundlePath != "" || *network != "" {
		b, berr := resolveBundle(*bundlePath, *network)
		if berr != nil {
			return fmt.Errorf("%w: %v", ErrVerifyUsage, berr)
		}
		effectivePin = b.NetworkID
	}

	proof, res, err := verifyProofFile(ctx, fs.Arg(0), effectivePin)
	if err != nil {
		return err
	}
	nid := proof.NetworkID
	data := VerifyData{
		Verified:    true,
		Format:      string(proof.Format),
		NetworkID:   hex.EncodeToString(nid[:]),
		TreeSize:    res.TreeSize,
		QuorumHave:  res.WitnessQuorum.Have,
		QuorumNeed:  res.WitnessQuorum.Need,
		Pinned:      effectivePin != "",
		PinnedTo:    effectivePin,
		Sections:    append([]string(nil), res.Coverage.Verified...),
		NotAsserted: append([]string(nil), res.Coverage.NotAsserted...),
	}
	return emitOutput(*output, "verify", data, func() error {
		tablef("proof: format=%s network=%s tree_size=%d quorum=%d-of-%d\n",
			data.Format, data.NetworkID, data.TreeSize, data.QuorumHave, data.QuorumNeed)
		tablef("proof: verified: %v\n", res.Coverage.Verified)
		if len(data.NotAsserted) > 0 {
			tablef("proof: not asserted (absent sections): %v\n", data.NotAsserted)
		}
		if effectivePin == "" {
			tableln("proof: ✔ VERIFIED (self-anchored / trust-on-first-use — pass --network/--bundle/--pin to bind to a network you already trust)")
		} else {
			tablef("proof: ✔ VERIFIED and pinned to network %s\n", short(effectivePin))
		}
		return nil
	})
}

// verifyProofFile decodes + verifies a v2 proof file offline. Failures are
// CLASSIFIED for the exit-code contract: unreadable/malformed inputs wrap
// ErrVerifyUsage (could not verify); pin mismatches, refused embedded
// constitutions, and failed cryptographic checks wrap ErrVerificationFailed
// (the proof is the problem). A nil error means the proof fully verified.
func verifyProofFile(ctx context.Context, path, pin string) (*sdkbundle.StandaloneProof, *sdkbundle.StandaloneResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read proof %q: %v", ErrVerifyUsage, path, err)
	}
	proof, err := sdkbundle.DecodeStandalone(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decode v2 proof %q: %v", ErrVerifyUsage, path, err)
	}
	if pin != "" {
		want, err := hexID(pin)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: --pin %v", ErrVerifyUsage, err)
		}
		if proof.NetworkID != want {
			return nil, nil, fmt.Errorf("%w: pin mismatch: proof is for network %x…, --pin is %x… (fail-closed)",
				ErrVerificationFailed, proof.NetworkID[:8], want[:8])
		}
	}
	trustRoots, err := trustRootFromProof(proof)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil {
		return nil, nil, fmt.Errorf("%w (fail-closed): %v", ErrVerificationFailed, err)
	}
	if res == nil || !res.Valid {
		return nil, nil, fmt.Errorf("%w: the proof did not verify (fail-closed)", ErrVerificationFailed)
	}
	return proof, res, nil
}

// trustRootFromProof derives the genesis trust root from the proof's OWN embedded
// bootstrap — the self-contained path that makes verify network-agnostic. It is
// the same derivation the e2e applies to a fetched bootstrap (genesisTrustRoots),
// sourced here from the proof so no network or bundle is needed. This is
// trust-on-first-use: it proves the proof is internally consistent and
// cryptographically sound for the network it names; --pin binds that name to one
// you already trust.
//
// The embedded constitution is admitted through the self-pin first-contact door
// (network.LoadSelfVerifiedBootstrap): strict decode + the genesis ceremony
// whenever the constitution requires endorsement. The proof embeds the
// constitution's TRANSPORT form (endorsements included, #51), so a
// require-network proof verifies its ceremony OFFLINE — and one stripped of its
// endorsements is refused, not silently trusted. Everything the trust root
// needs (witness DIDs, the constitutional GenesisQuorumK, the canonical-subset
// hash — which IS the NetworkID) is read from the verified document; the proof
// restates none of it.
func trustRootFromProof(proof *sdkbundle.StandaloneProof) (map[cosign.NetworkID]protocol.GenesisTrustRoot, error) {
	gb := proof.SelfAnchor.GenesisBootstrap
	if len(gb.BootstrapDocument) == 0 {
		return nil, fmt.Errorf("proof carries no embedded bootstrap — cannot self-verify (supply trust externally)")
	}
	doc, err := network.LoadSelfVerifiedBootstrap(gb.BootstrapDocument)
	if err != nil {
		return nil, fmt.Errorf("embedded bootstrap failed first-contact verification: %w", err)
	}
	ids, err := doc.IDs()
	if err != nil {
		return nil, fmt.Errorf("embedded bootstrap ids: %w", err)
	}
	nid := cosign.NetworkID(ids.NetworkID)
	return map[cosign.NetworkID]protocol.GenesisTrustRoot{
		nid: {
			NetworkID:             nid,
			GenesisWitnessDIDs:    append([]string(nil), doc.GenesisWitnessSet...),
			QuorumK:               doc.GenesisQuorumK,
			BootstrapDocumentHash: [32]byte(ids.NetworkID),
		},
	}, nil
}
