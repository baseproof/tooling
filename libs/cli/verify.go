package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/baseproof/baseproof/crypto/cosign"
	sdkbundle "github.com/baseproof/baseproof/log/bundle"
	"github.com/baseproof/baseproof/network"
	"github.com/baseproof/baseproof/protocol"
)

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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: baseproof verify <proof-file> [--pin <64hex> | --network <name> | --bundle <file>]")
	}

	// A network bundle is the cleaner ZT anchor than a raw --pin: its network id is
	// content-addressed to its bootstrap, so pinning the proof to it binds "this is
	// the network I trust". --pin (raw id) still works; neither ⇒ self-anchored TOFU.
	effectivePin := *pin
	if *bundlePath != "" || *network != "" {
		b, berr := resolveBundle(*bundlePath, *network)
		if berr != nil {
			return berr
		}
		effectivePin = b.NetworkID
	}

	proof, res, err := verifyProofFile(ctx, fs.Arg(0), effectivePin)
	if err != nil {
		return err
	}
	nid := proof.NetworkID
	fmt.Printf("proof: format=%s network=%s tree_size=%d quorum=%d-of-%d\n",
		proof.Format, hex.EncodeToString(nid[:]), res.TreeSize, res.WitnessQuorum.Have, res.WitnessQuorum.Need)
	fmt.Printf("proof: verified: %v\n", res.Coverage.Verified)
	if len(res.Coverage.NotAsserted) > 0 {
		fmt.Printf("proof: not asserted (absent sections): %v\n", res.Coverage.NotAsserted)
	}
	if effectivePin == "" {
		fmt.Println("proof: ✔ VERIFIED (self-anchored / trust-on-first-use — pass --network/--bundle/--pin to bind to a network you already trust)")
	} else {
		fmt.Printf("proof: ✔ VERIFIED and pinned to network %s\n", short(effectivePin))
	}
	return nil
}

// verifyProofFile decodes + verifies a v2 proof file offline. Every failure mode
// — unreadable file, non-v2 / malformed bytes, pin mismatch, or a failed
// cryptographic check — returns an error (fail-closed); a nil error means the
// proof fully verified.
func verifyProofFile(ctx context.Context, path, pin string) (*sdkbundle.StandaloneProof, *sdkbundle.StandaloneResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read proof %q: %w", path, err)
	}
	proof, err := sdkbundle.DecodeStandalone(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("decode v2 proof %q: %w", path, err)
	}
	if pin != "" {
		want, err := hexID(pin)
		if err != nil {
			return nil, nil, fmt.Errorf("--pin %w", err)
		}
		if proof.NetworkID != want {
			return nil, nil, fmt.Errorf("pin mismatch: proof is for network %x…, --pin is %x… (fail-closed)", proof.NetworkID[:8], want[:8])
		}
	}
	trustRoots, err := trustRootFromProof(proof)
	if err != nil {
		return nil, nil, err
	}
	res, err := sdkbundle.VerifyStandalone(ctx, proof, trustRoots)
	if err != nil {
		return nil, nil, fmt.Errorf("verify failed (fail-closed): %w", err)
	}
	if res == nil || !res.Valid {
		return nil, nil, fmt.Errorf("verify failed: the proof did not verify (fail-closed)")
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
// The embedded constitution is admitted through the SAME first-contact door the
// online clients use — network.LoadVerifiedBootstrap, self-pinned to the IDs the
// document itself derives — so OFFLINE verification enforces the genesis
// ceremony too: a require-network proof whose embedded constitution was stripped
// of its endorsements is refused, not silently trusted. (Today the SDK's v2
// builder embeds the canonical form, which carries no endorsements; once it
// embeds the endorsed form this gate verifies them with no change here.)
//
// K comes from the VERIFIED constitution (GenesisQuorumK — the NetworkID-bound
// single source); the section's QuorumK is demoted to a cross-check.
func trustRootFromProof(proof *sdkbundle.StandaloneProof) (map[cosign.NetworkID]protocol.GenesisTrustRoot, error) {
	gb := proof.SelfAnchor.GenesisBootstrap
	if len(gb.BootstrapDocument) == 0 {
		return nil, fmt.Errorf("proof carries no embedded bootstrap — cannot self-verify (supply trust externally)")
	}
	// Self-pin: derive the IDs the document claims, then run the full
	// first-contact verification (strict decode, canonical-subset hash equality,
	// ceremony when the policy requires it) against that pin.
	var probe network.BootstrapDocument
	if err := json.Unmarshal(gb.BootstrapDocument, &probe); err != nil {
		return nil, fmt.Errorf("decode embedded bootstrap: %w", err)
	}
	ids, err := probe.IDs()
	if err != nil {
		return nil, fmt.Errorf("embedded bootstrap ids: %w", err)
	}
	doc, err := network.LoadVerifiedBootstrap(gb.BootstrapDocument, [32]byte(ids.NetworkID))
	if err != nil {
		return nil, fmt.Errorf("embedded bootstrap failed first-contact verification: %w", err)
	}
	// One source for K: the constitution. A section that disagrees is a
	// malformed proof, not an alternative authority.
	if gb.QuorumK != 0 && gb.QuorumK != doc.GenesisQuorumK {
		return nil, fmt.Errorf("proof section quorum_k=%d disagrees with the constitutional genesis_quorum_k=%d (NetworkID-bound)",
			gb.QuorumK, doc.GenesisQuorumK)
	}
	canonical, err := doc.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("embedded bootstrap canonical bytes: %w", err)
	}
	nid := cosign.NetworkID(ids.NetworkID)
	return map[cosign.NetworkID]protocol.GenesisTrustRoot{
		nid: {
			NetworkID:             nid,
			GenesisWitnessDIDs:    append([]string(nil), doc.GenesisWitnessSet...),
			QuorumK:               doc.GenesisQuorumK,
			BootstrapDocumentHash: sha256.Sum256(canonical),
		},
	}, nil
}
