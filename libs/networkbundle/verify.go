/*
FILE PATH: libs/networkbundle/verify.go

DESCRIPTION:

	VerifyManifest — the first-class verify door for a received network
	bundle. Formalizes what `network add --from-ledger` proved ad hoc:
	the manifest is DISCOVERY, never authority; trust flows only through
	the hash-verified constitution. The corrected ownership principle,
	for the record:

	  SDK owns the TRUST container (the constitution + its doors);
	  libs owns the DISCOVERY container (this manifest/v1);
	  domain policy rides embedded, verified where its verifiers live;
	  protocol.NetworkBundle never serializes — it is the in-memory
	  assembly a client builds from a VERIFIED manifest plus a
	  hash-verified bootstrap.

	The door enforces, fail-closed:

	  1. WIRE: the received bytes strict-decode AND are the canonical
	     form (re-canonicalize to themselves) — a reformatted or
	     tampered document is refused, the same rule the serve handler
	     applies to on-log candidates.
	  2. IDENTITY: NetworkRef.NetworkID is present and equals the
	     hash-verified bootstrap's identity (doc.IDs(), which itself
	     validates the constitution). A bundle that names no network, or
	     a different one, cannot be bound to this trust root.
	  3. QUORUM-AS-CACHE: NetworkRef.QuorumK is a CACHE of the
	     constitutional GenesisQuorumK, never a source (the
	     K-comes-from-the-constitution stance). Absent (0) is fine;
	     present-and-disagreeing is fatal — consumers must not inherit a
	     drift channel.

	The caller supplies a bootstrap it ALREADY verified through the
	SDK's first-contact door (fetched and hash-checked against the
	pinned NetworkID); this door binds the discovery document to that
	established trust, it does not establish trust itself.
*/
package networkbundle

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/baseproof/baseproof/network"
)

// VerifyManifest binds received manifest bytes to a hash-verified bootstrap
// and returns the decoded document. Every failure is fail-closed with an
// error naming exactly which door refused.
func VerifyManifest(raw []byte, bootstrap *network.BootstrapDocument) (*Manifest, error) {
	if bootstrap == nil {
		return nil, fmt.Errorf("networkbundle: verify: nil bootstrap (verify the constitution first — the manifest is discovery, never authority)")
	}
	ids, err := bootstrap.IDs()
	if err != nil {
		return nil, fmt.Errorf("networkbundle: verify: bootstrap IDs: %w", err)
	}
	wantID := hex.EncodeToString(ids.NetworkID[:])

	m, err := DecodeManifest(raw)
	if err != nil {
		return nil, err
	}
	// Wire rule: the received bytes must BE the canonical form.
	recanon, err := m.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("networkbundle: verify: canonicalize: %w", err)
	}
	if !bytes.Equal(recanon, raw) {
		return nil, fmt.Errorf("networkbundle: verify: document is not canonical (reformatted or tampered bytes are refused)")
	}

	// Identity rule: the manifest must name the verified network.
	if m.Network.NetworkID == "" {
		return nil, fmt.Errorf("networkbundle: verify: manifest carries no network_id — it cannot be bound to a trust root")
	}
	if m.Network.NetworkID != wantID {
		return nil, fmt.Errorf("networkbundle: verify: manifest names network %s but the verified constitution is %s",
			short64(m.Network.NetworkID), short64(wantID))
	}

	// Quorum-as-cache rule: present-and-disagreeing is a drift channel.
	if m.Network.QuorumK != 0 && m.Network.QuorumK != bootstrap.GenesisQuorumK {
		return nil, fmt.Errorf("networkbundle: verify: manifest caches quorum_k=%d but the constitution's GenesisQuorumK=%d — the constitution is the single source of K",
			m.Network.QuorumK, bootstrap.GenesisQuorumK)
	}
	return m, nil
}

// short64 abbreviates a 64-hex id for error messages.
func short64(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}
