package quorum

import (
	"errors"
	"fmt"

	"github.com/baseproof/baseproof/types"
)

// ErrCosignSchemeNotAllowed is returned when a witness key declares a cosign
// SchemeTag the network's GenesisSignaturePolicy.AllowedCosignSchemeTags does
// not admit. Surfaced at the two seams that install an active witness set — boot
// keyset construction and on-log witness rotation — so a self-inconsistent
// witness set fails LOUDLY instead of silently admitting a forbidden cosign
// scheme.
var ErrCosignSchemeNotAllowed = errors.New(
	"quorum: witness cosign scheme not allowed by network signature policy")

// ValidateCosignSchemePolicy enforces the network's
// GenesisSignaturePolicy.AllowedCosignSchemeTags (SDK network/bootstrap.go) on a
// witness key set: every key's SchemeTag MUST be in `allowed`, else any
// cosignature that key would contribute is inadmissible under the network's
// policy. The SDK doc is explicit: "a cosignature whose scheme tag is outside
// this set fails verification."
//
// WHY THE LEDGER MUST DO THIS: the SDK's cosign.Verify dispatches on SchemeTag
// and binds a cosignature's tag to its registered key's tag
// (cosign.ErrSchemeMismatch), but it has NO notion of the network's allow-list —
// it accepts any tag it is wired to verify (ECDSA / BLS). AllowedCosignSchemeTags
// is a higher-level GOVERNANCE restriction (hashed into the NetworkID) that lives
// above the SDK's cryptographic dispatch. Enforcing it at the witness-keyset seam
// — the single place the ledger decides which witnesses may contribute to a
// cosigned head — turns this genesis policy field, previously parsed and
// discarded, into an enforced invariant. Because cosign.Verify already requires
// sig.SchemeTag == key.SchemeTag, gating the KEYS by scheme transitively gates
// every contributing cosignature.
//
// `allowed` empty → no-op. The BootstrapDocument validation already requires a
// non-empty genesis signature policy (an empty AllowedCosignSchemeTags is
// rejected at the SDK boundary), so this branch is purely defensive against a
// document that bypassed that gate; it deliberately does not invent a policy.
//
// Returns a descriptive error naming the FIRST offending witness so the failure
// (a genesis or a rotation that mixes an admitted witness set with a stricter
// cosign-scheme policy) is legible at the call site.
func ValidateCosignSchemePolicy(keys []types.WitnessPublicKey, allowed []uint8) error {
	if len(allowed) == 0 {
		return nil
	}
	allowedSet := make(map[uint8]struct{}, len(allowed))
	for _, tag := range allowed {
		allowedSet[tag] = struct{}{}
	}
	for i, k := range keys {
		if _, ok := allowedSet[k.SchemeTag]; !ok {
			return fmt.Errorf(
				"%w: witness[%d] id=%x declares cosign scheme 0x%02x, allowed_cosign_scheme_tags=%v",
				ErrCosignSchemeNotAllowed, i, k.ID[:8], k.SchemeTag, allowed)
		}
	}
	return nil
}
