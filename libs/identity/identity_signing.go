/*
FILE PATH: libs/identity/identity_signing.go

DESCRIPTION:

	Wallet-signing types used by IdentityProvider.SignDigest. Split
	out of identity.go to keep that file focused on the verification
	side of the interface.

	Why these shapes are EIP-712-flavored, not arbitrary bytes:

	  For judicial submissions the wallet UI MUST display the
	  structured fields the signer is committing to (action, docket,
	  artifact CID, expires-at, etc.). EIP-191 (personal_sign) shows
	  opaque hash bytes — fine for a login nonce, not fine for a
	  court action. EIP-712-style typed data lets the wallet render
	  the actual fields, and the domain separator binds the
	  signature to a specific (court, schema_version) so a sig for
	  davidson-tn cannot be replayed against shelby-tn.

	  JN computes the digest itself: keccak256(\x19\x01 ||
	  domain_separator_hash || typed_struct_hash). The provider does
	  NOT hash again; it signs the bytes. The Display struct carries
	  the same typed structure to the wallet for rendering.

OVERVIEW:

	SignRequest        — what JN passes to SignDigest.
	SignResponse       — what the provider returns on approval.
	TypedDataDisplay   — EIP-712 typed-data envelope for wallet UX.
	EIP712Domain       — the domain-separator inputs.
	EIP712Field        — one (name, type, value) row in the typed
	                     structure.

KEY DEPENDENCIES:
  - api/exchange/identity/identity.go (IdentityProvider interface).
*/
package identity

import "fmt"

// SignRequest is the payload for IdentityProvider.SignDigest.
type SignRequest struct {
	// SignerDID is the protocol did:key whose wallet should sign.
	// The provider rejects with ErrSignerNotFound if it does not
	// hold a wallet for this DID.
	SignerDID string

	// Digest is the 32-byte typed-data digest JN computed. The
	// provider signs these bytes verbatim.
	Digest [32]byte

	// Display is the EIP-712-style typed structure the wallet UI
	// will render to the user. Optional; if nil, the wallet shows
	// only the digest hex (acceptable for system-internal flows
	// like nonce-proof but NOT for court actions).
	Display *TypedDataDisplay

	// Reason is a short human-readable string the wallet UI shows
	// alongside the typed data ("Publish filing 2027-CR-4471").
	// 256 byte cap; longer reasons are truncated by the provider.
	Reason string

	// Timeout is the maximum time the provider should wait for the
	// user to approve. Zero means use the provider's default
	// (typically 60 seconds). Long timeouts trip ErrSignTimeout.
	TimeoutSeconds int
}

// Validate runs structural sanity on a SignRequest. Callers MUST
// validate before passing to SignDigest — the provider may not
// re-check.
func (r *SignRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("identity: nil sign request")
	}
	if r.SignerDID == "" {
		return fmt.Errorf("identity: sign request signer_did required")
	}
	// Zero digest is permitted in tests but flagged as a likely bug
	// (a real EIP-712 digest is overwhelmingly unlikely to be zero).
	if r.Digest == ([32]byte{}) {
		return fmt.Errorf("identity: sign request digest is all-zero (programming error?)")
	}
	if r.Display == nil {
		return fmt.Errorf("identity: sign request display required for court actions; pass typed data so the wallet can render it to the signer")
	}
	if err := r.Display.Validate(); err != nil {
		return fmt.Errorf("identity: sign request display: %w", err)
	}
	if len(r.Reason) > 256 {
		return fmt.Errorf("identity: sign request reason exceeds 256 bytes")
	}
	if r.TimeoutSeconds < 0 {
		return fmt.Errorf("identity: sign request timeout must be non-negative")
	}
	return nil
}

// SignResponse is what the provider returns on approval.
type SignResponse struct {
	// Signature is the secp256k1 signature. May be 65 bytes (R||S||V
	// canonical) or 64 bytes (R||S). Callers that need V (recovery
	// ID) should expect 65; callers that already know the public
	// key may accept 64.
	Signature []byte

	// PublicKey is the signer's secp256k1 public key, uncompressed
	// (65 bytes including the 0x04 prefix). Returned alongside the
	// signature so callers do not need a second round-trip to the
	// provider for verification.
	PublicKey []byte

	// Algorithm is "secp256k1" for Privy embedded wallets. Reserved
	// for future providers that may use other curves.
	Algorithm string

	// SignedAt is when the provider observed the user's approval.
	// Used for audit-trail correlation with the wallet's UX log.
	SignedAtUnixSeconds int64
}

// TypedDataDisplay is the EIP-712-style typed structure the wallet
// renders to the user at sign time. Mirrors the standard EIP-712
// shape but kept JN-internal (no Ethereum chain types) so we can
// evolve it without locking onto the spec verbatim.
type TypedDataDisplay struct {
	// Domain pins the signature to a specific (court, schema_version)
	// pair. Across domains the same payload bytes produce different
	// digests, blocking cross-court replay.
	Domain EIP712Domain

	// PrimaryType names the top-level typed structure ("Delegation",
	// "Filing", "Revocation"). The wallet displays this prominently
	// so the user sees what kind of action they are approving.
	PrimaryType string

	// Fields are the (name, type, value) rows that make up the
	// typed structure. Ordered; the wallet renders them top-to-bottom.
	Fields []EIP712Field
}

// EIP712Domain is the domain-separator input. Maps to EIP-712's
// EIP712Domain type. We intentionally OMIT chainId and
// verifyingContract because JN is not on a public chain; instead we
// use Name + Version + Salt as the domain identity, where Salt is
// the institutional did:key (e.g. did:web:state:tn:davidson) so each
// court is its own domain.
type EIP712Domain struct {
	// Name is the application identity ("Judicial Network").
	Name string

	// Version is the schema version ("v1"). Bumping this forces a
	// fresh signature when the entry shape changes.
	Version string

	// Salt is the institutional DID — a per-deployment domain
	// identifier. Hex- or base58-encoded (whatever the deployment
	// agrees on). Required.
	Salt string
}

// EIP712Field is one row in the typed structure. Type is the
// EIP-712 type name ("string", "uint64", "address", "bytes32") and
// Value is the value the wallet renders verbatim — pre-formatted
// so the wallet does not need to interpret types.
type EIP712Field struct {
	Name  string
	Type  string
	Value string
}

// Validate checks the typed-data display has the required fields.
func (d *TypedDataDisplay) Validate() error {
	if d == nil {
		return fmt.Errorf("identity: nil typed-data display")
	}
	if d.Domain.Name == "" {
		return fmt.Errorf("identity: typed-data domain name required")
	}
	if d.Domain.Version == "" {
		return fmt.Errorf("identity: typed-data domain version required")
	}
	if d.Domain.Salt == "" {
		return fmt.Errorf("identity: typed-data domain salt (institutional DID) required")
	}
	if d.PrimaryType == "" {
		return fmt.Errorf("identity: typed-data primary_type required")
	}
	if len(d.Fields) == 0 {
		return fmt.Errorf("identity: typed-data must have at least one field")
	}
	for i, f := range d.Fields {
		if f.Name == "" {
			return fmt.Errorf("identity: typed-data field[%d] name required", i)
		}
		if f.Type == "" {
			return fmt.Errorf("identity: typed-data field[%d] type required", i)
		}
	}
	return nil
}
